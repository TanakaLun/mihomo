//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"time"

	"github.com/metacubex/mihomo/log"
)

// The TC data plane publishes a reverse-path record into sb_tc_return for every
// intercepted flow and keeps refreshing its kernel timestamp while the flow is
// active. The userspace adapter never acquires or releases those records, so
// without a periodic sweep the map only grows: once its capacity is exhausted,
// tc_assign fails to publish a new record and the kernel drops the flow with
// TC_ACT_SHOT, which shows up as "new connections time out" until a restart
// recreates the maps (issue #43).
//
// SweepAssignments is the only control-plane path that deletes stale
// tc_return / tc_assignment / tc_return_frag entries. It rechecks each entry's
// generation before deleting, so a session that looks idle and then wakes up is
// never lost.
const (
	tcJanitorSweepInterval    = 5 * time.Minute
	tcJanitorPressureInterval = 15 * time.Second
	tcJanitorIdleInterval     = 30 * time.Minute
	tcJanitorSweepBudget      = 1024
)

// tcJanitorObservation is the input of one scheduling decision.
type tcJanitorObservation struct {
	pressure      bool
	failuresGrew  bool
	complete      bool
	scanned       uint32
	returnScanned uint32
}

// nextTCJanitorSchedule decides when the next sweep runs.
//
//   - A growth of return_update_failures means the kernel could not publish a
//     new record (the table is at or near capacity): sweep aggressively until a
//     full pass completes without further failures.
//   - A complete pass that scanned nothing parks the janitor on the long idle
//     interval instead of waking up every few minutes for an empty table.
//   - Otherwise keep the regular cadence.
//
// ReturnUsage is deliberately not consulted: it is derived from
// `scanned - accumulated_removed` across bounded passes and under-reports after
// partial traversals, so a remaining-but-undercounted table must not be treated
// as empty.
func nextTCJanitorSchedule(observation tcJanitorObservation) (time.Duration, bool) {
	pressure := observation.pressure
	if observation.failuresGrew {
		pressure = true
	} else if pressure && observation.complete {
		pressure = false
	}
	switch {
	case pressure:
		return tcJanitorPressureInterval, true
	case observation.complete && observation.scanned == 0 && observation.returnScanned == 0:
		return tcJanitorIdleInterval, false
	default:
		return tcJanitorSweepInterval, false
	}
}

func (i *Inbound) startTCAssignmentJanitor() {
	i.tcJanitorAccess.Lock()
	defer i.tcJanitorAccess.Unlock()
	if i.tcJanitorCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	i.tcJanitorCancel = cancel
	i.tcJanitorDone = done
	go i.runTCAssignmentJanitor(ctx, done)
}

func (i *Inbound) stopTCAssignmentJanitor() {
	i.tcJanitorAccess.Lock()
	if i.tcJanitorCancel == nil {
		i.tcJanitorAccess.Unlock()
		return
	}
	cancel := i.tcJanitorCancel
	done := i.tcJanitorDone
	i.tcJanitorCancel = nil
	i.tcJanitorDone = nil
	i.tcJanitorAccess.Unlock()
	cancel()
	<-done
}

func (i *Inbound) runTCAssignmentJanitor(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	// Run one pass immediately so a restart (or a home directory carried over
	// from a previous run) clears accumulated records right away.
	timer := time.NewTimer(0)
	defer timer.Stop()
	pressure := false
	var lastFailures uint64
	haveBaseline := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		// The backend can be replaced or released while this loop runs; always
		// resolve it through the inbound so a closed data plane ends the janitor.
		backend := i.tcBackend()
		if backend == nil {
			return
		}
		maxIdle := i.udpTimeout
		if maxIdle <= 0 {
			maxIdle = 5 * time.Minute
		}
		result, sweepErr := backend.SweepFlows(maxIdle, tcJanitorSweepBudget)
		if sweepErr != nil {
			if i.tcBackend() == nil {
				return
			}
			log.Warnln("[EBPF] sweep TC assignments: %s", sweepErr.Error())
		}
		failuresGrew := false
		if stats, err := backend.Stats(); err == nil {
			switch {
			case !haveBaseline:
				// A non-zero counter at startup means a previous run already
				// hit publication failures; clean up promptly.
				failuresGrew = stats.ReturnUpdateFailures > 0
			default:
				failuresGrew = stats.ReturnUpdateFailures > lastFailures
			}
			lastFailures = stats.ReturnUpdateFailures
			haveBaseline = true
		}
		if result.ReturnRemoved > 0 && !pressure {
			log.Debugln("[EBPF] swept %d idle TC return records (return_scanned=%d, assignment_scanned=%d)",
				result.ReturnRemoved, result.ReturnScanned, result.Scanned)
		}
		next, nextPressure := nextTCJanitorSchedule(tcJanitorObservation{
			pressure:      pressure,
			failuresGrew:  failuresGrew,
			complete:      result.Complete,
			scanned:       result.Scanned,
			returnScanned: result.ReturnScanned,
		})
		if nextPressure && !pressure {
			log.Warnln("[EBPF] TC return table under pressure (return_update_failures=%d); sweeping every %s",
				lastFailures, next)
		} else if pressure && !nextPressure {
			log.Infoln("[EBPF] TC return table pressure cleared (return_update_failures=%d)", lastFailures)
		}
		pressure = nextPressure
		timer.Reset(next)
	}
}
