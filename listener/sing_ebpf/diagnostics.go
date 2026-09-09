//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"sync"
	"time"
)

// EBPFAttachmentDiagnostics describes one TC/cgroup attachment for status
// reporting.
type EBPFAttachmentDiagnostics struct {
	// InterfaceName is the network interface name for a TC attachment, or
	// the cgroup path for the cgroup local data plane.
	InterfaceName string `json:"interface_name"`
	// InterfaceIndex is 0 for the cgroup local data plane, which has no
	// interface index.
	InterfaceIndex int    `json:"interface_index,omitempty"`
	Role           string `json:"role"`      // "local", "shared", or "local+shared"
	Framing        string `json:"framing"`   // "ethernet" or "raw_ip"; empty for cgroup
	Mechanism      string `json:"mechanism"` // "tcx", "clsact", or "cgroup"
	FakeIPICMP     bool   `json:"fakeip_icmp"`
}

// tcOutcomeHistory is the small amount of extra bookkeeping the recovery
// scheduler needs that nothing else in this package already tracks: the last
// outcome the update loop reported, when a failing component most recently
// cleared, and the loop's own current retry schedule.
type tcOutcomeHistory struct {
	access         sync.Mutex
	haveOutcome    bool
	lastOutcome    tcUpdateOutcome
	lastOutcomeAt  time.Time
	lastRecoveryAt time.Time
	// nextRetryAt is the zero time when the retry timer is currently
	// disarmed (nothing outstanding across any of the three components).
	nextRetryAt time.Time
}

// recordNextRetryDeadline is the update loop's onScheduleChange hook: called
// every time it arms or disarms its single physical timer.
func (i *Inbound) recordNextRetryDeadline(deadline time.Time) {
	i.diagnostics.access.Lock()
	i.diagnostics.nextRetryAt = deadline
	i.diagnostics.access.Unlock()
}

// recordTCUpdateOutcome is the update loop's hook: called with every outcome
// the update step reports, whether or not anything changed. It also drives
// the recovery attempt/success/failure counters across all three of
// tcUpdateOutcome's components.
func (i *Inbound) recordTCUpdateOutcome(outcome tcUpdateOutcome) {
	now := time.Now()
	i.diagnostics.access.Lock()
	defer i.diagnostics.access.Unlock()

	components := [...]tcSharedRewriteOutcome{outcome.sharedRewrite, outcome.general, outcome.bypassRuleSet}
	var previousComponents [3]tcSharedRewriteOutcome
	if i.diagnostics.haveOutcome {
		previousComponents = [3]tcSharedRewriteOutcome{
			i.diagnostics.lastOutcome.sharedRewrite,
			i.diagnostics.lastOutcome.general,
			i.diagnostics.lastOutcome.bypassRuleSet,
		}
	}
	recoveredThisRound := false
	attemptedThisRound := false
	stored := components
	for index, current := range components {
		if current == tcSharedRewriteRecoverable {
			attemptedThisRound = true
		}
		if i.diagnostics.haveOutcome {
			switch {
			case previousComponents[index] == tcSharedRewriteRecoverable && current == tcSharedRewriteSettled:
				i.counters.recoverySuccesses.Add(1)
				recoveredThisRound = true
			case previousComponents[index] != tcSharedRewriteUnrecoverable && current == tcSharedRewriteUnrecoverable:
				i.counters.recoveryFailures.Add(1)
			}
			if current == tcSharedRewriteUnknown {
				stored[index] = previousComponents[index]
			}
		}
	}
	if attemptedThisRound {
		i.counters.recoveryAttempts.Add(1)
	}
	if recoveredThisRound {
		i.diagnostics.lastRecoveryAt = now
	}
	i.diagnostics.lastOutcome = tcUpdateOutcome{
		sharedRewrite: stored[0],
		general:       stored[1],
		bypassRuleSet: stored[2],
	}
	i.diagnostics.lastOutcomeAt = now
	i.diagnostics.haveOutcome = true
}
