//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	sharedFlowMaxIdle               = 5 * time.Minute
	sharedFlowPressureMaxIdle       = 15 * time.Second
	sharedFlowPressureSweepInterval = 15 * time.Second
	sharedFlowSweepInterval         = 5 * time.Minute
	sharedFlowPressureEnterPercent  = 70
	sharedFlowPressureExitPercent   = 50
	sharedFlowPressureExitRounds    = 3
	sharedFlowFallbackScanBudget    = 1024
	sharedFlowReleaseFlushBudget    = 4096
)

type sharedRewrite struct {
	inbound              *Inbound
	interfaces           []string
	sharedBackend        *ECommon.SharedNetworkBackend
	dataPlane            *sharedRewriteDataPlane
	listeners            internalListenerSet
	sharedUDPClientTable sharedUDPClientTable
	udpWarnings          udpWarningLimiters
	tcpWarnings          warningLimiter
	mapCapacity          ECommon.SharedNetworkMapCapacities
	janitorWarnings      warningLimiter
	janitorAccess        sync.Mutex
	janitorCancel        context.CancelFunc
	janitorDone          chan struct{}
	tcPriority           uint16
	lifecycleAccess      sync.RWMutex
	backendAccess        sync.RWMutex
}

func newSharedRewrite(inbound *Inbound, options LC.EBPFShared) *sharedRewrite {
	mapCapacity := effectiveSharedNetworkMapCapacity(
		ECommon.DefaultSharedNetworkMapCapacities(),
		len(inbound.bypassRuleSet) > 0 ||
			len(options.IncludeSourceCIDR) > 0 || len(options.ExcludeSourceCIDR) > 0 ||
			len(options.IncludeMACAddress) > 0 || len(options.ExcludeMACAddress) > 0,
	)
	return &sharedRewrite{
		inbound:     inbound,
		interfaces:  append([]string(nil), options.Interface...),
		mapCapacity: mapCapacity,
		tcPriority:  inbound.tcPriority,
	}
}

func effectiveSharedNetworkMapCapacity(
	capacity ECommon.SharedNetworkMapCapacities,
	bypassFlowCache bool,
) ECommon.SharedNetworkMapCapacities {
	if !bypassFlowCache {
		capacity.Bypass = 1
	}
	return capacity
}

func (s *sharedRewrite) Start(interfaceNames []string, hostAddresses []netip.Addr) error {
	if err := s.startListeners(); err != nil {
		return E.Errors(err, s.closeListeners())
	}
	s.dataPlane = newSharedRewriteDataPlane(s, s.tcPriority)
	if err := s.dataPlane.reconcile(interfaceNames, hostAddresses); err != nil {
		return E.Errors(err, s.Close())
	}
	if s.sharedBackendInstance() == nil {
		log.Debugln("[EBPF] shared packet-rewrite waiting for downstream interfaces: interfaces=[%s]",
			strings.Join(s.interfaces, ", "))
	}
	return nil
}

func (s *sharedRewrite) prepareBackend() (*ECommon.SharedNetworkBackend, error) {
	redirectIPv6 := netip.Prefix{}
	if s.inbound.sharedRewriteIPv6Enabled() {
		redirectIPv6 = s.inbound.redirectIPv6Prefix
	}
	cgroupBackend := s.inbound.cgroupBackendInstance()
	backend, err := ECommon.PrepareSharedNetwork(cgroupBackend, ECommon.SharedNetworkConfig{
		ListenerPort: s.listeners.selectedPort(),
		EnableTCP:    s.inbound.enableTCP,
		EnableUDP:    s.inbound.enableUDP,
		RedirectIPv4: s.inbound.redirectIPv4Prefix,
		RedirectIPv6: redirectIPv6,
		Policy:       s.inbound.compiledPolicy,
		MapCapacity:  s.mapCapacity,
		UDPTimeout:   s.inbound.udpTimeout,
	})
	if err != nil {
		return nil, err
	}
	s.inbound.bypassRuleSetAccess.Lock()
	if cgroupBackend != nil {
		ipv4Count, ipv6Count := cgroupBackend.BypassCIDRCount()
		err = backend.SetBypassCIDRState(ipv4Count, ipv6Count)
	} else {
		_, err = backend.UpdateCompiledBypassCIDR(s.inbound.bypassRuleSetPolicy)
	}
	if err == nil {
		s.setSharedBackend(backend)
	}
	s.inbound.bypassRuleSetAccess.Unlock()
	if err != nil {
		return nil, E.Errors(err, backend.Close())
	}
	return backend, nil
}

func (s *sharedRewrite) sharedRewriteReadyLocked(attachments []string) {
	s.startFlowJanitor()
	log.Debugln("[EBPF] shared packet-rewrite active: attachments=[%s], redirect_listener_port=%d, dns_mode=%s, ipv6=%v, bypass_private_address=%v, source_cidr={include:%d, exclude:%d}, source_mac={include:%d, exclude:%d}",
		strings.Join(attachments, ", "),
		s.listeners.selectedPort(),
		s.inbound.sharedDNSMode,
		s.inbound.sharedRewriteIPv6Enabled(),
		s.inbound.sharedBypassPrivate,
		len(s.inbound.sharedOptions.IncludeSourceCIDR),
		len(s.inbound.sharedOptions.ExcludeSourceCIDR),
		len(s.inbound.sharedIncludeMAC),
		len(s.inbound.sharedExcludeMAC),
	)
}

func (s *sharedRewrite) startListeners() error {
	return s.listeners.start(
		s.inbound.enableTCP,
		s.inbound.enableUDP,
		s.inbound.redirectIPv4Prefix.IsValid(),
		s.inbound.sharedRewriteIPv6Enabled(),
		s.newListener,
	)
}

func (s *sharedRewrite) newListener(network string, ipv6Listener bool, port uint16) (*internalListener, error) {
	return newInternalListener(s.inbound.socketControl(ipv6Listener), network, ipv6Listener, port, s)
}

func (s *sharedRewrite) Close() error {
	if s == nil {
		return nil
	}
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	var closeErr error
	if s.dataPlane != nil {
		closeErr = s.dataPlane.Close()
		s.dataPlane = nil
	}
	s.stopFlowJanitor()
	backend := s.takeSharedBackend()
	var backendErr error
	if backend != nil {
		backendErr = backend.Close()
		if !backend.IsClosed() {
			s.setSharedBackend(backend)
			if backendErr == nil {
				backendErr = E.New("shared-network eBPF backend remained open after close")
			}
		}
	}
	listenerErr := s.closeListeners()
	return E.Errors(closeErr, backendErr, listenerErr)
}

func (s *sharedRewrite) closeListeners() error {
	return s.listeners.close()
}

func (s *sharedRewrite) IsClosed() bool {
	if s == nil {
		return true
	}
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	return s.dataPlane == nil && s.sharedBackendInstance() == nil && s.listeners.isClosed()
}

func (s *sharedRewrite) sharedBackendInstance() *ECommon.SharedNetworkBackend {
	s.backendAccess.RLock()
	defer s.backendAccess.RUnlock()
	return s.sharedBackend
}

func (s *sharedRewrite) takeSharedBackend() *ECommon.SharedNetworkBackend {
	s.backendAccess.Lock()
	backend := s.sharedBackend
	s.sharedBackend = nil
	s.backendAccess.Unlock()
	return backend
}

func (s *sharedRewrite) setSharedBackend(backend *ECommon.SharedNetworkBackend) {
	s.backendAccess.Lock()
	s.sharedBackend = backend
	s.backendAccess.Unlock()
}

// purgeUDP resets client-facing UDP state after the attachment set changes.
func (s *sharedRewrite) purgeUDP() {
}

func (s *sharedRewrite) acceptWarn(message ...any) {
	s.udpWarnings.accept.warn(s.inbound.logWarn, message...)
}

func (s *sharedRewrite) packetWarn(message ...any) {
	s.udpWarnings.packetInfo.warn(s.inbound.logWarn, message...)
}

func (s *sharedRewrite) startFlowJanitor() {
	s.janitorAccess.Lock()
	defer s.janitorAccess.Unlock()
	if s.janitorCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.janitorCancel = cancel
	s.janitorDone = done
	go s.runFlowJanitor(ctx, done)
}

func (s *sharedRewrite) stopFlowJanitor() {
	s.janitorAccess.Lock()
	if s.janitorCancel == nil {
		s.janitorAccess.Unlock()
		return
	}
	cancel := s.janitorCancel
	done := s.janitorDone
	s.janitorCancel = nil
	s.janitorDone = nil
	s.janitorAccess.Unlock()
	cancel()
	<-done
}

func (s *sharedRewrite) runFlowJanitor(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	sweepTimer := time.NewTimer(sharedFlowSweepInterval)
	sweepTimerChannel := sweepTimer.C
	var pressureTimer *time.Timer
	var pressureTimerChannel <-chan time.Time
	resetPressureTimer := func(active bool) {
		if !active {
			if pressureTimer != nil {
				if !pressureTimer.Stop() {
					select {
					case <-pressureTimer.C:
					default:
					}
				}
			}
			pressureTimerChannel = nil
			return
		}
		if pressureTimer == nil {
			pressureTimer = time.NewTimer(sharedFlowPressureSweepInterval)
		} else {
			if !pressureTimer.Stop() {
				select {
				case <-pressureTimer.C:
				default:
				}
			}
			pressureTimer.Reset(sharedFlowPressureSweepInterval)
		}
		pressureTimerChannel = pressureTimer.C
	}
	var releaseTimer *time.Timer
	var releaseTimerChannel <-chan time.Time
	resetReleaseTimer := func(backend *ECommon.SharedNetworkBackend) {
		delay, available := backend.NextTCPFlowReleaseDelay(time.Now())
		if !available {
			if releaseTimer != nil {
				releaseTimer.Stop()
			}
			releaseTimerChannel = nil
			return
		}
		if releaseTimer == nil {
			releaseTimer = time.NewTimer(delay)
		} else {
			if !releaseTimer.Stop() {
				select {
				case <-releaseTimer.C:
				default:
				}
			}
			releaseTimer.Reset(delay)
		}
		releaseTimerChannel = releaseTimer.C
	}
	defer func() {
		if releaseTimer != nil {
			releaseTimer.Stop()
		}
		if pressureTimer != nil {
			pressureTimer.Stop()
		}
	}()
	pressure := false
	knownPressure := false
	belowExitRounds := 0
	var lastReservationFailures uint64
	scanInProgress := false
	attachmentActive := s.dataPlane != nil && s.dataPlane.isEnabled()
	resetSweepTimer := func() {
		if !sweepTimer.Stop() {
			select {
			case <-sweepTimer.C:
			default:
			}
		}
		sweepTimer.Reset(sharedFlowSweepInterval)
		sweepTimerChannel = sweepTimer.C
	}
	defer sweepTimer.Stop()
	for {
		backend := s.sharedBackendInstance()
		if backend == nil {
			return
		}
		sweepRequested := false
		select {
		case <-ctx.Done():
			return
		case <-sweepTimerChannel:
			sweepRequested = true
		case <-pressureTimerChannel:
			sweepRequested = true
		case <-backend.TCPFlowWake():
			resetReleaseTimer(backend)
			knownPressure, sweepRequested = updateSharedFlowWakeState(
				pressure,
				knownPressure,
				scanInProgress,
				backend.KnownFlowUsage(),
			)
			if !sweepRequested {
				continue
			}
		case <-releaseTimerChannel:
		}
		now := time.Now()
		if !sweepRequested {
			_, flushErr := backend.FlushReleasedTCPFlows(now, sharedFlowReleaseFlushBudget)
			if flushErr != nil {
				s.janitorWarnings.warn(s.inbound.logWarn, "flush released shared-network TCP flows: ", flushErr)
			}
			resetReleaseTimer(backend)
			continue
		}
		if s.dataPlane == nil || !s.dataPlane.isEnabled() {
			attachmentActive = false
			pressure = false
			knownPressure = false
			belowExitRounds = 0
			scanInProgress = false
			resetSweepTimer()
			resetPressureTimer(false)
			continue
		}
		if !attachmentActive {
			attachmentActive = true
		}
		reservationPressure := false
		reservationFailures, failureErr := backend.TokenReservationFailures()
		if failureErr != nil {
			s.janitorWarnings.warn(s.inbound.logWarn, "read shared-network token reservation failures: ", failureErr)
		} else {
			reservationPressure = reservationFailures > lastReservationFailures
			lastReservationFailures = reservationFailures
		}
		maxIdle := sharedFlowMaxIdle
		if pressure || reservationPressure {
			maxIdle = sharedFlowPressureMaxIdle
		}
		result, err := backend.SweepOrphanedFlows(maxIdle, sharedFlowFallbackScanBudget)
		if err != nil {
			if reservationPressure {
				pressure = true
			}
			s.janitorWarnings.warn(s.inbound.logWarn, "sweep orphaned shared-network flows: ", err)
			resetPressureTimer(pressure || scanInProgress)
		} else {
			scanInProgress = !result.Complete
			if result.Complete {
				resetSweepTimer()
			}
			if !result.Complete {
				backend.RequestMaintenance()
				resetSweepTimer()
				resetPressureTimer(true)
				continue
			}
			entered, exited := false, false
			pressure, belowExitRounds, entered, exited = updateSharedFlowPressure(
				pressure,
				belowExitRounds,
				result.Usage,
			)
			if reservationPressure {
				pressure = true
				belowExitRounds = 0
			}
			if entered {
				log.Warnln("[EBPF] shared-network proxy map pressure: state=%d/%d, max_idle=%s",
					result.Usage.Entries, result.Usage.Capacity, sharedFlowPressureMaxIdle)
			} else if exited {
				log.Infoln("[EBPF] shared-network proxy map pressure cleared: state=%d/%d, sweep_interval=%s",
					result.Usage.Entries, result.Usage.Capacity, sharedFlowSweepInterval)
			}
		}
		resetPressureTimer(pressure || scanInProgress)
		resetSweepTimer()
	}
}

func updateSharedFlowWakeState(pressure, knownPressure, scanInProgress bool, usage ECommon.MapUsage) (bool, bool) {
	if !knownPressure {
		knownPressure = flowUsagePressure(false, usage)
	} else if !flowUsagePressure(true, usage) {
		knownPressure = false
	}
	return knownPressure, pressure || knownPressure || scanInProgress
}

func flowUsagePressure(active bool, usage ECommon.MapUsage) bool {
	if usage.Capacity == 0 {
		return false
	}
	if active {
		return uint64(usage.Entries)*100 > uint64(usage.Capacity)*sharedFlowPressureExitPercent
	}
	return uint64(usage.Entries)*100 >= uint64(usage.Capacity)*sharedFlowPressureEnterPercent
}

func updateSharedFlowPressure(active bool, belowExitRounds int, usage ECommon.MapUsage) (bool, int, bool, bool) {
	if usage.Capacity == 0 {
		return active, 0, false, false
	}
	if !active {
		if uint64(usage.Entries)*100 >= uint64(usage.Capacity)*sharedFlowPressureEnterPercent {
			return true, 0, true, false
		}
		return false, 0, false, false
	}
	if uint64(usage.Entries)*100 > uint64(usage.Capacity)*sharedFlowPressureExitPercent {
		return true, 0, false, false
	}
	belowExitRounds++
	if belowExitRounds < sharedFlowPressureExitRounds {
		return true, belowExitRounds, false, false
	}
	return false, 0, false, true
}

var _ = unix.ENOENT
var _ = C.EBPF
var _ = N.NewCustomAddr
var _ = inbound.ApplyAdditions
var _ = net.IPv4len
