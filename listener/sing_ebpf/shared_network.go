//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"sync"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"

	tun "github.com/metacubex/sing-tun"
)

type sharedNetwork struct {
	inbound        *Inbound
	interfaces     []string
	sharedBackend  *ECommon.SharedNetworkBackend
	tcManager      *sharedTCManager
	listeners      internalListenerSet
	udpClientTable udpClientTable
	udpWarnings    udpWarningLimiters
	mapCapacity    uint32

	lifecycleAccess sync.RWMutex
	backendAccess   sync.RWMutex
	periodicStop    chan struct{}
	periodicDone    chan struct{}
}

func newSharedNetwork(inbound *Inbound, options []string, mapCapacity uint32) *sharedNetwork {
	return &sharedNetwork{
		inbound:     inbound,
		interfaces:  append([]string(nil), options...),
		mapCapacity: mapCapacity,
	}
}

func (s *sharedNetwork) Start(cgroupBackend *ECommon.CgroupBackend) error {
	if err := s.startListeners(); err != nil {
		return E.Errors(err, s.closeListeners())
	}
	backend, err := ECommon.PrepareSharedNetwork(cgroupBackend, ECommon.SharedNetworkConfig{
		ListenerPort: s.listeners.selectedPort(),
		EnableTCP:    s.inbound.enableTCP,
		EnableUDP:    s.inbound.enableUDP,
		HijackDNS:    s.inbound.dnsMode == dnsModeHijack,
		RedirectIPv4: s.inbound.redirectIPv4Prefix,
		RedirectIPv6: s.inbound.redirectIPv6Prefix,
		MapCapacity:  s.mapCapacity,
		UDPTimeout:   s.inbound.udpTimeout,
	})
	if err != nil {
		return E.Errors(err, s.closeListeners())
	}
	s.setSharedBackend(backend)
	if err = backend.SetBypassCIDRState(s.inbound.currentBypassCIDR()); err != nil {
		return E.Errors(err, s.Close())
	}
	s.tcManager = &sharedTCManager{
		backend:     backend,
		interfaces:  s.interfaces,
		enableIPv4:  s.inbound.redirectIPv4Prefix.IsValid(),
		attachments: make(map[string]*sharedTCAttachment),
	}
	if monitor, monitorErr := tun.NewNetworkUpdateMonitor(log.SingLogger); monitorErr == nil {
		s.tcManager.networkMonitor = monitor
	}
	if err = s.tcManager.Start(); err != nil {
		return E.Errors(err, s.Close())
	}
	s.startUDPPeriodic()
	log.Infoln("[EBPF] shared-network TC interception ready: downstream_interfaces=[%s], redirect_listener_port=%d, dns_mode=%s, tc_priority=%d, map_capacity=%d, programs=[tc/ingress, tc/egress]",
		s.tcManager.InterfaceString(),
		s.listeners.selectedPort(),
		s.inbound.dnsMode,
		sharedNetworkTCPriority,
		s.mapCapacity,
	)
	return nil
}

func (s *sharedNetwork) startListeners() error {
	return s.listeners.start(
		s.inbound.enableTCP,
		s.inbound.enableUDP,
		s.inbound.redirectIPv4Prefix.IsValid(),
		s.inbound.redirectIPv6Prefix.IsValid(),
		s.newListener,
	)
}

func (s *sharedNetwork) newListener(network string, ipv6 bool, port uint16) (*internalListener, error) {
	return newInternalListener(s.inbound.socketControl(ipv6), network, ipv6, port, s)
}

func (s *sharedNetwork) startUDPPeriodic() {
	s.periodicStop = make(chan struct{})
	s.periodicDone = make(chan struct{})
	go s.udpPeriodicLoop(s.periodicStop, s.periodicDone)
}

func (s *sharedNetwork) stopUDPPeriodic() {
	if s.periodicStop == nil {
		return
	}
	close(s.periodicStop)
	<-s.periodicDone
	s.periodicStop = nil
}

func (s *sharedNetwork) udpPeriodicLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	interval := s.inbound.udpTimeout / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.udpClientTable.sweep(time.Now(), s.inbound.udpTimeout, s.releaseFlows)
		}
	}
}

func (s *sharedNetwork) InterfaceUpdated() {
	s.udpClientTable.sweep(time.Now(), 0, s.releaseFlows)
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	if manager := s.tcManager; manager != nil {
		manager.Wake()
	}
}

func (s *sharedNetwork) Close() error {
	if s == nil {
		return nil
	}
	s.lifecycleAccess.Lock()
	defer s.lifecycleAccess.Unlock()
	s.stopUDPPeriodic()
	if s.tcManager != nil {
		if err := s.tcManager.Close(); err != nil {
			return err
		}
		s.tcManager = nil
	}
	var backendErr error
	if backend := s.sharedBackendInstance(); backend != nil {
		backendErr = backend.Close()
		if backend.IsClosed() {
			s.setSharedBackend(nil)
		}
	}
	return E.Errors(backendErr, s.closeListeners())
}

func (s *sharedNetwork) closeListeners() error {
	return s.listeners.close()
}

func (s *sharedNetwork) IsClosed() bool {
	if s == nil {
		return true
	}
	s.lifecycleAccess.RLock()
	defer s.lifecycleAccess.RUnlock()
	return s.tcManager == nil && s.sharedBackendInstance() == nil && s.listeners.isClosed()
}

func (s *sharedNetwork) sharedBackendInstance() *ECommon.SharedNetworkBackend {
	s.backendAccess.RLock()
	defer s.backendAccess.RUnlock()
	return s.sharedBackend
}

func (s *sharedNetwork) setSharedBackend(backend *ECommon.SharedNetworkBackend) {
	s.backendAccess.Lock()
	s.sharedBackend = backend
	s.backendAccess.Unlock()
}

func (s *sharedNetwork) acceptWarn(message ...any) {
	s.udpWarnings.accept.warn(s.inbound.logWarn, message...)
}

func (s *sharedNetwork) packetWarn(message ...any) {
	s.udpWarnings.packetInfo.warn(s.inbound.logWarn, message...)
}

var _ internalListenerHandler = (*sharedNetwork)(nil)
