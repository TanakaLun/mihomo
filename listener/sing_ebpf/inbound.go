//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/network"
)

// Listener is the eBPF inbound listener.
type Listener interface {
	Close() error
	Address() string
}

type Inbound struct {
	ctx       context.Context
	tunnel    C.Tunnel
	additions []inbound.Addition
	options   LC.EBPF

	cgroupPath         string
	enableTCP          bool
	enableUDP          bool
	dnsMode            string
	redirectIPv4Prefix netip.Prefix
	redirectIPv6Prefix netip.Prefix
	cgroupMapCapacity  ECommon.CgroupMapCapacity
	cgroupPolicy       ECommon.CgroupPolicy
	udpTimeout         time.Duration

	listeners internalListenerSet

	backendAccess sync.RWMutex
	backend       *ECommon.CgroupBackend

	protectRegistered bool

	localRoutes []*localRoute

	udpClientTable udpClientTable
	udpWarnings    udpWarningLimiters

	bypassRuleSetAccess   sync.Mutex
	bypassRuleSet         []P.RuleProvider
	bypassRuleSetCallback io.Closer
	bypassRuleSetStarted  bool

	udpPeriodicStop chan struct{}
	udpPeriodicDone chan struct{}

	closeOnce sync.Once
}

// New creates, prepares, and attaches the eBPF inbound.
func New(ctx context.Context, options LC.EBPF, tunnel C.Tunnel, additions ...inbound.Addition) (Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{inbound.WithInName("DEFAULT-EBPF")}
	}
	enableTCP, enableUDP := parseNetworkOptions(options.Network)
	if !enableTCP && !enableUDP {
		return nil, E.New("eBPF inbound network must include tcp or udp")
	}
	cgroupPath, err := normalizeCgroupPath(options.CgroupPath)
	if err != nil {
		return nil, err
	}
	redirectIPv4Prefix, redirectIPv6Prefix, err := normalizeRedirectAddresses(options.RedirectAddress)
	if err != nil {
		return nil, err
	}
	dnsMode, err := normalizeDNSMode(options.DNSMode)
	if err != nil {
		return nil, err
	}
	cgroupMapCapacity, err := normalizeCgroupMapCapacity(options.MapCapacity)
	if err != nil {
		return nil, err
	}
	includeUIDRanges, err := parseUIDRanges(options.IncludeUID, options.IncludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse include_uid_range")
	}
	excludeUIDRanges, err := parseUIDRanges(options.ExcludeUID, options.ExcludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse exclude_uid_range")
	}
	excludeUIDRanges = append(excludeUIDRanges, platformExcludedUIDRanges(runtime.GOOS)...)
	udpTimeout := time.Duration(options.UDPTimeout)
	if udpTimeout == 0 {
		udpTimeout = 5 * time.Minute
	}

	inboundListener := &Inbound{
		ctx:                ctx,
		tunnel:             tunnel,
		additions:          additions,
		options:            options,
		cgroupPath:         cgroupPath,
		enableTCP:          enableTCP,
		enableUDP:          enableUDP,
		dnsMode:            dnsMode,
		redirectIPv4Prefix: redirectIPv4Prefix,
		redirectIPv6Prefix: redirectIPv6Prefix,
		cgroupMapCapacity:  cgroupMapCapacity,
		udpTimeout:         udpTimeout,
		cgroupPolicy: ECommon.CgroupPolicy{
			HijackDNS:  dnsMode == dnsModeHijack,
			IncludeUID: includeUIDRanges,
			ExcludeUID: excludeUIDRanges,
		},
	}

	rp, ok := tunnel.(P.Tunnel)
	if !ok {
		return nil, E.New("tunnel does not expose rule providers")
	}
	for _, ruleSetTag := range options.BypassRuleSet {
		ruleSet, loaded := rp.RuleProviders()[ruleSetTag]
		if !loaded {
			return nil, E.New("parse bypass_rule_set: rule-set not found: ", ruleSetTag)
		}
		inboundListener.bypassRuleSet = append(inboundListener.bypassRuleSet, ruleSet)
	}

	if err = inboundListener.start(); err != nil {
		_ = inboundListener.Close()
		return nil, err
	}
	return inboundListener, nil
}

func parseNetworkOptions(networks []string) (tcp bool, udp bool) {
	if len(networks) == 0 {
		return true, true
	}
	for _, networkName := range networks {
		switch strings.ToLower(networkName) {
		case network.NetworkTCP:
			tcp = true
		case network.NetworkUDP:
			udp = true
		}
	}
	return
}

func (i *Inbound) start() error {
	policy := i.cgroupPolicy
	policy.EnableBypassCIDR = true
	backend, err := ECommon.PrepareCgroup(ECommon.CgroupConfig{
		Path:         i.cgroupPath,
		EnableTCP:    i.enableTCP,
		EnableUDP:    i.enableUDP,
		RedirectIPv4: i.redirectIPv4Prefix,
		RedirectIPv6: i.redirectIPv6Prefix,
		MapCapacity:  i.cgroupMapCapacity,
		Policy:       policy,
	})
	if err != nil {
		return err
	}
	i.setBackend(backend)

	if protectFunc := backend.SocketProtectFunc(); protectFunc != nil {
		dialer.RegisterSocketProtectFunc(func(_ context.Context, network, address string, rawConn syscall.RawConn) error {
			return protectFunc(network, address, rawConn)
		})
		i.protectRegistered = true
	}

	if err = i.startBypassRuleSets(); err != nil {
		return err
	}
	if err = i.setupLocalRoutes(); err != nil {
		return err
	}
	if err = i.listeners.start(
		i.enableTCP,
		i.enableUDP,
		i.redirectIPv4Prefix.IsValid(),
		i.redirectIPv6Prefix.IsValid(),
		i.newListener,
	); err != nil {
		return err
	}
	if err = backend.LoadPrograms(i.listeners.selectedPort()); err != nil {
		return err
	}
	if err = backend.Attach(); err != nil {
		return err
	}

	i.startUDPPeriodic()

	bypassIPv4Count, bypassIPv6Count := backend.BypassCIDRCount()
	log.Infoln("[EBPF] inbound attached: cgroup=%s, listen_port=%d, dns_mode=%s, self_bypass=%s, redirect_address=[%s], bypass_cidr={ipv4:%d, ipv6:%d}, programs=[%s]",
		backend.CgroupPath(),
		i.listeners.selectedPort(),
		i.dnsMode,
		backend.SelfBypassMode(),
		strings.Join(i.redirectAddressStrings(), ", "),
		bypassIPv4Count,
		bypassIPv6Count,
		strings.Join(backend.AttachedPrograms(), ", "),
	)
	if len(i.bypassRuleSet) > 0 {
		log.Infoln("[EBPF] bypass_rule_set will populate after rule-providers finish loading; see the next 'refreshed bypass CIDR policy' log")
	}
	return nil
}

func (i *Inbound) Close() error {
	var closeErr error
	i.closeOnce.Do(func() {
		i.stopUDPPeriodic()
		i.stopBypassRuleSets()
		resolver.EBFPBypassIPSet.Store(nil)
		backend := i.backendInstance()
		if backend != nil {
			closeErr = backend.Close()
			if backend.IsClosed() {
				i.setBackend(nil)
			}
		}
		i.unregisterSocketProtect()
		closeErr = E.Errors(closeErr, i.listeners.close())
		closeErr = E.Errors(closeErr, i.removeLocalRoutes())
	})
	return closeErr
}

func (i *Inbound) Address() string {
	address := "eBPF(cgroup=" + i.backendCgroupPath() + ", listen_port=" + fmt.Sprintf("%d", i.listeners.selectedPort()) + ")"
	return address
}

func (i *Inbound) backendCgroupPath() string {
	if backend := i.backendInstance(); backend != nil {
		return backend.CgroupPath()
	}
	return ""
}

func (i *Inbound) redirectAddressStrings() []string {
	addresses := make([]string, 0, 2)
	if i.redirectIPv4Prefix.IsValid() {
		addresses = append(addresses, i.redirectIPv4Prefix.String())
	}
	if i.redirectIPv6Prefix.IsValid() {
		addresses = append(addresses, i.redirectIPv6Prefix.String())
	}
	return addresses
}

func (i *Inbound) backendInstance() *ECommon.CgroupBackend {
	i.backendAccess.RLock()
	defer i.backendAccess.RUnlock()
	return i.backend
}

func (i *Inbound) setBackend(backend *ECommon.CgroupBackend) {
	i.backendAccess.Lock()
	i.backend = backend
	i.backendAccess.Unlock()
}

func (i *Inbound) unregisterSocketProtect() {
	if !i.protectRegistered {
		return
	}
	dialer.UnregisterSocketProtectFunc()
	i.protectRegistered = false
}

func (i *Inbound) startUDPPeriodic() {
	i.udpPeriodicStop = make(chan struct{})
	i.udpPeriodicDone = make(chan struct{})
	go i.udpPeriodicLoop(i.udpPeriodicStop, i.udpPeriodicDone)
}

func (i *Inbound) stopUDPPeriodic() {
	if i.udpPeriodicStop == nil {
		return
	}
	close(i.udpPeriodicStop)
	<-i.udpPeriodicDone
	i.udpPeriodicStop = nil
}

func (i *Inbound) udpPeriodicLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	interval := i.udpTimeout / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	bypassTicker := time.NewTicker(3 * time.Second)
	defer bypassTicker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			i.udpClientTable.sweep(time.Now(), i.udpTimeout, i)
		case <-bypassTicker.C:
			i.refreshBypassCIDRPeriodic()
		}
	}
}

func (i *Inbound) refreshBypassCIDRPeriodic() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	updated, err := i.refreshBypassCIDRsLocked()
	if err != nil {
		if backend := i.backendInstance(); backend != nil && !backend.IsClosed() {
			log.Debugln("[EBPF] refresh bypass CIDR: %s", err.Error())
		}
		return
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
}

func (i *Inbound) logBypassCIDRUpdate() {
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	ipv4Count, ipv6Count := backend.BypassCIDRCount()
	log.Debugln("[EBPF] refreshed bypass CIDR policy: ipv4=%d, ipv6=%d", ipv4Count, ipv6Count)
}

func localInterfacePrefixes() []netip.Prefix {
	iface.FlushCache()
	networkInterfaces, _ := iface.Interfaces()
	var prefixes []netip.Prefix
	for _, networkInterface := range networkInterfaces {
		for _, prefix := range networkInterface.Addresses {
			if !prefix.IsValid() {
				continue
			}
			prefix = prefix.Masked()
			address := prefix.Addr().Unmap()
			prefixBits := prefix.Bits()
			if prefix.Addr().Is4In6() {
				if prefixBits < 96 {
					continue
				}
				prefixBits -= 96
			}
			if address.IsUnspecified() || address.IsLoopback() {
				continue
			}
			prefixes = append(prefixes, netip.PrefixFrom(address, prefixBits).Masked())
		}
	}
	return prefixes
}
