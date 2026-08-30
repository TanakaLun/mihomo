//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"
)

// Listener is the eBPF inbound listener.
type Listener interface {
	Close() error
	Address() string
	InterfaceUpdated()
}

type fakeIPRangeProvider interface {
	FakeIPRanges() (netip.Prefix, netip.Prefix)
}

type Inbound struct {
	ctx           context.Context
	tunnel        C.Tunnel
	additions     []inbound.Addition
	mode          string
	localEnabled  bool
	sharedEnabled bool
	enableTCP     bool
	enableUDP     bool

	localDNSMode        string
	sharedDNSMode       string
	localIPv6           bool
	sharedIPv6          bool
	sharedBypassPrivate bool
	tcPriority          uint16
	localPolicy         ECommon.LocalPolicy
	sharedOptions       LC.EBPFShared
	sharedIncludeMAC    []ECommon.MACAddress
	sharedExcludeMAC    []ECommon.MACAddress
	fakeIPIPv4Prefix    netip.Prefix
	fakeIPIPv6Prefix    netip.Prefix
	androidUIDOptions   *androidUIDOptions
	udpTimeout          time.Duration

	selfBypass       *ECommon.SelfBypass
	selfBypassCgroup bool
	processTracker   *ECommon.ProcessTracker

	listeners         internalListenerSet
	udpClientTable    udpClientTable
	udpReplySockets   udpReplySocketPool
	udpWarnings       udpWarningLimiters
	interfaceWarnings interfaceWarningLimiters

	tcDataPlane       *tcDataPlane
	interfaceMonitor  tcInterfaceMonitor
	tcDataPlaneAccess sync.RWMutex
	lifecycleAccess   sync.Mutex

	bypassRuleSetAccess   sync.Mutex
	bypassRuleSet         []P.RuleProvider
	bypassRuleSetCallback io.Closer
	bypassRuleSetStarted  bool
	bypassCIDR            []netip.Prefix

	protectRegistered bool

	closeOnce sync.Once
}

type interfaceWarningLimiters struct {
	inventory        warningLimiter
	topology         warningLimiter
	defaultInterface warningLimiter
	infrastructure   warningLimiter
	hostPolicy       warningLimiter
	reconcile        warningLimiter
}

func (i *Inbound) logWarn(format string, args ...any) {
	log.Warnln(format, args...)
}

// New creates, prepares, and attaches the unified TC eBPF inbound.
func New(ctx context.Context, options LC.EBPF, tunnel C.Tunnel, additions ...inbound.Addition) (Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{inbound.WithInName("DEFAULT-EBPF")}
	}
	mode, localEnabled, sharedEnabled, err := normalizeMode(options.Mode)
	if err != nil {
		return nil, err
	}
	if err = validateLocalOptions(localEnabled, options.Local); err != nil {
		return nil, err
	}
	if err = validateSharedOptions(sharedEnabled, options.Shared); err != nil {
		return nil, err
	}
	if err = validateAndroidUIDOptions(runtime.GOOS, options.Local); err != nil {
		return nil, err
	}
	localDNSMode, err := normalizeDNSMode(options.Local.DNSMode)
	if err != nil {
		return nil, E.Cause(err, "parse local.dns_mode")
	}
	sharedDNSMode, err := normalizeDNSMode(options.Shared.DNSMode)
	if err != nil {
		return nil, E.Cause(err, "parse shared.dns_mode")
	}
	includeUIDRanges, err := parseUIDRanges(options.Local.IncludeUID, options.Local.IncludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse include_uid_range")
	}
	excludeUIDRanges, err := parseUIDRanges(options.Local.ExcludeUID, options.Local.ExcludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse exclude_uid_range")
	}
	sharedOptions := LC.EBPFShared{}
	if sharedEnabled {
		sharedOptions, err = normalizeSharedOptions(options.Shared)
		if err != nil {
			return nil, err
		}
	}
	sharedIncludeMAC, err := parseSharedMACAddresses(
		"include_mac_address",
		sharedOptions.IncludeMACAddress,
	)
	if err != nil {
		return nil, err
	}
	sharedExcludeMAC, err := parseSharedMACAddresses(
		"exclude_mac_address",
		sharedOptions.ExcludeMACAddress,
	)
	if err != nil {
		return nil, err
	}
	enableTCP := len(options.Network) == 0 || containsNetwork(options.Network, "tcp")
	enableUDP := len(options.Network) == 0 || containsNetwork(options.Network, "udp")

	var selfBypass *ECommon.SelfBypass
	if localEnabled {
		selfBypass, err = ECommon.NewSelfBypass()
		if err != nil {
			return nil, E.Cause(err, "prepare eBPF self-bypass sockets")
		}
	}

	inbound := &Inbound{
		ctx:                 ctx,
		tunnel:              tunnel,
		additions:           additions,
		mode:                mode,
		localEnabled:        localEnabled,
		sharedEnabled:       sharedEnabled,
		enableTCP:           enableTCP,
		enableUDP:           enableUDP,
		selfBypass:          selfBypass,
		localDNSMode:        localDNSMode,
		sharedDNSMode:       sharedDNSMode,
		localIPv6:           localEnabled && enabledByDefault(options.Local.IPv6),
		sharedIPv6:          sharedEnabled && enabledByDefault(options.Shared.IPv6),
		sharedBypassPrivate: options.Shared.BypassPrivateAddress == nil || *options.Shared.BypassPrivateAddress,
		tcPriority:          options.TCPriority,
		sharedOptions:       sharedOptions,
		sharedIncludeMAC:    sharedIncludeMAC,
		sharedExcludeMAC:    sharedExcludeMAC,
		localPolicy: ECommon.LocalPolicy{
			EnableBypassCIDR:     true,
			DNSMode:              toCommonDNSMode(localDNSMode),
			BypassPrivateAddress: options.Local.BypassPrivateAddress == nil || *options.Local.BypassPrivateAddress,
			IncludeUIDConfigured: len(options.Local.IncludeUID) > 0 ||
				len(options.Local.IncludeUIDRange) > 0 || len(options.Local.IncludePackage) > 0,
			IncludeUID: includeUIDRanges,
			ExcludeUID: excludeUIDRanges,
		},
		androidUIDOptions: newAndroidUIDOptions(options.Local),
	}
	if inbound.tcPriority == 0 {
		inbound.tcPriority = defaultTCPriority
	}
	inbound.fakeIPIPv4Prefix, inbound.fakeIPIPv6Prefix = resolver.EBFPFakeIPRanges.Get()
	if err = inbound.normalizeFakeIPPrefixes(); err != nil {
		return nil, err
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
		inbound.bypassRuleSet = append(inbound.bypassRuleSet, ruleSet)
	}
	udpTimeout := 5 * time.Minute
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	}
	inbound.udpTimeout = udpTimeout
	return inbound, nil
}

func containsNetwork(networks []string, target string) bool {
	for _, network := range networks {
		if network == target {
			return true
		}
	}
	return false
}

func (i *Inbound) start() error {
	if i.localEnabled && i.androidUIDOptions != nil {
		if err := i.resolveAndroidUIDPolicy(); err != nil {
			return E.Cause(err, "resolve Android UID policy")
		}
	}
	if i.selfBypass != nil {
		dialer.RegisterSocketProtectFunc(func(_ context.Context, network, address string, rawConn syscall.RawConn) error {
			return i.selfBypass.RegisterSocket(rawConn)
		})
		i.protectRegistered = true
	}
	if err := i.startSelfBypass(); err != nil {
		log.Debugln("[EBPF] cgroup socket tracking unavailable; using socket-cookie registration: %s", err.Error())
	}
	i.startProcessTracker()
	defaultInterface := i.currentDefaultInterfaceName()
	localInterface := ""
	if i.localEnabled {
		localInterface = defaultInterface
		if localInterface == "" {
			log.Warnln("[EBPF] default interface unavailable; local TC eBPF interception is paused")
		}
	}
	sharedInterfaces := activeSharedInterfaces(i.sharedOptions.Interface, defaultInterface)
	if err := i.startTCListeners(); err != nil {
		return err
	}
	backendConfig := ECommon.TCConfig{
		ListenerPort:        i.listeners.selectedPort(),
		EnableLocal:         i.localEnabled,
		EnableShared:        i.sharedEnabled,
		EnableIPv4:          true,
		EnableLocalIPv6:     i.localIPv6,
		EnableSharedIPv6:    i.sharedIPv6,
		EnableTCP:           i.enableTCP,
		EnableUDP:           i.enableUDP,
		LocalPolicy:         i.localPolicy,
		SharedDNSMode:       toCommonDNSMode(i.sharedDNSMode),
		SharedBypassPrivate: i.sharedBypassPrivate,
		FakeIPIPv4:          i.fakeIPIPv4Prefix,
		FakeIPIPv6:          i.fakeIPIPv6Prefix,
		IncludeSourceCIDR:   i.sharedOptions.IncludeSourceCIDR,
		ExcludeSourceCIDR:   i.sharedOptions.ExcludeSourceCIDR,
		IncludeSourceMAC:    i.sharedIncludeMAC,
		ExcludeSourceMAC:    i.sharedExcludeMAC,
		TrackProcess:        i.processTracker != nil,
	}
	if i.selfBypass != nil {
		backendConfig.SelfBypassMap = i.selfBypass.Map()
	}
	backend, err := ECommon.PrepareTC(backendConfig)
	if err != nil && i.processTracker != nil {
		trackingErr := err
		_ = i.processTracker.Close()
		i.processTracker = nil
		backendConfig.TrackProcess = false
		backend, err = ECommon.PrepareTC(backendConfig)
		if err == nil {
			log.Debugln("[EBPF] cgroup process tracking unavailable; using userspace process search: %s", trackingErr.Error())
		}
	}
	if err != nil {
		return err
	}
	if err = i.listeners.registerTCTCPListeners(backend); err != nil {
		return E.Errors(err, backend.Close())
	}
	dataPlane, err := startTCDataPlane(
		backend,
		i.localEnabled,
		i.localIPv6 || i.sharedIPv6,
		localInterface,
		sharedInterfaces,
		i.hostAddresses(),
		len(i.sharedIncludeMAC)+len(i.sharedExcludeMAC) > 0,
		i.tcPriority,
	)
	if err != nil {
		return err
	}
	i.setTCDataPlane(dataPlane)
	if err = i.startBypassRuleSets(); err != nil {
		return E.Cause(err, "initialize TC eBPF bypass_rule_set")
	}
	if err = backend.Enable(); err != nil {
		return err
	}
	if err = i.startTCInterfaceMonitor(); err != nil {
		return err
	}
	network := "tcp"
	if i.enableTCP && i.enableUDP {
		network = "tcp,udp"
	} else if i.enableUDP {
		network = "udp"
	}
	log.Infoln("[EBPF] TC active: mode=%s, network=%s, local_ipv6=%v, shared_ipv6=%v, default_interface=%s, local_interface=%s, shared_interfaces=[%s], attachments=[%s], listeners=[%s], delivery_interface=%s, routing_mark=0x%x, routing_table=%d, tc_priority=%d",
		i.mode,
		network,
		i.localIPv6,
		i.sharedIPv6,
		defaultInterface,
		localInterface,
		joinStringList(i.sharedOptions.Interface),
		joinStringList(dataPlane.attachmentDescriptions()),
		i.listeners.String(),
		dataPlane.deliveryName(),
		dataPlane.routing.mark,
		dataPlane.routing.table,
		i.tcPriority,
	)
	return nil
}

func joinStringList(values []string) string {
	joined := ""
	for index, value := range values {
		if index > 0 {
			joined += ", "
		}
		joined += value
	}
	return joined
}

func (i *Inbound) startSelfBypass() error {
	if i.selfBypass == nil || i.selfBypassCgroup {
		return nil
	}
	if err := i.selfBypass.AttachCgroup(); err != nil {
		return err
	}
	i.selfBypassCgroup = true
	return nil
}

func (i *Inbound) startProcessTracker() {
	if !i.localEnabled || i.processTracker != nil {
		return
	}
	tracker, err := ECommon.AttachProcessTracker(ECommon.ProcessTrackerConfig{
		EnableTCP:  i.enableTCP,
		EnableUDP:  i.enableUDP,
		EnableIPv6: i.localIPv6,
	})
	if err != nil {
		log.Debugln("[EBPF] cgroup process tracking unavailable; using userspace process search: %s", err.Error())
		return
	}
	i.processTracker = tracker
}

func (i *Inbound) setTCDataPlane(dataPlane *tcDataPlane) {
	i.tcDataPlaneAccess.Lock()
	i.tcDataPlane = dataPlane
	i.tcDataPlaneAccess.Unlock()
}

func (i *Inbound) takeTCDataPlane() *tcDataPlane {
	i.tcDataPlaneAccess.Lock()
	dataPlane := i.tcDataPlane
	i.tcDataPlane = nil
	i.tcDataPlaneAccess.Unlock()
	return dataPlane
}

func (i *Inbound) tcBackend() *ECommon.TCBackend {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.backend
}

func (i *Inbound) reconcileTCDataPlane(localInterface string, sharedInterfaces []string, hostAddresses []netip.Addr) error {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.reconcile(localInterface, sharedInterfaces, hostAddresses)
}

func (i *Inbound) Close() error {
	var closeErr error
	i.closeOnce.Do(func() {
		if i.protectRegistered {
			dialer.UnregisterSocketProtectFunc()
			i.protectRegistered = false
		}
		monitorErr := i.stopTCInterfaceMonitor()
		i.stopBypassRuleSets()
		dataPlane := i.takeTCDataPlane()
		disableErr := dataPlane.disable()
		listenerErr := i.listeners.close()
		udpReplySocketErr := i.udpReplySockets.close()
		dataPlaneErr := dataPlane.Close()
		var processTrackerErr error
		if i.processTracker != nil {
			processTrackerErr = i.processTracker.Close()
			i.processTracker = nil
		}
		var selfBypassErr error
		if i.selfBypass != nil {
			selfBypassErr = i.selfBypass.Close()
			i.selfBypass = nil
		}
		closeErr = E.Errors(monitorErr, disableErr, listenerErr, udpReplySocketErr, dataPlaneErr, processTrackerErr, selfBypassErr)
	})
	return closeErr
}

func (i *Inbound) Address() string {
	if i.tcDataPlane == nil {
		return "eBPF(TC)"
	}
	return "eBPF(TC, listen_port=" + fmt.Sprint(i.listeners.selectedPort()) + ")"
}
