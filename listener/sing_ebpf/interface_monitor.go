//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/log"
	"github.com/sagernet/netlink"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/x/list"
)

type tcInterfaceMonitor struct {
	access                   sync.Mutex
	network                  tun.NetworkUpdateMonitor
	networkOwned             bool
	networkCallback          *list.Element[tun.NetworkUpdateCallback]
	defaultInterface         tun.DefaultInterfaceMonitor
	defaultInterfaceOwned    bool
	defaultInterfaceCallback *list.Element[tun.DefaultInterfaceUpdateCallback]
	defaultInterfaceName     string
	cancel                   context.CancelFunc
	updates                  chan struct{}
}

func (i *Inbound) InterfaceUpdated() {
	i.setDefaultInterfaceName(i.currentDefaultInterfaceName())
}

func (i *Inbound) startTCInterfaceMonitor() error {
	networkMonitor, err := tun.NewNetworkUpdateMonitor(log.SingLogger)
	if err != nil {
		return E.Cause(err, "create TC eBPF network monitor")
	}
	networkOwned := true
	defaultInterfaceMonitor, err := tun.NewDefaultInterfaceMonitor(
		networkMonitor,
		log.SingLogger,
		tun.DefaultInterfaceMonitorOptions{
			InterfaceFinder: sing_tun.DefaultInterfaceFinder,
		},
	)
	if err != nil {
		if networkOwned {
			_ = networkMonitor.Close()
		}
		return E.Cause(err, "create TC eBPF default interface monitor")
	}
	defaultInterfaceOwned := true
	monitorContext, cancel := context.WithCancel(context.Background())
	updates := make(chan struct{}, 1)
	state := &i.interfaceMonitor
	state.access.Lock()
	if state.network != nil {
		state.access.Unlock()
		cancel()
		if defaultInterfaceOwned {
			_ = defaultInterfaceMonitor.Close()
		}
		if networkOwned {
			_ = networkMonitor.Close()
		}
		return nil
	}
	state.network = networkMonitor
	state.networkOwned = networkOwned
	state.defaultInterface = defaultInterfaceMonitor
	state.defaultInterfaceOwned = defaultInterfaceOwned
	state.cancel = cancel
	state.updates = updates
	state.networkCallback = networkMonitor.RegisterCallback(i.notifyTCInterfaceUpdate)
	state.defaultInterfaceCallback = defaultInterfaceMonitor.RegisterCallback(i.defaultInterfaceUpdated)
	state.defaultInterfaceName = interfaceName(defaultInterfaceMonitor.DefaultInterface())
	state.access.Unlock()
	go i.runTCInterfaceUpdates(monitorContext, updates)
	if networkOwned {
		if err := networkMonitor.Start(); err != nil {
			return E.Errors(E.Cause(err, "start TC eBPF network monitor"), i.stopTCInterfaceMonitor())
		}
	}
	if defaultInterfaceOwned {
		if err := defaultInterfaceMonitor.Start(); err != nil {
			return E.Errors(E.Cause(err, "start TC eBPF default interface monitor"), i.stopTCInterfaceMonitor())
		}
	}
	i.notifyTCInterfaceUpdate()
	return nil
}

func (i *Inbound) stopTCInterfaceMonitor() error {
	state := &i.interfaceMonitor
	state.access.Lock()
	networkMonitor := state.network
	networkOwned := state.networkOwned
	networkCallback := state.networkCallback
	defaultInterfaceMonitor := state.defaultInterface
	defaultInterfaceOwned := state.defaultInterfaceOwned
	defaultInterfaceCallback := state.defaultInterfaceCallback
	cancel := state.cancel
	state.network = nil
	state.networkOwned = false
	state.networkCallback = nil
	state.defaultInterface = nil
	state.defaultInterfaceOwned = false
	state.defaultInterfaceCallback = nil
	state.defaultInterfaceName = ""
	state.cancel = nil
	state.updates = nil
	state.access.Unlock()
	if networkMonitor == nil {
		return nil
	}
	if networkCallback != nil {
		networkMonitor.UnregisterCallback(networkCallback)
	}
	if defaultInterfaceMonitor != nil && defaultInterfaceCallback != nil {
		defaultInterfaceMonitor.UnregisterCallback(defaultInterfaceCallback)
	}
	if cancel != nil {
		cancel()
	}
	var closeErr error
	if defaultInterfaceOwned {
		closeErr = defaultInterfaceMonitor.Close()
	}
	if networkOwned {
		closeErr = E.Errors(closeErr, networkMonitor.Close())
	}
	return closeErr
}

func (i *Inbound) defaultInterfaceUpdated(defaultInterface *control.Interface, _ int) {
	i.setDefaultInterfaceName(interfaceName(defaultInterface))
}

func interfaceName(networkInterface *control.Interface) string {
	if networkInterface == nil {
		return ""
	}
	return networkInterface.Name
}

func (i *Inbound) currentDefaultInterfaceName() string {
	state := &i.interfaceMonitor
	state.access.Lock()
	defaultInterfaceMonitor := state.defaultInterface
	state.access.Unlock()
	if defaultInterfaceMonitor == nil {
		return ""
	}
	return interfaceName(defaultInterfaceMonitor.DefaultInterface())
}

func (i *Inbound) setDefaultInterfaceName(interfaceName string) {
	state := &i.interfaceMonitor
	state.access.Lock()
	state.defaultInterfaceName = interfaceName
	updates := state.updates
	active := state.network != nil && updates != nil
	state.access.Unlock()
	if active {
		notifyTCInterfaceUpdate(updates)
	}
}

func (i *Inbound) notifyTCInterfaceUpdate() {
	state := &i.interfaceMonitor
	state.access.Lock()
	updates := state.updates
	active := state.network != nil && updates != nil
	state.access.Unlock()
	if !active {
		return
	}
	notifyTCInterfaceUpdate(updates)
}

func notifyTCInterfaceUpdate(updates chan<- struct{}) {
	select {
	case updates <- struct{}{}:
	default:
	}
}

func (i *Inbound) runTCInterfaceUpdates(ctx context.Context, updates <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-updates:
			i.updateTCInterfaces(ctx)
		}
	}
}

func (i *Inbound) updateTCInterfaces(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if ctx.Err() != nil {
		return
	}
	if err := sing_tun.DefaultInterfaceFinder.Update(); err != nil {
		i.interfaceWarnings.inventory.warn(i.logWarn, "update interfaces for TC eBPF: ", err)
	}
	defaultInterface := i.monitoredDefaultInterfaceName()
	localTCEnabled := i.localTCEnabled()
	localInterface, err := availableLocalTCInterface(localTCEnabled, defaultInterface)
	if err != nil {
		i.interfaceWarnings.topology.warn(i.logWarn, "inspect TC eBPF local interface: ", err)
		return
	}
	if localTCEnabled && localInterface == "" {
		i.interfaceWarnings.defaultInterface.warn(i.logWarn, "default interface unavailable; retaining previous local TC attachment")
	}
	sharedInterfaces := activeSharedInterfaces(i.sharedOptions.Interface, defaultInterface)
	tcSharedInterfaces := sharedInterfaces
	if i.sharedRewriteEnabled() {
		tcSharedInterfaces = nil
	}
	hostAddresses := i.hostAddresses()
	if i.sharedRewrite != nil && i.sharedRewrite.dataPlane != nil {
		previous := i.sharedRewrite.dataPlane.attachmentDescriptions()
		if err = i.sharedRewrite.dataPlane.reconcile(sharedInterfaces, hostAddresses); err != nil {
			i.interfaceWarnings.reconcile.warn(i.logWarn, "refresh shared packet-rewrite interfaces: ", err)
		} else if attachments := i.sharedRewrite.dataPlane.attachmentDescriptions(); !slices.Equal(previous, attachments) {
			log.Debugln("[EBPF] shared packet-rewrite attachments updated: attachments=[%s]", strings.Join(attachments, ", "))
		}
	}
	infrastructureChanged, err := i.repairTCInfrastructure()
	infrastructureHealthy := err == nil
	if err != nil {
		i.interfaceWarnings.infrastructure.warn(i.logWarn, "repair TC eBPF network state: ", err)
	}
	changed, err := i.tcAttachmentStateChanged(localInterface, tcSharedInterfaces)
	if err != nil {
		i.interfaceWarnings.topology.warn(i.logWarn, "inspect TC eBPF interfaces: ", err)
		return
	}
	if !changed {
		if err = i.updateTCHostAddresses(hostAddresses); err != nil {
			i.interfaceWarnings.hostPolicy.warn(i.logWarn, "refresh TC eBPF host addresses: ", err)
		}
		if err = i.updateCgroupHostAddresses(hostAddresses); err != nil {
			i.interfaceWarnings.hostPolicy.warn(i.logWarn, "refresh cgroup eBPF host addresses: ", err)
		}
		if infrastructureChanged && infrastructureHealthy {
			log.Debugln("[EBPF] TC network state restored")
		}
		return
	}
	previousAttachments := i.tcAttachmentDescriptions()
	if err = i.reconcileTCDataPlane(localInterface, tcSharedInterfaces, hostAddresses); err != nil {
		i.interfaceWarnings.reconcile.warn(i.logWarn, "refresh TC eBPF interfaces: ", err)
		return
	}
	log.Debugln("[EBPF] TC attachments updated: %s -> [%s]",
		strings.Join(previousAttachments, ", "),
		strings.Join(i.tcAttachmentDescriptions(), ", "))
}

func (i *Inbound) updateCgroupHostAddresses(hostAddresses []netip.Addr) error {
	cgroupBackend := i.cgroupBackendInstance()
	if cgroupBackend == nil {
		return nil
	}
	return cgroupBackend.UpdateHostAddresses(hostAddresses)
}

func (i *Inbound) repairTCInfrastructure() (bool, error) {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return false, nil
	}
	return i.tcDataPlane.repairInfrastructure()
}

func (i *Inbound) monitoredDefaultInterfaceName() string {
	state := &i.interfaceMonitor
	state.access.Lock()
	defer state.access.Unlock()
	return state.defaultInterfaceName
}

func availableLocalTCInterface(enabled bool, interfaceName string) (string, error) {
	if !enabled || interfaceName == "" {
		return "", nil
	}
	_, err := netlink.LinkByName(interfaceName)
	if err != nil && tcLinkNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", E.Cause(err, "find local TC eBPF interface ", interfaceName)
	}
	return interfaceName, nil
}

func activeSharedInterfaces(configured []string, defaultInterface string) []string {
	return slices.DeleteFunc(slices.Clone(configured), func(interfaceName string) bool {
		return interfaceName == defaultInterface
	})
}

func (i *Inbound) tcAttachmentStateChanged(localInterface string, sharedInterfaces []string) (bool, error) {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return false, nil
	}
	return i.tcDataPlane.attachmentStateChanged(localInterface, sharedInterfaces)
}

func (i *Inbound) tcAttachmentDescriptions() []string {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.attachmentDescriptions()
}

func (i *Inbound) updateTCHostAddresses(hostAddresses []netip.Addr) error {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.updateHostAddresses(hostAddresses)
}

func (i *Inbound) hostAddresses() []netip.Addr {
	interfaces, err := iface.Interfaces()
	if err != nil {
		return nil
	}
	return collectHostAddresses(interfaces)
}

func collectHostAddresses(interfaces map[string]*iface.Interface) []netip.Addr {
	var addresses []netip.Addr
	for _, networkInterface := range interfaces {
		for _, prefix := range networkInterface.Addresses {
			if !prefix.IsValid() {
				continue
			}
			address := prefix.Addr().Unmap()
			if address.IsUnspecified() || address.IsLoopback() {
				continue
			}
			addresses = append(addresses, address)
		}
	}
	slices.SortFunc(addresses, func(left, right netip.Addr) int {
		return left.Compare(right)
	})
	addresses = slices.Compact(addresses)
	return addresses
}

func (d *tcDataPlane) attachmentStateChanged(localInterface string, sharedInterfaces []string) (bool, error) {
	d.access.Lock()
	defer d.access.Unlock()
	desired, err := d.desiredAttachmentState(localInterface, sharedInterfaces)
	if err != nil {
		return false, err
	}
	if tcAttachmentTopologyChanged(d.attachments, desired) {
		return true, nil
	}
	for _, attachment := range d.attachments {
		if localInterface == "" && attachment.role.local {
			if _, err = netlink.LinkByName(attachment.interfaceName); tcLinkNotFound(err) {
				continue
			}
			if err != nil {
				return false, err
			}
		}
		attached, err := attachment.filtersAttached(d.priority)
		if err != nil {
			return false, err
		}
		if !attached {
			return true, nil
		}
	}
	return false, nil
}

type tcAttachmentState struct {
	index   int
	framing ECommon.TCLinkFraming
	role    tcInterfaceRole
}

func desiredTCAttachmentState(
	localInterface string,
	sharedInterfaces []string,
	linkByName func(string) (netlink.Link, error),
) (map[string]tcAttachmentState, error) {
	roles := make(map[string]tcInterfaceRole, len(sharedInterfaces)+1)
	if localInterface != "" {
		roles[localInterface] = tcInterfaceRole{local: true}
	}
	for _, interfaceName := range sharedInterfaces {
		role := roles[interfaceName]
		role.shared = true
		roles[interfaceName] = role
	}
	interfaces := make(map[string]tcAttachmentState, len(roles))
	for interfaceName, role := range roles {
		link, err := linkByName(interfaceName)
		if err != nil && tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return nil, E.Cause(err, "find TC eBPF interface ", interfaceName)
		}
		if link == nil || link.Attrs() == nil {
			return nil, E.New("invalid TC eBPF interface ", interfaceName)
		}
		framing, err := tcLinkFraming(link)
		if err != nil {
			return nil, err
		}
		interfaces[interfaceName] = tcAttachmentState{
			index:   link.Attrs().Index,
			framing: framing,
			role:    role,
		}
	}
	return interfaces, nil
}

func tcAttachmentTopologyChanged(attachments []*tcInterfaceAttachment, desired map[string]tcAttachmentState) bool {
	if len(attachments) != len(desired) {
		return true
	}
	for _, attachment := range attachments {
		state, loaded := desired[attachment.interfaceName]
		if !loaded || state.index != attachment.interfaceIndex ||
			state.framing != attachment.framing || state.role != attachment.role {
			return true
		}
	}
	return false
}
