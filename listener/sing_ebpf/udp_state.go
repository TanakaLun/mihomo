//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net"
	"net/netip"
	"sync"
	"time"

	ECommon "github.com/metacubex/mihomo/common/ebpf"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type udpClientTable struct {
	access             sync.RWMutex
	clients            map[netip.AddrPort]*udpClientState
	redirectAccess     sync.Mutex
	redirectReferences map[udpRedirectReference]uint32
}

type udpClientState struct {
	access     sync.RWMutex
	connected  bool
	lastActive time.Time
	bindings   map[netip.AddrPort]udpRedirectBinding
	originals  map[netip.Addr]udpOriginalDestination
}

type udpRedirectBinding struct {
	address    netip.Addr
	packetInfo []byte
	connected  bool
	reference  udpRedirectReference
}

type udpRedirectReference struct {
	client  netip.AddrPort
	address netip.Addr
}

type udpOriginalDestination struct {
	original ECommon.OriginalDestination
}

func (t *udpClientTable) load(client netip.AddrPort) (*udpClientState, bool) {
	t.access.RLock()
	clientState, loaded := t.clients[client]
	t.access.RUnlock()
	return clientState, loaded
}

func (t *udpClientTable) loadOrCreate(client netip.AddrPort) *udpClientState {
	if clientState, loaded := t.load(client); loaded {
		return clientState
	}
	t.access.Lock()
	defer t.access.Unlock()
	return t.loadOrCreateLocked(client)
}

func (t *udpClientTable) loadOrCreateLocked(client netip.AddrPort) *udpClientState {
	if clientState, loaded := t.clients[client]; loaded {
		return clientState
	}
	if t.clients == nil {
		t.clients = make(map[netip.AddrPort]*udpClientState)
	}
	clientState := &udpClientState{
		bindings:   make(map[netip.AddrPort]udpRedirectBinding),
		originals:  make(map[netip.Addr]udpOriginalDestination),
		lastActive: time.Now(),
	}
	t.clients[client] = clientState
	return clientState
}

func (t *udpClientTable) touch(client netip.AddrPort, now time.Time) {
	if clientState, loaded := t.load(client); loaded {
		clientState.access.Lock()
		clientState.lastActive = now
		clientState.access.Unlock()
	}
}

func (t *udpClientTable) cachedOriginal(client netip.AddrPort, redirectAddress netip.Addr) (udpOriginalDestination, bool) {
	original, _, loaded := t.cachedPacketState(client, redirectAddress)
	return original, loaded
}

func (t *udpClientTable) cachedPacketState(
	client netip.AddrPort,
	redirectAddress netip.Addr,
) (udpOriginalDestination, bool, bool) {
	clientState, loaded := t.load(client)
	if !loaded {
		return udpOriginalDestination{}, false, false
	}
	clientState.access.RLock()
	original, loaded := clientState.originals[redirectAddress]
	if !loaded {
		clientState.access.RUnlock()
		return udpOriginalDestination{}, false, false
	}
	binding, bindingLoaded := clientState.bindings[original.original.Destination]
	bindingReady := bindingLoaded &&
		binding.address == redirectAddress &&
		binding.connected == original.original.ConnectedUDP
	clientState.access.RUnlock()
	return original, bindingReady, true
}

func (t *udpClientTable) setBinding(
	client netip.AddrPort,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
	connected bool,
) []netip.Addr {
	releases := t.setBindingState(
		client,
		redirectAddress,
		udpRedirectReference{address: redirectAddress},
		udpOriginalDestination{
			original: ECommon.OriginalDestination{
				Destination:  destination,
				ConnectedUDP: connected,
			},
		},
	)
	addresses := make([]netip.Addr, 0, len(releases))
	for _, release := range releases {
		addresses = append(addresses, release.reference.address)
	}
	return addresses
}

func (t *udpClientTable) setBindingState(
	client netip.AddrPort,
	redirectAddress netip.Addr,
	reference udpRedirectReference,
	original udpOriginalDestination,
) []udpRedirectRelease {
	t.access.RLock()
	clientState, loaded := t.clients[client]
	if loaded {
		released := t.setClientBinding(clientState, redirectAddress, reference, original)
		t.access.RUnlock()
		return released
	}
	t.access.RUnlock()

	t.access.Lock()
	clientState = t.loadOrCreateLocked(client)
	released := t.setClientBinding(clientState, redirectAddress, reference, original)
	t.access.Unlock()
	return released
}

type udpRedirectRelease struct {
	reference udpRedirectReference
}

func (t *udpClientTable) setClientBinding(
	clientState *udpClientState,
	redirectAddress netip.Addr,
	reference udpRedirectReference,
	original udpOriginalDestination,
) []udpRedirectRelease {
	destination := original.original.Destination
	connected := original.original.ConnectedUDP
	clientState.access.RLock()
	current, loaded := clientState.bindings[destination]
	clientState.access.RUnlock()
	if loaded && current.address == redirectAddress && current.connected == connected {
		return nil
	}

	clientState.access.Lock()
	defer clientState.access.Unlock()
	current, loaded = clientState.bindings[destination]
	clientState.lastActive = time.Now()
	clientState.originals[redirectAddress] = original
	if loaded && current.address == redirectAddress && current.connected == connected {
		return nil
	}
	clientState.bindings[destination] = udpRedirectBinding{
		address:    redirectAddress,
		packetInfo: sourcePacketInfo(redirectAddress),
		connected:  connected,
		reference:  reference,
	}

	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	if !connected {
		t.retainRedirectLocked(reference)
	}
	if loaded && !current.connected && t.releaseRedirectLocked(current.reference) {
		return []udpRedirectRelease{{reference: current.reference}}
	}
	return nil
}

func (t *udpClientTable) delete(client netip.AddrPort, expectedState *udpClientState) []netip.Addr {
	releases := t.deleteClient(client, expectedState)
	addresses := make([]netip.Addr, 0, len(releases))
	for _, release := range releases {
		addresses = append(addresses, release.reference.address)
	}
	return addresses
}

func (t *udpClientTable) deleteClient(client netip.AddrPort, expectedState *udpClientState) []udpRedirectRelease {
	t.access.Lock()
	defer t.access.Unlock()
	if t.clients[client] != expectedState {
		return nil
	}
	delete(t.clients, client)

	expectedState.access.Lock()
	defer expectedState.access.Unlock()
	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	var released []udpRedirectRelease
	for bindingKey := range expectedState.bindings {
		binding := expectedState.bindings[bindingKey]
		if !binding.connected && t.releaseRedirectLocked(binding.reference) {
			released = append(released, udpRedirectRelease{reference: binding.reference})
		}
		delete(expectedState.bindings, bindingKey)
	}
	for originalKey := range expectedState.originals {
		delete(expectedState.originals, originalKey)
	}
	return released
}

// sweep removes client states that have been idle for longer than timeout and
// releases their unconnected UDP redirect entries.
func (t *udpClientTable) sweep(now time.Time, timeout time.Duration, inbound *Inbound) {
	t.access.Lock()
	clients := make([]netip.AddrPort, 0, len(t.clients))
	for client, clientState := range t.clients {
		clientState.access.RLock()
		idle := now.Sub(clientState.lastActive)
		clientState.access.RUnlock()
		if idle > timeout {
			clients = append(clients, client)
		}
	}
	t.access.Unlock()
	for _, client := range clients {
		clientState, loaded := t.load(client)
		if !loaded {
			continue
		}
		addresses := t.delete(client, clientState)
		inbound.deleteUDPRedirects(addresses)
	}
}

func (t *udpClientTable) retainRedirectLocked(reference udpRedirectReference) {
	if t.redirectReferences == nil {
		t.redirectReferences = make(map[udpRedirectReference]uint32)
	}
	t.redirectReferences[reference]++
}

func (t *udpClientTable) releaseRedirectLocked(reference udpRedirectReference) bool {
	references := t.redirectReferences[reference]
	if references > 1 {
		t.redirectReferences[reference] = references - 1
		return false
	}
	if references == 1 {
		delete(t.redirectReferences, reference)
		return true
	}
	return false
}

func (s *udpClientState) redirectBinding(destination netip.AddrPort) (udpRedirectBinding, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding, loaded
}

func (s *udpClientState) setConnected(connected bool) {
	s.access.Lock()
	s.connected = connected
	s.access.Unlock()
}

func (s *udpClientState) isConnected() bool {
	s.access.RLock()
	connected := s.connected
	s.access.RUnlock()
	return connected
}

func sourcePacketInfo(address netip.Addr) []byte {
	if address.Is4() {
		return (&ipv4.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
	}
	return (&ipv6.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
}
