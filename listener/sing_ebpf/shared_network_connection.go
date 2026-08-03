//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	E "github.com/metacubex/sing/common/exceptions"
)

func (s *sharedNetwork) NewConnection(conn net.Conn) {
	backend := s.sharedBackendInstance()
	if backend == nil {
		_ = conn.Close()
		return
	}
	client, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	tokenDestination, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	original, flow, err := backend.LookupFlow(ECommon.ProtocolTCP, client, tokenDestination)
	if err != nil {
		s.udpWarnings.cleanup.warn(s.inbound.logWarn, "lookup shared-network TCP original destination: ", err)
		_ = conn.Close()
		return
	}
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.EBPF,
		DstIP:   original.Destination.Addr().Unmap(),
		DstPort: original.Destination.Port(),
		SrcIP:   client.Addr().Unmap(),
		SrcPort: client.Port(),
	}
	inbound.ApplyAdditions(metadata, s.inbound.additions...)
	s.inbound.tunnel.HandleTCPConn(&sharedConn{Conn: conn, shared: s, flow: flow}, metadata)
}

func (s *sharedNetwork) NewPacket(data []byte, oob []byte, source netip.AddrPort) {
	backend := s.sharedBackendInstance()
	if backend == nil {
		return
	}
	tokenAddress, err := redirectAddressFromOOB(oob)
	if err != nil {
		s.udpWarnings.packetInfo.warn(s.inbound.logWarn, "read shared-network UDP token address: ", err)
		return
	}
	client := source
	tokenDestination := netip.AddrPortFrom(tokenAddress, s.listeners.selectedPort())
	cached, bindingReady, loaded := s.udpClientTable.cachedPacketState(client, tokenAddress)
	original := cached.original
	flow := cached.sharedFlow
	if !loaded {
		original, flow, err = backend.LookupFlow(ECommon.ProtocolUDP, client, tokenDestination)
		if err != nil {
			s.udpWarnings.originalDestination.warn(s.inbound.logWarn, "lookup shared-network UDP original destination: ", err)
			return
		}
	}
	if !bindingReady {
		released := s.udpClientTable.setSharedBinding(client, original.Destination, tokenAddress, flow)
		s.releaseFlows(released)
	}

	clientState := s.udpClientTable.loadOrCreate(client)
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.EBPF,
		DstIP:   original.Destination.Addr().Unmap(),
		DstPort: original.Destination.Port(),
		SrcIP:   client.Addr().Unmap(),
		SrcPort: client.Port(),
	}
	inbound.ApplyAdditions(metadata, s.inbound.additions...)

	packet := &sharedPacket{
		shared:      s,
		client:      client,
		clientState: clientState,
		data:        data,
		lAddr:       N.NewCustomAddr(C.EBPF.String(), client.String(), net.UDPAddrFromAddrPort(client)),
	}
	s.inbound.tunnel.HandleUDPPacket(packet, metadata)
}

func (s *sharedNetwork) releaseFlows(releases []udpRedirectRelease) {
	for _, release := range releases {
		s.releaseFlow(release.sharedFlow)
	}
}

func (s *sharedNetwork) releaseFlow(flow *ECommon.SharedNetworkFlowHandle) {
	if flow == nil {
		return
	}
	backend := s.sharedBackendInstance()
	if backend == nil {
		return
	}
	if err := backend.ReleaseFlow(flow); err != nil {
		s.udpWarnings.cleanup.warn(s.inbound.logWarn, "release shared-network flow: ", err)
	}
}

type sharedConn struct {
	net.Conn
	shared *sharedNetwork
	flow   *ECommon.SharedNetworkFlowHandle
	once   sync.Once
}

func (c *sharedConn) Close() error {
	c.once.Do(func() {
		c.shared.releaseFlow(c.flow)
	})
	return c.Conn.Close()
}

type sharedPacket struct {
	shared      *sharedNetwork
	client      netip.AddrPort
	clientState *udpClientState
	data        []byte
	lAddr       net.Addr
}

func (p *sharedPacket) Data() []byte {
	return p.data
}

func (p *sharedPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	destination, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, E.New("invalid UDP reply address")
	}
	p.shared.lifecycleAccess.RLock()
	defer p.shared.lifecycleAccess.RUnlock()
	if p.clientState == nil {
		return 0, E.New("missing shared-network UDP state for ", p.client)
	}
	binding, loaded := p.clientState.redirectBinding(destination.AddrPort())
	if !loaded {
		return 0, E.New("missing shared-network UDP binding for ", destination.AddrPort())
	}
	if err := p.shared.listeners.writeUDP(b, binding.packetInfo, p.client, binding.address); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *sharedPacket) Drop() {
}

func (p *sharedPacket) LocalAddr() net.Addr {
	return p.lAddr
}

var _ C.UDPPacket = (*sharedPacket)(nil)
