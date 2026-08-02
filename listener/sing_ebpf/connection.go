//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/adapter/inbound"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func (i *Inbound) NewConnection(conn net.Conn) {
	backend := i.backendInstance()
	if backend == nil {
		_ = conn.Close()
		return
	}
	localAddr, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	original, err := backend.TakeOriginal(ECommon.ProtocolTCP, localAddr)
	if err != nil {
		i.logWarn("[EBPF] lookup TCP original destination: %s", err)
		_ = conn.Close()
		return
	}
	sourceAddr, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.EBPF,
		DstIP:   original.Destination.Addr().Unmap(),
		DstPort: original.Destination.Port(),
	}
	restored, restoreErr := restoreOriginalSource(sourceAddr, original.Destination.Addr(), original.UID)
	if restoreErr != nil {
		metadata.SrcIP = sourceAddr.Addr().Unmap()
		metadata.SrcPort = sourceAddr.Port()
	} else {
		metadata.SrcIP = restored.Addr().Unmap()
		metadata.SrcPort = restored.Port()
	}
	inbound.ApplyAdditions(metadata, i.additions...)
	i.tunnel.HandleTCPConn(conn, metadata)
}

func (i *Inbound) NewPacket(data []byte, oob []byte, source netip.AddrPort) {
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	redirectAddress, err := redirectAddressFromOOB(oob)
	if err != nil {
		i.udpWarnings.packetInfo.warn(i.logWarn, "read UDP redirect address: ", err)
		return
	}
	client := source
	redirectDestination := netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort())
	cached, loaded := i.udpClientTable.cachedOriginal(client, redirectAddress)
	original := cached.original
	if !loaded {
		original, err = backend.LookupOriginal(ECommon.ProtocolUDP, redirectDestination)
		if err != nil {
			i.udpWarnings.originalDestination.warn(i.logWarn, "lookup UDP original destination: ", err)
			return
		}
	}
	releasedRedirects := i.udpClientTable.setBinding(
		client,
		original.Destination,
		redirectAddress,
		original.ConnectedUDP,
		original.UID,
	)
	i.deleteUDPRedirects(releasedRedirects)

	clientState := i.udpClientTable.loadOrCreate(client)
	if original.ConnectedUDP {
		clientState.setConnected(true)
	}

	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.EBPF,
		DstIP:   original.Destination.Addr().Unmap(),
		DstPort: original.Destination.Port(),
		SrcIP:   client.Addr().Unmap(),
		SrcPort: client.Port(),
	}
	if clientState != nil {
		if restored, restoreErr := restoreOriginalSource(client, original.Destination.Addr(), clientState.sourceUID()); restoreErr == nil {
			metadata.SrcIP = restored.Addr().Unmap()
			metadata.SrcPort = restored.Port()
		}
	}
	inbound.ApplyAdditions(metadata, i.additions...)

	packet := &udpPacket{
		inbound:     i,
		client:      client,
		clientState: clientState,
		data:        data,
		lAddr:       N.NewCustomAddr(C.EBPF.String(), client.String(), net.UDPAddrFromAddrPort(client)),
	}
	i.tunnel.HandleUDPPacket(packet, metadata)
}

type udpPacket struct {
	inbound     *Inbound
	client      netip.AddrPort
	clientState *udpClientState
	data        []byte
	lAddr       net.Addr
}

func (p *udpPacket) Data() []byte {
	return p.data
}

func (p *udpPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	destination, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, E.New("invalid UDP reply address")
	}
	if p.clientState == nil {
		return 0, E.New("missing UDP redirect state for ", p.client)
	}
	binding, loaded := p.clientState.redirectBinding(destination.AddrPort())
	if !loaded {
		return 0, E.New("missing UDP redirect binding for ", destination.AddrPort())
	}
	udpConn := p.inbound.listeners.udpConn(binding.address.Is6())
	if udpConn == nil {
		return 0, E.New("eBPF UDP listener is unavailable")
	}
	n, _, err := udpConn.WriteMsgUDPAddrPort(b, binding.packetInfo, p.client)
	return n, err
}

func (p *udpPacket) Drop() {
}

func (p *udpPacket) LocalAddr() net.Addr {
	return p.lAddr
}

var _ C.UDPPacket = (*udpPacket)(nil)

var _ C.UDPPacket = (*udpPacket)(nil)

func (i *Inbound) deleteUDPRedirects(redirectAddresses []netip.Addr) {
	if len(redirectAddresses) == 0 {
		return
	}
	backend := i.backendInstance()
	if backend == nil {
		return
	}
	for _, redirectAddress := range redirectAddresses {
		redirectDestination := netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort())
		if err := backend.DeleteRedirect(ECommon.ProtocolUDP, redirectDestination); err != nil {
			i.udpWarnings.cleanup.warn(i.logWarn, "delete UDP redirect mapping for ", redirectDestination, ": ", err)
		}
	}
}

func redirectAddressFromOOB(oob []byte) (netip.Addr, error) {
	var controlMessage4 ipv4.ControlMessage
	if err := controlMessage4.Parse(oob); err == nil {
		if address, loaded := netip.AddrFromSlice(controlMessage4.Dst); loaded && address.Is4() {
			return address.Unmap(), nil
		}
	}
	var controlMessage6 ipv6.ControlMessage
	if err := controlMessage6.Parse(oob); err == nil {
		if address, loaded := netip.AddrFromSlice(controlMessage6.Dst); loaded && address.Is6() && !address.Is4In6() {
			return address, nil
		}
	}
	return netip.Addr{}, E.New("IP packet info is missing")
}
