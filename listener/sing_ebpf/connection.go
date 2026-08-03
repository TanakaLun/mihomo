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

	"golang.org/x/sys/unix"
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
		SrcIP:   sourceAddr.Addr().Unmap(),
		SrcPort: sourceAddr.Port(),
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
	cached, bindingReady, loaded := i.udpClientTable.cachedPacketState(client, redirectAddress)
	original := cached.original
	if !loaded {
		original, err = backend.LookupOriginal(ECommon.ProtocolUDP, redirectDestination)
		if err != nil {
			i.udpWarnings.originalDestination.warn(i.logWarn, "lookup UDP original destination: ", err)
			return
		}
	}
	if !bindingReady {
		releasedRedirects := i.udpClientTable.setBinding(
			client,
			original.Destination,
			redirectAddress,
			original.ConnectedUDP,
		)
		i.deleteUDPRedirects(releasedRedirects)
	}

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
	for len(oob) > 0 {
		header, data, remainder, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return netip.Addr{}, E.Cause(err, "parse IP packet info")
		}
		switch {
		case header.Level == unix.IPPROTO_IP && header.Type == unix.IP_PKTINFO:
			if len(data) < unix.SizeofInet4Pktinfo {
				return netip.Addr{}, E.New("invalid IPv4 packet info length: ", len(data))
			}
			var address [4]byte
			copy(address[:], data[8:12])
			return netip.AddrFrom4(address), nil
		case header.Level == unix.IPPROTO_IPV6 && header.Type == unix.IPV6_PKTINFO:
			if len(data) < unix.SizeofInet6Pktinfo {
				return netip.Addr{}, E.New("invalid IPv6 packet info length: ", len(data))
			}
			var address [16]byte
			copy(address[:], data[:16])
			return netip.AddrFrom16(address), nil
		}
		oob = remainder
	}
	return netip.Addr{}, E.New("IP packet info is missing")
}
