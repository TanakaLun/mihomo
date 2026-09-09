//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"github.com/metacubex/mihomo/adapter/inbound"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// NewConnection handles a TCP connection accepted by the internal listeners.
// It dispatches between the cgroup and TC data planes by the redirect address
// the connection was steered into.
func (i *Inbound) NewConnection(conn net.Conn) {
	if i.localCgroupEnabled() {
		localAddr, err := netip.ParseAddrPort(conn.LocalAddr().String())
		if err == nil && i.isCgroupRedirectAddress(localAddr.Addr()) {
			i.newCgroupTCPConnection(conn)
			return
		}
	}
	backend := i.tcBackend()
	if backend == nil {
		_ = conn.Close()
		return
	}
	i.newTCConnection(backend, conn)
}

func (i *Inbound) newCgroupTCPConnection(conn net.Conn) {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		_ = conn.Close()
		return
	}
	listenerDestination, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	original, err := backend.TakeOriginal(ECommon.ProtocolTCP, listenerDestination)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) {
			i.udpWarnings.cleanup.warn(i.logWarn, "lookup cgroup eBPF TCP original destination: ", err)
		}
		_ = conn.Close()
		return
	}
	source, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	if i.hijackDNS(original.Destination) {
		go i.relayTCPDNS(conn)
		return
	}
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.EBPF,
		DstIP:   original.Destination.Addr().Unmap(),
		DstPort: original.Destination.Port(),
		SrcIP:   source.Addr().Unmap(),
		SrcPort: source.Port(),
	}
	inbound.ApplyAdditions(metadata, i.additions...)
	i.tunnel.HandleTCPConn(conn, metadata)
}

func (i *Inbound) newTCConnection(backend *ECommon.TCBackend, conn net.Conn) {
	source, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	destination, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		_ = conn.Close()
		return
	}
	_, err = backend.LookupAssignment(ECommon.ProtocolTCP, source, destination, 0, true)
	if err != nil {
		i.udpWarnings.cleanup.warn(i.logWarn, "lookup TC eBPF TCP assignment: ", err)
		_ = conn.Close()
		return
	}
	if i.hijackDNS(destination) {
		go i.relayTCPDNS(conn)
		return
	}
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.EBPF,
		DstIP:   destination.Addr().Unmap(),
		DstPort: destination.Port(),
		SrcIP:   source.Addr().Unmap(),
		SrcPort: source.Port(),
	}
	inbound.ApplyAdditions(metadata, i.additions...)
	i.tunnel.HandleTCPConn(conn, metadata)
}

// NewPacket handles a UDP datagram received by the internal listeners.
func (i *Inbound) NewPacket(data []byte, oob []byte, source netip.AddrPort) {
	if i.localCgroupEnabled() {
		if redirectAddress, err := redirectAddressFromOOB(oob); err == nil && i.isCgroupRedirectAddress(redirectAddress) {
			i.newCgroupPacket(data, oob, source)
			return
		}
	}
	backend := i.tcBackend()
	if backend == nil {
		return
	}
	i.newTCPacket(backend, data, oob, source)
}

func (i *Inbound) newCgroupPacket(data []byte, oob []byte, source netip.AddrPort) {
	redirectAddress, _, _, err := packetDestinationsFromOOB(oob)
	if err != nil {
		i.udpWarnings.packetInfo.warn(i.logWarn, "read cgroup eBPF UDP redirect address: ", err)
		return
	}
	backend := i.cgroupBackendInstance()
	if backend == nil || !i.isCgroupRedirectAddress(redirectAddress) {
		i.udpWarnings.originalDestination.warn(i.logWarn, "cgroup eBPF UDP redirect address is not owned: ", redirectAddress)
		return
	}
	client := source
	redirectDestination := netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort())
	original, loaded := i.udpClientTable.cachedCgroupOriginal(client, redirectAddress)
	if !loaded {
		original, err = backend.LookupOriginal(ECommon.ProtocolUDP, redirectDestination)
		if errors.Is(err, unix.ENOENT) {
			original, err = backend.RecoverUDPOriginal(redirectDestination)
		}
		if errors.Is(err, unix.ENOENT) {
			original, err = backend.RecoverConnectedUDPOriginal(redirectDestination)
		}
		if err != nil {
			i.udpWarnings.originalDestination.warn(i.logWarn, "lookup cgroup eBPF UDP original destination: ", err)
			return
		}
		i.udpClientTable.setCgroupBinding(client, original, redirectAddress)
	}
	if i.hijackDNS(original.Destination) {
		clientState := i.udpClientTable.loadOrCreate(client)
		i.relayUDPDNS(data, client, clientState, original.Destination)
		return
	}
	i.forwardLocalUDP(data, client, original.Destination, original.ConnectedUDP)
}

func (i *Inbound) newTCPacket(backend *ECommon.TCBackend, data []byte, oob []byte, source netip.AddrPort) {
	_, destination, interfaceIndex, err := packetDestinationsFromOOB(oob)
	if err != nil {
		i.udpWarnings.packetInfo.warn(i.logWarn, "read TC eBPF UDP destination: ", err)
		return
	}
	if !destination.IsValid() {
		i.udpWarnings.packetInfo.warn(i.logWarn, "TC eBPF UDP original destination is missing")
		return
	}
	client := source
	assignment, err := backend.LookupAssignment(ECommon.ProtocolUDP, client, destination, interfaceIndex, false)
	if err != nil && interfaceIndex != 0 {
		assignment, err = backend.LookupAssignment(ECommon.ProtocolUDP, client, destination, 0, false)
	}
	if err != nil {
		i.udpWarnings.originalDestination.warn(i.logWarn, "lookup TC eBPF UDP assignment: ", err)
		return
	}
	var sourceMAC net.HardwareAddr
	if assignment.Path == ECommon.TCPathShared && assignment.SourceMACValid != 0 {
		sourceMAC = net.HardwareAddr(assignment.SourceMAC[:])
	}
	i.udpClientTable.setDirectBinding(client, destination, sourceMAC, assignment.SocketCookie)
	if i.hijackDNS(destination) {
		clientState := i.udpClientTable.loadOrCreate(client)
		i.relayUDPDNS(data, client, clientState, destination)
		return
	}
	i.forwardLocalUDP(data, client, destination, false)
}

// forwardLocalUDP forwards a UDP datagram from a local or TC client to the
// mihomo tunnel with per-packet write-back through the reply socket / cgroup
// redirect as selected by the client's data plane.
func (i *Inbound) forwardLocalUDP(data []byte, client netip.AddrPort, destination netip.AddrPort, connected bool) {
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.EBPF,
		DstIP:   destination.Addr().Unmap(),
		DstPort: destination.Port(),
		SrcIP:   client.Addr().Unmap(),
		SrcPort: client.Port(),
	}
	inbound.ApplyAdditions(metadata, i.additions...)

	clientState := i.udpClientTable.loadOrCreate(client)
	packet := &udpPacket{
		inbound:     i,
		client:      client,
		clientState: clientState,
		data:        data,
		lAddr:       N.NewCustomAddr(C.EBPF.String(), client.String(), net.UDPAddrFromAddrPort(client)),
	}
	i.tunnel.HandleUDPPacket(packet, metadata)
}

func (i *Inbound) hijackDNS(destination netip.AddrPort) bool {
	return i.localDNSMode != dnsModeOff && destination.Port() == 53
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
		return 0, E.New("missing eBPF UDP state for ", p.client)
	}
	if err := p.inbound.writeUDPReply(p.client, p.clientState, destination.AddrPort(), b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// writeUDPReply writes a UDP reply toward the client through the data plane of
// the client's state: cgroup clients use the internal listener writeUDP with
// the redirect address as source (the kernel restores the reply path), while
// TC clients use a transparent reply socket bound to the original destination.
func (i *Inbound) writeUDPReply(client netip.AddrPort, clientState *udpClientState, destinationAddress netip.AddrPort, payload []byte) error {
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	binding, loaded := clientState.redirectBinding(destinationAddress)
	if !loaded {
		if clientState.isCgroupDataPlane() {
			backend := i.cgroupBackendInstance()
			if backend == nil {
				return E.New("cgroup eBPF backend is closed")
			}
			redirectAddress, err := backend.ReserveUDPReplyRedirect(destinationAddress, i.listeners.selectedPort())
			if err != nil {
				return err
			}
			if !i.udpClientTable.setCgroupReplyBinding(client, clientState, destinationAddress, redirectAddress) {
				_ = backend.DeleteRedirect(
					ECommon.ProtocolUDP,
					netip.AddrPortFrom(redirectAddress, i.listeners.selectedPort()),
				)
				return E.New("cgroup eBPF UDP reply binding was rejected")
			}
			binding, loaded = clientState.redirectBinding(destinationAddress)
			if !loaded {
				return E.New("cgroup eBPF UDP reply binding is unavailable")
			}
		}
	}
	if !loaded {
		if !clientState.hasAddressFamily(destinationAddress.Addr().Is4()) {
			return E.New("eBPF UDP reply alias limit reached or address family unavailable")
		}
		installed := i.udpClientTable.setDirectReplyBinding(client, clientState, destinationAddress)
		if !installed {
			return E.New("eBPF UDP session closed or reply alias was rejected")
		}
		binding, loaded = clientState.redirectBinding(destinationAddress)
		if !loaded {
			return E.New("eBPF UDP reply binding is unavailable")
		}
	}
	if clientState.isCgroupDataPlane() {
		return i.listeners.writeUDP(payload, binding.packetInfo, client, binding.redirectAddress)
	}
	socket, release, err := i.udpReplySockets.get(destinationAddress, i.newTCUDPReplySocket)
	if err != nil {
		return err
	}
	defer release()
	_, err = socket.WriteToUDPAddrPort(payload, client)
	return err
}

func (p *udpPacket) Drop() {
}

func (p *udpPacket) LocalAddr() net.Addr {
	return p.lAddr
}

var _ C.UDPPacket = (*udpPacket)(nil)

func (i *Inbound) newTCUDPReplySocket(source netip.AddrPort) (*net.UDPConn, error) {
	network := "udp6"
	if source.Addr().Is4() {
		network = "udp4"
	}
	listenConfig := net.ListenConfig{Control: func(_ string, _ string, rawConn syscall.RawConn) error {
		if err := rawConn.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
				return
			}
			if source.Addr().Is4() {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			} else {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
			}
		}); err != nil {
			return err
		}
		if i.selfBypass != nil {
			return i.selfBypass.RegisterSocket(rawConn)
		}
		return nil
	}}
	packetConnection, err := listenConfig.ListenPacket(contextBackground(), network, source.String())
	if err != nil {
		return nil, E.Cause(err, "bind eBPF UDP reply socket to ", source)
	}
	udpConnection, loaded := packetConnection.(*net.UDPConn)
	if !loaded {
		_ = packetConnection.Close()
		return nil, E.New("eBPF UDP reply socket has unexpected type")
	}
	return udpConnection, nil
}

func packetDestinationsFromOOB(oob []byte) (netip.Addr, netip.AddrPort, uint32, error) {
	var packetAddress netip.Addr
	var originalDestination netip.AddrPort
	var interfaceIndex uint32
	for len(oob) > 0 {
		header, data, remainder, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return netip.Addr{}, netip.AddrPort{}, 0, E.Cause(err, "parse IP packet info")
		}
		switch {
		case header.Level == unix.IPPROTO_IP && header.Type == unix.IP_PKTINFO:
			if len(data) < unix.SizeofInet4Pktinfo {
				return netip.Addr{}, netip.AddrPort{}, 0, E.New("invalid IPv4 packet info length: ", len(data))
			}
			interfaceIndex = binary.NativeEndian.Uint32(data[:4])
			var address [4]byte
			copy(address[:], data[8:12])
			packetAddress = netip.AddrFrom4(address)
		case header.Level == unix.IPPROTO_IPV6 && header.Type == unix.IPV6_PKTINFO:
			if len(data) < unix.SizeofInet6Pktinfo {
				return netip.Addr{}, netip.AddrPort{}, 0, E.New("invalid IPv6 packet info length: ", len(data))
			}
			interfaceIndex = binary.NativeEndian.Uint32(data[16:20])
			var address [16]byte
			copy(address[:], data[:16])
			packetAddress = netip.AddrFrom16(address)
		case header.Level == unix.SOL_IP && header.Type == unix.IP_RECVORIGDSTADDR && len(data) >= 8:
			var address [4]byte
			copy(address[:], data[4:8])
			originalDestination = netip.AddrPortFrom(netip.AddrFrom4(address), binary.BigEndian.Uint16(data[2:4]))
		case header.Level == unix.SOL_IPV6 && header.Type == unix.IPV6_RECVORIGDSTADDR && len(data) >= 24:
			var address [16]byte
			copy(address[:], data[8:24])
			originalDestination = netip.AddrPortFrom(netip.AddrFrom16(address), binary.BigEndian.Uint16(data[2:4]))
		}
		oob = remainder
	}
	if !packetAddress.IsValid() {
		return netip.Addr{}, netip.AddrPort{}, 0, E.New("IP packet info is missing")
	}
	return packetAddress, originalDestination, interfaceIndex, nil
}

func redirectAddressFromOOB(oob []byte) (netip.Addr, error) {
	address, _, _, err := packetDestinationsFromOOB(oob)
	return address, err
}
