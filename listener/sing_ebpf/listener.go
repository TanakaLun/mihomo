//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

type internalListener struct {
	network  string
	ipv6     bool
	listener net.Listener
	packet   net.PacketConn
	closed   chan struct{}
}

type internalListenerSet struct {
	access sync.Mutex
	tcp4   *internalListener
	tcp6   *internalListener
	udp4   *internalListener
	udp6   *internalListener
	port   uint16
}

type listenerFactory func(network string, ipv6 bool, port uint16) (*internalListener, error)

func (s *internalListenerSet) start(
	enableTCP bool,
	enableUDP bool,
	enableIPv4 bool,
	enableIPv6 bool,
	newListener listenerFactory,
) error {
	s.access.Lock()
	defer s.access.Unlock()
	if !s.isClosed() || s.port != 0 {
		return E.New("internal eBPF listeners are already started")
	}
	type listenerSpec struct {
		network string
		ipv6    bool
		target  **internalListener
	}
	var specs []listenerSpec
	if enableIPv4 {
		if enableTCP {
			specs = append(specs, listenerSpec{"tcp", false, &s.tcp4})
		}
		if enableUDP {
			specs = append(specs, listenerSpec{"udp", false, &s.udp4})
		}
	}
	if enableIPv6 {
		if enableTCP {
			specs = append(specs, listenerSpec{"tcp", true, &s.tcp6})
		}
		if enableUDP {
			specs = append(specs, listenerSpec{"udp", true, &s.udp6})
		}
	}
	for _, spec := range specs {
		current, err := newListener(spec.network, spec.ipv6, s.port)
		if err != nil {
			return err
		}
		*spec.target = current
		if s.port == 0 {
			port, err := listenerPort(current)
			if err != nil {
				return err
			}
			s.port = port
		}
	}
	if s.port == 0 {
		return E.New("internal eBPF listener has no enabled address family or protocol")
	}
	return nil
}

func listenerPort(current *internalListener) (uint16, error) {
	var port int
	if current.listener != nil {
		port = current.listener.Addr().(*net.TCPAddr).Port
	} else if udpAddr, ok := current.packet.LocalAddr().(*net.UDPAddr); ok {
		port = udpAddr.Port
	}
	if port == 0 {
		return 0, E.New("internal eBPF listener selected an invalid port")
	}
	return uint16(port), nil
}

func (s *internalListenerSet) close() error {
	s.access.Lock()
	defer s.access.Unlock()
	listeners := []*internalListener{s.tcp4, s.tcp6, s.udp4, s.udp6}
	s.tcp4 = nil
	s.tcp6 = nil
	s.udp4 = nil
	s.udp6 = nil
	s.port = 0
	var closeErr error
	for _, current := range listeners {
		if current == nil {
			continue
		}
		close(current.closed)
		if current.listener != nil {
			closeErr = E.Errors(closeErr, current.listener.Close())
		}
		if current.packet != nil {
			closeErr = E.Errors(closeErr, current.packet.Close())
		}
	}
	return closeErr
}

func (s *internalListenerSet) isClosed() bool {
	return s.tcp4 == nil && s.tcp6 == nil && s.udp4 == nil && s.udp6 == nil
}

func (s *internalListenerSet) selectedPort() uint16 {
	s.access.Lock()
	defer s.access.Unlock()
	return s.port
}

func (s *internalListenerSet) udpConn(ipv6 bool) *net.UDPConn {
	s.access.Lock()
	defer s.access.Unlock()
	var current *internalListener
	if ipv6 {
		current = s.udp6
	} else {
		current = s.udp4
	}
	if current == nil {
		return nil
	}
	udpConn, ok := current.packet.(*net.UDPConn)
	if !ok {
		return nil
	}
	return udpConn
}

func (i *Inbound) newListener(network string, ipv6 bool, port uint16) (*internalListener, error) {
	listenAddress := "0.0.0.0"
	listenNetwork := network + "4"
	if ipv6 {
		listenAddress = "::"
		listenNetwork = network + "6"
	}
	listenPort := "0"
	if port != 0 {
		listenPort = fmt.Sprintf("%d", port)
	}
	address := net.JoinHostPort(listenAddress, listenPort)

	lc := net.ListenConfig{
		Control: i.socketControl(ipv6),
	}
	current := &internalListener{
		network: network,
		ipv6:    ipv6,
		closed:  make(chan struct{}),
	}
	var err error
	if network == "tcp" {
		current.listener, err = lc.Listen(context.Background(), listenNetwork, address)
	} else {
		current.packet, err = lc.ListenPacket(context.Background(), listenNetwork, address)
	}
	if err != nil {
		return nil, err
	}
	go current.acceptLoop(i)
	return current, nil
}

func (l *internalListener) acceptLoop(i *Inbound) {
	if l.listener != nil {
		i.acceptTCP(l)
		return
	}
	i.readUDP(l)
}

func (i *Inbound) acceptTCP(l *internalListener) {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			i.udpWarnings.accept.warn(i.logWarn, "accept TCP connection: ", err)
			continue
		}
		go i.NewConnection(conn)
	}
}

func (i *Inbound) readUDP(l *internalListener) {
	udpConn, ok := l.packet.(*net.UDPConn)
	if !ok {
		return
	}
	buffer := make([]byte, 65536)
	oob := make([]byte, 512)
	for {
		n, oobN, _, source, err := udpConn.ReadMsgUDPAddrPort(buffer, oob)
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			i.udpWarnings.packetInfo.warn(i.logWarn, "read UDP packet: ", err)
			continue
		}
		if n == 0 {
			continue
		}
		packetBuffer := make([]byte, n)
		copy(packetBuffer, buffer[:n])
		packetOOB := make([]byte, oobN)
		copy(packetOOB, oob[:oobN])
		i.NewPacket(packetBuffer, packetOOB, source)
	}
}

func (i *Inbound) logWarn(format string, args ...any) {
	log.Warnln(format, args...)
}

func (i *Inbound) socketControl(ipv6 bool) func(network, address string, rawConn syscall.RawConn) error {
	return func(network, address string, rawConn syscall.RawConn) error {
		if ipv6 {
			if err := rawConn.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
				if strings.HasPrefix(network, "udp") {
					_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
				}
			}); err != nil {
				return err
			}
		} else if strings.HasPrefix(network, "udp") {
			if err := rawConn.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
			}); err != nil {
				return err
			}
		}
		// Register the internal listener socket cookie so the eBPF programs
		// never re-capture the internal listeners' own traffic.
		return dialer.ApplySocketProtect(network, address, rawConn)
	}
}
