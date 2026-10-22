//go:build with_gvisor && !no_tailscale

package outbound

import (
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/tailscale/tsnet"
	"github.com/metacubex/tailscale/types/nettype"
)

const tailscaleInboundUDPTimeout = 5 * time.Minute
const tailscaleInboundUDPBufferSize = 65535

// registerInboundHandlers wires tsnet's fallback flow handlers into the
// tunnel so traffic arriving from the tailnet for advertised routes (subnet
// router / exit node) is dispatched through mihomo's rule engine. Flows whose
// destination is one of this node's Tailscale IPs are left to tsnet's default
// behavior (explicit listeners / reject).
func (t *Tailscale) registerInboundHandlers(server *tsnet.Server, tunnel C.Tunnel) {
	if server == nil {
		return
	}
	server.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		if isSelfTailscaleAddr(server, dst.Addr()) || !t.isAdvertisedRoute(dst.Addr()) {
			return nil, false
		}
		return func(conn net.Conn) {
			metadata := &C.Metadata{
				NetWork: C.TCP,
				Type:    C.TAILSCALE,
				SrcIP:   src.Addr().Unmap(),
				SrcPort: src.Port(),
				DstIP:   dst.Addr().Unmap(),
				DstPort: dst.Port(),
			}
			tunnel.HandleTCPConn(conn, metadata)
		}, true
	})
	server.RegisterFallbackUDPHandler(func(src, dst netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
		if isSelfTailscaleAddr(server, dst.Addr()) || !t.isAdvertisedRoute(dst.Addr()) {
			return nil, false
		}
		return func(conn nettype.ConnPacketConn) {
			if !t.acquireUDPFlow() {
				_ = conn.Close()
				return
			}
			defer t.releaseUDPFlow()
			t.handleInboundUDPFlow(tunnel, conn, src, dst)
		}, true
	})
	log.Infoln("[Tailscale](%s) inbound handlers registered for advertised routes", t.option.Name)
}

func (t *Tailscale) isAdvertisedRoute(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, route := range t.advertisedRoutes {
		if route.Contains(addr) {
			return true
		}
	}
	return false
}

func (t *Tailscale) acquireUDPFlow() bool {
	if t.udpFlows == nil {
		return true
	}
	select {
	case t.udpFlows <- struct{}{}:
		return true
	default:
		return false
	}
}

func (t *Tailscale) releaseUDPFlow() {
	if t.udpFlows != nil {
		<-t.udpFlows
	}
}

func isSelfTailscaleAddr(server *tsnet.Server, addr netip.Addr) bool {
	if server == nil {
		return false
	}
	v4, v6 := server.TailscaleIPs()
	addr = addr.Unmap()
	return addr == v4 || addr == v6
}

func (t *Tailscale) isSelfTailscaleAddr(addr netip.Addr) bool {
	server, err := t.snapshotServer()
	if err != nil {
		return false
	}
	return isSelfTailscaleAddr(server, addr)
}

func (t *Tailscale) handleInboundUDPFlow(tunnel C.Tunnel, conn nettype.ConnPacketConn, src, dst netip.AddrPort) {
	defer func() { _ = conn.Close() }()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tailscaleInboundUDPTimeout))
		buf := pool.Get(tailscaleInboundUDPBufferSize)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			_ = pool.Put(buf)
			return
		}
		metadata := &C.Metadata{
			NetWork: C.UDP,
			Type:    C.TAILSCALE,
			SrcIP:   src.Addr().Unmap(),
			SrcPort: src.Port(),
			DstIP:   dst.Addr().Unmap(),
			DstPort: dst.Port(),
		}
		tunnel.HandleUDPPacket(&tailscaleUDPPacket{buf: buf, data: buf[:n], src: src, conn: conn}, metadata)
	}
}

type tailscaleUDPPacket struct {
	buf  []byte
	data []byte
	src  netip.AddrPort
	conn nettype.ConnPacketConn
}

func (p *tailscaleUDPPacket) Data() []byte { return p.data }

// WriteBack writes the payload back to the tailnet peer. The netstack flow is
// connected, so the source address seen by the peer is always the flow's
// original destination; addr cannot be spoofed here (same limitation as any
// netstack-based UDP relay).
func (p *tailscaleUDPPacket) WriteBack(b []byte, _ net.Addr) (int, error) {
	return p.conn.Write(b)
}

func (p *tailscaleUDPPacket) Drop() {
	if p.buf != nil {
		_ = pool.Put(p.buf)
		p.buf = nil
		p.data = nil
	}
}

func (p *tailscaleUDPPacket) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(p.src)
}

var _ C.UDPPacket = (*tailscaleUDPPacket)(nil)
