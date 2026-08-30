//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/component/resolver"
)

// relayTCPDNS relays a hijacked TCP DNS connection into mihomo's own resolver
// pipeline (the same pipeline behind dns.listen and the type: dns outbound).
func (i *Inbound) relayTCPDNS(conn net.Conn) {
	if err := resolver.RelayDnsConn(context.Background(), conn, resolver.DefaultDnsReadTimeout); err != nil {
		i.udpWarnings.cleanup.warn(i.logWarn, "relay hijacked TCP DNS: ", err)
	}
}

// relayUDPDNS relays a hijacked UDP DNS query into mihomo's resolver pipeline
// and writes the reply back to the client through the TC reply socket bound to
// the original destination.
func (i *Inbound) relayUDPDNS(data []byte, client netip.AddrPort, clientState *udpClientState, destination netip.AddrPort) {
	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDnsRelayTimeout)
	defer cancel()
	buff := make([]byte, resolver.SafeDnsPacketSize)
	reply, err := resolver.RelayDnsPacket(ctx, data, buff)
	if err != nil {
		i.udpWarnings.originalDestination.warn(i.logWarn, "relay hijacked UDP DNS: ", err)
		return
	}
	_, loaded := clientState.redirectBinding(destination)
	if !loaded {
		if !clientState.hasAddressFamily(destination.Addr().Is4()) {
			i.udpWarnings.originalDestination.warn(i.logWarn, "TC eBPF UDP DNS reply alias limit reached")
			return
		}
		installed := i.udpClientTable.setDirectReplyBinding(client, clientState, destination)
		if !installed {
			i.udpWarnings.originalDestination.warn(i.logWarn, "TC eBPF UDP DNS session closed or reply alias was rejected")
			return
		}
	}
	socket, err := i.udpReplySockets.get(destination, i.newTCUDPReplySocket)
	if err != nil {
		i.udpWarnings.cleanup.warn(i.logWarn, "bind TC eBPF UDP DNS reply socket: ", err)
		return
	}
	if _, err = socket.WriteToUDPAddrPort(reply, client); err != nil {
		i.udpWarnings.cleanup.warn(i.logWarn, "write hijacked UDP DNS reply: ", err)
	}
}
