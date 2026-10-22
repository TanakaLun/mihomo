//go:build linux

package dialer

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"github.com/metacubex/mihomo/common/sockopt"
)

func bindMarkToDialer(mark int, dialer *net.Dialer, _ string, _ netip.Addr) {
	addControlToDialer(dialer, bindMarkToControl(mark))
}

func bindMarkToListenConfig(mark int, lc *net.ListenConfig, _, _ string) {
	addControlToListenConfig(lc, bindMarkToControl(mark))
}

// BindMarkToListenConfig attaches the routing mark to sockets created by lc.
// Exported for callers outside the dialer pipeline (e.g. the tailscale
// outbound's magicsock listener) that need mark-based routing without
// binding the socket to an interface.
func BindMarkToListenConfig(mark int, lc *net.ListenConfig, network, address string) {
	bindMarkToListenConfig(mark, lc, network, address)
}

func bindMarkToControl(mark int) controlFn {
	return func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
		addrPort, err := netip.ParseAddrPort(address)
		if err == nil && !addrPort.Addr().IsGlobalUnicast() {
			return
		}

		return sockopt.RawConnMark(c, mark)
	}
}
