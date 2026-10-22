//go:build !linux

package dialer

import (
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/log"
)

var printMarkWarnOnce sync.Once

func printMarkWarn() {
	printMarkWarnOnce.Do(func() {
		log.Warnln("Routing mark on socket is not supported on current platform")
	})
}

func bindMarkToDialer(mark int, dialer *net.Dialer, _ string, _ netip.Addr) {
	printMarkWarn()
}

func bindMarkToListenConfig(mark int, lc *net.ListenConfig, _, _ string) {
	printMarkWarn()
}

// BindMarkToListenConfig attaches the routing mark to sockets created by lc.
// Exported for callers outside the dialer pipeline (e.g. the tailscale
// outbound's magicsock listener) that need mark-based routing without
// binding the socket to an interface.
func BindMarkToListenConfig(mark int, lc *net.ListenConfig, network, address string) {
	bindMarkToListenConfig(mark, lc, network, address)
}
