//go:build !windows

package sing_tun

import "net/netip"

// applyBypassRoutesLocked is a no-op outside Windows: Linux/Android rely on
// the eBPF inbound's kernel pass decisions and nftables auto-redirect, and
// darwin has no mihomo-level route reconciler yet. Kept as a matching-name
// stub so server.go stays platform-neutral.
func (l *Listener) applyBypassRoutesLocked(prefixes []netip.Prefix) {}

func (l *Listener) resetBypassRoutes() {}
