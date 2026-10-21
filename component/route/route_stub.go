//go:build !windows

package route

import (
	"errors"
	"net/netip"
)

// NewRouter returns an unsupported error on platforms without a mutable
// routing-table API. Linux/Android rely on nftables auto-redirect and the
// eBPF inbound for kernel-level pass decisions, so no physical routes are
// needed there for the TUN data path.
func NewRouter(tunInterface string, protected []netip.Prefix) (Router, error) {
	return nil, errors.New("route: bypass routes are only supported on windows")
}
