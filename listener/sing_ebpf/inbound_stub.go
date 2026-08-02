//go:build !(with_ebpf && (linux || android))

package sing_ebpf

import (
	"context"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"

	E "github.com/metacubex/sing/common/exceptions"
)

// Listener is the eBPF inbound listener. It is only available when the
// binary is built for linux/android with cgo and the `with_ebpf` build tag.
type Listener interface {
	Close() error
	Address() string
}

// New creates an eBPF inbound. Without the `with_ebpf` build tag and cgo the
// feature is unavailable and this returns an error.
func New(ctx context.Context, options LC.EBPF, tunnel C.Tunnel, additions ...inbound.Addition) (Listener, error) {
	return nil, E.New("eBPF inbound requires cgo and the with_ebpf build tag on linux/android")
}
