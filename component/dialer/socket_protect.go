package dialer

import (
	"context"
	"sync/atomic"
	"syscall"
)

type protectFn = func(ctx context.Context, network, address string, c syscall.RawConn) error

// DefaultSocketProtect holds an optional socket-protect function that is
// appended to every control chain in this package. It is used to register
// eBPF socket cookies so that the eBPF inbound does not capture sockets
// created by mihomo itself. It is an append-only hook and never replaces the
// bind/mark/TFO controls.
var DefaultSocketProtect atomic.Value // holds protectFn or nil

// RegisterSocketProtectFunc installs a socket-protect function. Pass nil to
// disable. The previous function is replaced, not chained.
func RegisterSocketProtectFunc(fn protectFn) {
	if fn == nil {
		UnregisterSocketProtectFunc()
		return
	}
	DefaultSocketProtect.Store(fn)
}

// UnregisterSocketProtectFunc removes the active socket-protect function.
func UnregisterSocketProtectFunc() {
	DefaultSocketProtect.Store((protectFn)(nil))
}

// ApplySocketProtect invokes the active socket-protect function, if any. It is
// exposed so socket-creation paths outside this package (for example inbound
// listener control chains) can register their sockets with the eBPF inbound.
func ApplySocketProtect(network, address string, c syscall.RawConn) error {
	if fn, loaded := DefaultSocketProtect.Load().(protectFn); loaded && fn != nil {
		return fn(context.Background(), network, address, c)
	}
	return nil
}
