package dialer

import (
	"context"
	"sync"
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

var (
	socketProtectMu    sync.Mutex
	socketProtectCount int
)

// RegisterSocketProtectFunc installs a socket-protect function and returns a
// cleanup that removes exactly this registration. The active function is
// single-slot (a later registration replaces the previous one), but the
// registration is reference counted so closing one eBPF inbound no longer
// strips the protection another inbound still relies on. Pass nil to install
// nothing (the returned cleanup is a safe no-op).
func RegisterSocketProtectFunc(fn protectFn) func() {
	if fn == nil {
		return func() {}
	}
	socketProtectMu.Lock()
	defer socketProtectMu.Unlock()
	socketProtectCount++
	DefaultSocketProtect.Store(fn)
	return func() {
		socketProtectMu.Lock()
		defer socketProtectMu.Unlock()
		if socketProtectCount == 0 {
			return
		}
		socketProtectCount--
		if socketProtectCount == 0 {
			DefaultSocketProtect.Store((protectFn)(nil))
		}
	}
}

// UnregisterSocketProtectFunc removes the active socket-protect function
// unconditionally. Kept for callers that took over management themselves.
func UnregisterSocketProtectFunc() {
	socketProtectMu.Lock()
	defer socketProtectMu.Unlock()
	socketProtectCount = 0
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
