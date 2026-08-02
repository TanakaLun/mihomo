package resolver

import (
	"sync/atomic"

	"go4.org/netipx"
)

// EBFPBypassIPSet holds the current eBPF inbound bypass CIDR set. It is
// registered by the eBPF inbound and consulted by the DNS fake-ip middleware
// so that domains whose real addresses fall in the bypass set are answered
// with their real IP instead of a fake-ip, letting the kernel eBPF bypass
// engage (matching sing-box's effective behavior). It is nil when no eBPF
// inbound with a bypass policy is active.
var EBFPBypassIPSet atomic.Pointer[netipx.IPSet]
