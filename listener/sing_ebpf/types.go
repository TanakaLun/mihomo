//go:build with_ebpf && (linux || android)

package sing_ebpf

// UIDRange is an inclusive UID interval used by the adapter's local UID
// policy parser. sing-ebpf does not re-export the backend UIDRange type, so
// the adapter keeps its own and lowers it into UIDDecision values when it
// compiles the ActionPolicy.
type UIDRange struct {
	Start uint32
	End   uint32
}

// PortRange is an inclusive port interval used by the adapter's bypass-port
// parser. The compiled policy lowers it into PortDecision values.
type PortRange struct {
	Start uint16
	End   uint16
}

// localUIDPolicy carries the adapter-side semantics that were previously held
// by the backend LocalPolicy type: which rules the caller configured, their
// DNS mode, and the parsed UID ranges. The compiled ActionPolicy lowers these
// into UIDDecision/PortDecision values.
type localUIDPolicy struct {
	EnableBypassCIDR     bool
	IncludeUIDConfigured bool
	DNSMode              string
	BypassPrivateAddress bool
	IncludeUID           []UIDRange
	ExcludeUID           []UIDRange
}