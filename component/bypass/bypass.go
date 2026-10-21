// Package bypass maintains the union of destination CIDR sets published by
// every transparent inbound (eBPF, TUN) that wants matching traffic to keep
// its real destination and skip the proxy path. The DNS fake-ip middleware
// consumes the snapshot so domains whose addresses fall inside the union are
// answered with their real IP instead of a fake-ip, letting the kernel-level
// bypass (eBPF pass decision, TUN route exclusion) actually engage.
package bypass

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"go4.org/netipx"
)

// Registry is a multi-publisher leaf store. Each inbound that may produce a
// bypass CIDR set registers a Publisher handle; the registry recomputes the
// union on every publish and exposes it atomically. Closing a publisher
// removes only that inbound's prefixes, so a stale set can never survive the
// inbound that produced it (unlike a single global atomic that is only
// overwritten).
type Registry struct {
	mu       sync.Mutex
	next     uint64
	entries  map[uint64]*pubEntry
	snapshot atomic.Pointer[netipx.IPSet]
}

type pubEntry struct {
	owner    string
	prefixes []netip.Prefix
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: make(map[uint64]*pubEntry)}
}

var global = NewRegistry()

// Global returns the process-wide registry consulted by the DNS middleware.
func Global() *Registry {
	return global
}

// Register adds a publisher owned by the given description (used in logs) and
// returns a handle whose lifetime is tied to the inbound that created it.
func (r *Registry) Register(owner string) *Publisher {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.next
	r.next++
	r.entries[id] = &pubEntry{owner: owner}
	return &Publisher{registry: r, id: id, owner: owner}
}

// Publisher is a per-inbound handle into a Registry.
type Publisher struct {
	registry *Registry
	id       uint64
	owner    string
}

// Publish replaces this publisher's prefixes with the given set. Passing an
// empty or nil slice removes this publisher's contribution from the union.
func (p *Publisher) Publish(prefixes []netip.Prefix) {
	p.registry.publish(p.id, prefixes)
}

// Close removes this publisher from the registry. It is idempotent.
func (p *Publisher) Close() {
	p.registry.remove(p.id)
}

func (r *Registry) publish(id uint64, prefixes []netip.Prefix) {
	r.mu.Lock()
	if entry, ok := r.entries[id]; ok {
		entry.prefixes = prefixes
	}
	r.mu.Unlock()
	r.rebuild()
}

func (r *Registry) remove(id uint64) {
	r.mu.Lock()
	delete(r.entries, id)
	r.mu.Unlock()
	r.rebuild()
}

// rebuild recomputes the union snapshot from all live publishers. It must not
// be called while holding r.mu.
func (r *Registry) rebuild() {
	r.mu.Lock()
	entries := r.entries
	var builder netipx.IPSetBuilder
	loaded := false
	for _, entry := range entries {
		for _, prefix := range entry.prefixes {
			if prefix.IsValid() {
				builder.AddPrefix(prefix)
				loaded = true
			}
		}
	}
	var next *netipx.IPSet
	if loaded {
		if set, err := builder.IPSet(); err == nil {
			next = set
		}
	}
	r.mu.Unlock()
	r.snapshot.Store(next)
}

// Snapshot returns the current union of all published prefixes, or nil when
// no inbound has published anything. The returned set must not be mutated.
func (r *Registry) Snapshot() *netipx.IPSet {
	return r.snapshot.Load()
}
