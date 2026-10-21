// Package route implements kernel-level exclusion of destination CIDRs from
// the TUN data path on platforms that expose a mutable routing table
// (Windows). Inbound transparent proxies publish the CIDR sets they want to
// bypass (their "pass" set); this package reconciles those prefixes as
// more-specific physical routes so matching traffic never enters the TUN
// device, mirroring the eBPF DecisionPass semantics on Windows.
//
// The package is split into a platform-neutral core (pure prefix/route-table
// math, unit-testable everywhere) and a Windows backend that talks to iphlpapi
// (GetIpForwardTable2 / CreateIpForwardEntry2 / DeleteIpForwardEntry2). Other
// platforms get a stub Router that reports unsupported.
package route

import "net/netip"

// Row is the view of a routing-table entry needed to pick a physical next hop
// for a bypass prefix.
type Row struct {
	InterfaceLUID  uint64
	InterfaceIndex uint32
	Prefix         netip.Prefix
	NextHop        netip.Addr
	Metric         uint32
}

// prefixCovers reports whether cover contains every address of prefix.
func prefixCovers(cover, prefix netip.Prefix) bool {
	cover = cover.Masked()
	prefix = prefix.Masked()
	if !cover.IsValid() || !prefix.IsValid() || cover.Addr().Is4() != prefix.Addr().Is4() {
		return false
	}
	if cover.Bits() > prefix.Bits() {
		return false
	}
	return cover.Contains(prefix.Addr())
}

// betterRow reports whether a is a better best-match than b for the same
// destination: longer prefix wins, then lower metric.
func betterRow(a, b Row) bool {
	switch {
	case a.Prefix.Bits() != b.Prefix.Bits():
		return a.Prefix.Bits() > b.Prefix.Bits()
	case a.Metric != b.Metric:
		return a.Metric < b.Metric
	}
	return true
}

// SelectBestPhysical returns the row that fully covers prefix p on an
// interface other than tunLUID. Rows that only partially cover p are rejected
// so the bypass route never points part of the prefix at a wrong next hop.
func SelectBestPhysical(rows []Row, tunLUID uint64, p netip.Prefix) (Row, bool) {
	p = p.Masked()
	if !p.IsValid() {
		return Row{}, false
	}
	var best Row
	found := false
	for _, row := range rows {
		if row.InterfaceLUID == tunLUID {
			continue
		}
		if !prefixCovers(row.Prefix, p) {
			continue
		}
		if !found || betterRow(row, best) {
			best = row
			found = true
		}
	}
	return best, found
}

// Key identifies a route that must be installed on a specific interface with
// a specific next hop. A prefix whose best physical route changes produces a
// different Key, so the reconciler replaces it atomically-like (add then
// delete). Metric mirrors the selected physical row so multi-homed hosts keep
// the pre-TUN best-path selection among equal prefixes. ScopeID is the
// interface index carried into IPv6 link-local next hops.
type Key struct {
	Prefix        netip.Prefix
	NextHop       netip.Addr
	InterfaceLUID uint64
	ScopeID       uint32
	Metric        uint32
}

// Plan computes the transition from current to desired route keys. Additions
// are returned separately from removals so the caller can add before it
// deletes, avoiding transient black holes.
func Plan(current, desired []Key) (adds, removes []Key) {
	currentSet := make(map[Key]struct{}, len(current))
	for _, key := range current {
		currentSet[key] = struct{}{}
	}
	desiredSet := make(map[Key]struct{}, len(desired))
	for _, key := range desired {
		desiredSet[key] = struct{}{}
	}
	for _, key := range current {
		if _, ok := desiredSet[key]; !ok {
			removes = append(removes, key)
		}
	}
	for _, key := range desired {
		if _, ok := currentSet[key]; !ok {
			adds = append(adds, key)
		}
	}
	return adds, removes
}

// FilterProtected removes bypass prefixes that overlap any protected prefix
// (for example the TUN device's own addressing or loopback ranges), which must
// always stay on the TUN/interception path. It returns a new slice; nil is
// returned when every prefix is filtered out.
func FilterProtected(prefixes, protected []netip.Prefix) []netip.Prefix {
	if len(protected) == 0 {
		return prefixes
	}
	guarded := make([]netip.Prefix, 0, len(protected))
	for _, prefix := range protected {
		if prefix.IsValid() {
			guarded = append(guarded, prefix.Masked())
		}
	}
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		if !prefix.IsValid() {
			continue
		}
		blocked := false
		for _, guard := range guarded {
			if prefixesOverlap(prefix, guard) {
				blocked = true
				break
			}
		}
		if !blocked {
			out = append(out, prefix)
		}
	}
	return out
}

func prefixesOverlap(a, b netip.Prefix) bool {
	if !a.IsValid() || !b.IsValid() || a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	if a.Bits() <= b.Bits() {
		return a.Contains(b.Addr())
	}
	return b.Contains(a.Addr())
}

// Router installs and removes bypass routes on the physical data path so that
// matching destination CIDRs never enter the TUN device.
type Router interface {
	// Apply reconciles the installed routes with the given bypass prefixes and
	// reports how many were installed and how many were skipped (protected or
	// no usable physical covering route).
	Apply(prefixes []netip.Prefix) (installed, skipped int, err error)
	// Reset removes every route this Router installed.
	Reset() error
}
