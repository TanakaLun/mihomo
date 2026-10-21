package route

import (
	"net/netip"
	"testing"
)

func mp(s string) netip.Prefix {
	return netip.MustParsePrefix(s)
}

func ma(s string) netip.Addr {
	return netip.MustParseAddr(s)
}

var tunLUID = uint64(100)

func testRows() []Row {
	return []Row{
		{InterfaceLUID: tunLUID, Prefix: mp("0.0.0.0/0"), NextHop: ma("198.18.0.1"), Metric: 0},
		{InterfaceLUID: 1, Prefix: mp("0.0.0.0/0"), NextHop: ma("192.168.1.1"), Metric: 25},
		{InterfaceLUID: 1, Prefix: mp("10.0.0.0/8"), NextHop: ma("192.168.1.1"), Metric: 25},
		{InterfaceLUID: 2, Prefix: mp("100.64.0.0/10"), NextHop: ma("172.21.5.1"), Metric: 5},
		{InterfaceLUID: 2, Prefix: mp("::/0"), NextHop: ma("fe80::1"), Metric: 25},
		{InterfaceLUID: 1, Prefix: mp("::/1"), NextHop: ma("fe80::2"), Metric: 20},
		{InterfaceLUID: 1, Prefix: mp("2001:db8::/32"), NextHop: ma("fe80::3"), Metric: 20},
	}
}

func TestSelectBestPhysicalLongestPrefixWins(t *testing.T) {
	row, ok := SelectBestPhysical(testRows(), tunLUID, mp("10.5.5.0/24"))
	if !ok {
		t.Fatal("expected a physical route for 10.5.5.0/24")
	}
	if row != (Row{InterfaceLUID: 1, Prefix: mp("10.0.0.0/8"), NextHop: ma("192.168.1.1"), Metric: 25}) {
		t.Fatalf("expected 10/8 row, got %+v", row)
	}
}

func TestSelectBestPhysicalMetricTieBreak(t *testing.T) {
	rows := testRows()
	row, ok := SelectBestPhysical(rows, tunLUID, mp("100.64.1.0/24"))
	if !ok {
		t.Fatal("expected a physical route for 100.64.1.0/24")
	}
	// 100.64.0.0/10 via interface 2 must win over 0.0.0.0/0 via interface 1.
	if row.InterfaceLUID != 2 {
		t.Fatalf("expected interface 2 row, got %+v", row)
	}
}

func TestSelectBestPhysicalExcludesTun(t *testing.T) {
	// Only the TUN default route covers 172.16.0.0/12 → no physical route.
	rows := []Row{
		{InterfaceLUID: tunLUID, Prefix: mp("0.0.0.0/0"), NextHop: ma("198.18.0.1"), Metric: 0},
		{InterfaceLUID: 1, Prefix: mp("10.0.0.0/8"), NextHop: ma("192.168.1.1"), Metric: 25},
	}
	if _, ok := SelectBestPhysical(rows, tunLUID, mp("172.16.0.0/12")); ok {
		t.Fatal("excluded prefix must not select the TUN route")
	}
}

func TestSelectBestPhysicalPartiallyCoveringRejected(t *testing.T) {
	// 10.0.0.0/8 covers only part of 10.0.0.0/7 → must be rejected, even
	// though longer than 0/0.
	rows := []Row{
		{InterfaceLUID: 1, Prefix: mp("10.0.0.0/8"), NextHop: ma("192.168.1.1"), Metric: 25},
		{InterfaceLUID: 1, Prefix: mp("0.0.0.0/0"), NextHop: ma("192.168.1.1"), Metric: 25},
	}
	row, ok := SelectBestPhysical(rows, tunLUID, mp("10.0.0.0/7"))
	if !ok {
		t.Fatal("expected the 0/0 fallback to be selected")
	}
	if row.Prefix.Bits() != 0 {
		t.Fatalf("expected the 0/0 fallback, got %+v", row)
	}
}

func TestSelectBestPhysicalFamilyIsolated(t *testing.T) {
	// An IPv6 prefix must never match an IPv4 row.
	rows := []Row{
		{InterfaceLUID: 1, Prefix: mp("0.0.0.0/0"), NextHop: ma("192.168.1.1"), Metric: 25},
		{InterfaceLUID: 1, Prefix: mp("::/0"), NextHop: ma("fe80::1"), Metric: 5},
	}
	row, ok := SelectBestPhysical(rows, tunLUID, mp("2001:db8::/32"))
	if !ok || !row.Prefix.Addr().Is6() {
		t.Fatalf("expected the v6 default row, got %+v", row)
	}
}

func TestPlanAddAndRemove(t *testing.T) {
	current := []Key{
		{Prefix: mp("10.0.0.0/8"), NextHop: ma("192.168.1.1"), InterfaceLUID: 1},
		{Prefix: mp("172.16.0.0/12"), NextHop: ma("192.168.1.1"), InterfaceLUID: 1},
	}
	desired := []Key{
		{Prefix: mp("10.0.0.0/8"), NextHop: ma("192.168.1.1"), InterfaceLUID: 1},
		{Prefix: mp("192.168.0.0/16"), NextHop: ma("192.168.1.1"), InterfaceLUID: 1},
	}
	adds, removes := Plan(current, desired)
	if len(adds) != 1 || adds[0].Prefix.String() != "192.168.0.0/16" {
		t.Fatalf("unexpected adds: %+v", adds)
	}
	if len(removes) != 1 || removes[0].Prefix.String() != "172.16.0.0/12" {
		t.Fatalf("unexpected removes: %+v", removes)
	}
}

func TestPlanNextHopChangeReplaces(t *testing.T) {
	current := []Key{{Prefix: mp("10.0.0.0/8"), NextHop: ma("192.168.1.1"), InterfaceLUID: 1}}
	desired := []Key{{Prefix: mp("10.0.0.0/8"), NextHop: ma("192.168.2.1"), InterfaceLUID: 1}}
	adds, removes := Plan(current, desired)
	if len(adds) != 1 || len(removes) != 1 {
		t.Fatalf("next-hop change must add+remove, got adds=%d removes=%d", len(adds), len(removes))
	}
}

func TestPlanEmpty(t *testing.T) {
	adds, removes := Plan(nil, nil)
	if len(adds) != 0 || len(removes) != 0 {
		t.Fatalf("empty plan must be empty, got adds=%d removes=%d", len(adds), len(removes))
	}
}

func TestFilterProtected(t *testing.T) {
	prefixes := []netip.Prefix{mp("10.0.0.0/8"), mp("100.64.0.0/10"), mp("2001:db8::/32")}
	protected := []netip.Prefix{mp("100.64.0.0/10"), mp("198.18.0.0/15")}
	got := FilterProtected(prefixes, protected)
	if len(got) != 2 {
		t.Fatalf("expected 2 prefixes after filter, got %d: %+v", len(got), got)
	}
	if got[0].String() != "10.0.0.0/8" || got[1].String() != "2001:db8::/32" {
		t.Fatalf("unexpected survivors: %+v", got)
	}
}

func TestFilterProtectedBroaderGuardWins(t *testing.T) {
	// A bypass prefix that contains a protected prefix must also be dropped.
	prefixes := []netip.Prefix{mp("198.16.0.0/14")} // contains 198.18.0.0/15
	protected := []netip.Prefix{mp("198.18.0.0/15")}
	got := FilterProtected(prefixes, protected)
	if len(got) != 0 {
		t.Fatalf("prefix containing a protected prefix must be filtered, got %+v", got)
	}
}

func TestFilterProtectedNoProtected(t *testing.T) {
	prefixes := []netip.Prefix{mp("10.0.0.0/8")}
	if got := FilterProtected(prefixes, nil); len(got) != 1 {
		t.Fatalf("nil protected must not filter anything, got %+v", got)
	}
}
