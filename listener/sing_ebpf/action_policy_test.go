//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"strings"
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	LC "github.com/metacubex/mihomo/listener/config"
)

func TestNormalizeBypassExclude(t *testing.T) {
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	v6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	// valid: one v4 + one v6
	got, err := normalizeBypassExclude("local.bypass-exclude", []netip.Prefix{v4, v6})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(got))
	}
	// masked: un-aligned prefix is normalized
	raw := netip.MustParsePrefix("100.64.0.0/9")
	got, err = normalizeBypassExclude("local.bypass-exclude", []netip.Prefix{raw})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].String() != "100.0.0.0/9" {
		t.Fatalf("expected masked prefix, got %s", got[0])
	}
	// two v4 is an error
	if _, err = normalizeBypassExclude("local.bypass-exclude", []netip.Prefix{v4, netip.MustParsePrefix("10.0.0.0/8")}); err == nil {
		t.Fatal("expected two IPv4 prefixes to be rejected")
	}
	// two v6 is an error
	if _, err = normalizeBypassExclude("local.bypass-exclude", []netip.Prefix{v6, netip.MustParsePrefix("fd00::/8")}); err == nil {
		t.Fatal("expected two IPv6 prefixes to be rejected")
	}
	// IPv4-mapped IPv6 is converted to its IPv4 form
	mapped := netip.MustParsePrefix("::ffff:100.64.0.0/104")
	mappedPrefixes, err := normalizeBypassExclude("local.bypass-exclude", []netip.Prefix{mapped})
	if err != nil || len(mappedPrefixes) != 1 || mappedPrefixes[0].String() != "100.0.0.0/8" {
		t.Fatalf("expected IPv4-mapped IPv6 to be converted to IPv4, got %v, %v", mappedPrefixes, err)
	}
	// empty is fine
	got, err = normalizeBypassExclude("local.bypass-exclude", nil)
	if err != nil || got != nil {
		t.Fatalf("expected nil,nil for empty input, got %v,%v", got, err)
	}
}

func TestBypassExcludeConflict(t *testing.T) {
	i := &Inbound{
		localBypassExclude:  []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		sharedBypassExclude: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0::/48")},
	}
	if err := i.validateBypassExcludeConflicts(); err != nil {
		t.Fatal(err)
	}
	// fakeip v4 collides with local v4
	i.fakeIPIPv4Prefix = netip.MustParsePrefix("198.18.0.0/16")
	if err := i.validateBypassExcludeConflicts(); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("expected fakeip conflict error, got %v", err)
	}
	i.fakeIPIPv4Prefix = netip.Prefix{}
	// fakeip v6 collides with shared v6
	i.fakeIPIPv6Prefix = netip.MustParsePrefix("fdfe:dcba:9876::/64")
	if err := i.validateBypassExcludeConflicts(); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("expected fakeip conflict error, got %v", err)
	}
}

func TestCompileActionPolicyBypassExclude(t *testing.T) {
	i := &Inbound{
		enableTCP: true,
		enableUDP: true,
		localPolicy: localUIDPolicy{
			BypassPrivateAddress: true,
		},
		localBypassExclude: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
	}
	if _, err := i.compileActionPolicy(); err != nil {
		t.Fatal(err)
	}
}

func TestCompileActionPolicyConflictingBypassExclude(t *testing.T) {
	i := &Inbound{
		enableTCP: true,
		enableUDP: true,
		localPolicy: localUIDPolicy{
			BypassPrivateAddress: true,
		},
		localBypassExclude: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		fakeIPIPv4Prefix:   netip.MustParsePrefix("198.18.0.0/16"),
	}
	if _, err := i.compileActionPolicy(); err == nil {
		t.Fatal("expected fakeip conflict to abort policy compilation")
	}
}

var _ = LC.EBPF{}
var _ = commonEBPF.DecisionIntercept