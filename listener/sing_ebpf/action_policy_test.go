//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
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
	// multiple prefixes per family are accepted: the backend force-intercept
	// is an LPM trie, not a single slot.
	got, err = normalizeBypassExclude("local.bypass-exclude", []netip.Prefix{v4, netip.MustParsePrefix("10.0.0.0/8")})
	if err != nil {
		t.Fatalf("two IPv4 prefixes must be accepted: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 IPv4 prefixes, got %d", len(got))
	}
	got, err = normalizeBypassExclude("local.bypass-exclude", []netip.Prefix{v6, netip.MustParsePrefix("fd00::/8")})
	if err != nil {
		t.Fatalf("two IPv6 prefixes must be accepted: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 IPv6 prefixes, got %d", len(got))
	}
	// duplicate prefixes are collapsed
	got, err = normalizeBypassExclude("local.bypass-exclude", []netip.Prefix{v4, v4})
	if err != nil || len(got) != 1 {
		t.Fatalf("expected duplicate prefixes to collapse, got %v, %v", got, err)
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

// Fake-ip and bypass-exclude prefixes of the same address family are compiled
// into the same force LPM trie; they must not be rejected as "conflicting".
func TestCompileActionPolicyFakeIPWithBypassExclude(t *testing.T) {
	i := &Inbound{
		enableTCP: true,
		enableUDP: true,
		localPolicy: localUIDPolicy{
			BypassPrivateAddress: true,
		},
		localBypassExclude: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("203.0.113.0/24"),
		},
		fakeIPIPv4Prefix: netip.MustParsePrefix("198.18.0.0/16"),
	}
	if _, err := i.compileActionPolicy(); err != nil {
		t.Fatalf("fake-ip and bypass-exclude should coexist: %v", err)
	}
}

var _ = LC.EBPF{}
var _ = commonEBPF.DecisionIntercept
