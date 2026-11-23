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

// Every dns-mode except off must compile an intercept port decision for 53.
// Without it the kernel keeps evaluating bypass CIDRs and a bypass-rule-set
// that covers the upstream DNS address would pass the query in kernel, so the
// core never allocates a fake-ip (issue #45).
func TestAppendPortDecisionsDNSModes(t *testing.T) {
	cases := []struct {
		mode string
		want commonEBPF.Decision
	}{
		{dnsModeHijack, commonEBPF.DecisionIntercept},
		{dnsModeRespectPolicy, commonEBPF.DecisionIntercept},
		{dnsModeRespectBypass, commonEBPF.DecisionIntercept},
		{dnsModeOff, commonEBPF.DecisionPass},
	}
	for _, tc := range cases {
		var scope commonEBPF.ActionScope
		appendPortDecisions(&scope, nil, tc.mode, true, true)
		tcp, tcpSet := commonEBPF.Decision(0), false
		udp, udpSet := commonEBPF.Decision(0), false
		for _, decision := range scope.DestinationPort {
			if decision.Port != 53 {
				continue
			}
			switch decision.Protocol {
			case commonEBPF.ProtocolTCP:
				tcp, tcpSet = decision.Action, true
			case commonEBPF.ProtocolUDP:
				udp, udpSet = decision.Action, true
			}
		}
		if !tcpSet || !udpSet || tcp != tc.want || udp != tc.want {
			t.Fatalf("mode %s: tcp=%v/%v udp=%v/%v, want both %v",
				tc.mode, tcp, tcpSet, udp, udpSet, tc.want)
		}
	}
	// A bypass-port range that includes 53 must not turn the DNS intercept
	// into a pass while dns-mode is active.
	var scope commonEBPF.ActionScope
	appendPortDecisions(&scope, []PortRange{{Start: 53, End: 53}}, dnsModeRespectPolicy, true, true)
	for _, decision := range scope.DestinationPort {
		if decision.Port == 53 && decision.Action != commonEBPF.DecisionIntercept {
			t.Fatalf("bypass-port 53 overrode the DNS intercept: %v", decision.Action)
		}
	}
}

var _ = LC.EBPF{}
var _ = commonEBPF.DecisionIntercept
