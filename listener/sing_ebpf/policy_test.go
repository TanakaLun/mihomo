//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"go4.org/netipx"
)

// ipcidrFakeRuleProvider is a minimal RuleProvider whose Strategy implements
// toIpCidr. loaded=false mirrors issue #34's startup window: a rule provider
// created but not yet initialized has a nil backing cidrSet, so ToIpCidr()
// returns nil and the collector must simply skip it (no log spam). loaded=true
// yields the collected prefixes.
type ipcidrFakeRuleProvider struct {
	name     string
	loaded   bool
	prefixes []netip.Prefix
}

func (f *ipcidrFakeRuleProvider) Name() string { return f.name }

func (f *ipcidrFakeRuleProvider) Strategy() any {
	if !f.loaded {
		return &ipcidrFakeStrategy{} // nil ToIpCidr
	}
	b := netipx.IPSetBuilder{}
	for _, p := range f.prefixes {
		b.AddPrefix(p)
	}
	set, _ := b.IPSet()
	return &ipcidrFakeStrategy{set: set}
}

func (f *ipcidrFakeRuleProvider) Count() int                 { return len(f.prefixes) }
func (f *ipcidrFakeRuleProvider) Behavior() P.RuleBehavior   { return P.IPCIDR }
func (f *ipcidrFakeRuleProvider) Initial() error             { return nil }
func (f *ipcidrFakeRuleProvider) Update() error              { return nil }
func (f *ipcidrFakeRuleProvider) VehicleType() P.VehicleType { return P.Inline }
func (f *ipcidrFakeRuleProvider) Type() P.ProviderType       { return P.Rule }
func (f *ipcidrFakeRuleProvider) Match(*constant.Metadata, constant.RuleMatchHelper) bool {
	return false
}

// ipcidrFakeStrategy implements toIpCidr. A zero value (set == nil) is what a
// fresh, not-yet-loaded ipcidr rule provider exposes.
type ipcidrFakeStrategy struct {
	set *netipx.IPSet
}

func (s *ipcidrFakeStrategy) ToIpCidr() *netipx.IPSet { return s.set }

func TestCollectBypassPrefixesSkipsLoadingProvider(t *testing.T) {
	loaded := &ipcidrFakeRuleProvider{
		name:     "loaded",
		loaded:   true,
		prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")},
	}
	loading := &ipcidrFakeRuleProvider{name: "loading"} // loaded=false

	prefixes := collectBypassPrefixes([]P.RuleProvider{loaded, loading})
	if len(prefixes) != 2 {
		t.Fatalf("collectBypassPrefixes = %v, want the loaded provider's 2 prefixes only", prefixes)
	}
	want := netip.MustParsePrefix("10.0.0.0/8")
	found := false
	for _, p := range prefixes {
		if p == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("loaded provider prefixes not collected: %v", prefixes)
	}
}
