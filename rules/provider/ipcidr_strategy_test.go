package provider

import (
	"bytes"
	"testing"

	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIPCIDRStrategyMrsRoundTrip verifies the mrs conversion/parse path used
// by bypass-rule-set rule providers: a text/IP list converted with
// ConvertToMrs must parse back with the same prefixes and expose them through
// ToIpCidr. This mirrors issue #34's CN_IP (remote mrs) and fcm_ip (a local
// list the user converted to mrs) configs.
func TestIPCIDRStrategyMrsRoundTrip(test *testing.T) {
	cases := []struct {
		name     string
		rules    []string
		expected []string
	}{
		{
			name:     "single",
			rules:    []string{"10.0.0.0/8"},
			expected: []string{"10.0.0.0/8"},
		},
		{
			name:     "merge-adjacent",
			rules:    []string{"192.168.0.0/24", "192.168.1.0/24"},
			expected: []string{"192.168.0.0/23"},
		},
		{
			name:     "v6",
			rules:    []string{"2001:db8::/32"},
			expected: []string{"2001:db8::/32"},
		},
		{
			name:     "mixed-and-merged",
			rules:    []string{"1.0.0.0/24", "1.0.1.0/24", "2001:db8:1::/48"},
			expected: []string{"1.0.0.0/23", "2001:db8:1::/48"},
		},
	}
	for _, tc := range cases {
		test.Run(tc.name, func(test *testing.T) {
			var text bytes.Buffer
			text.WriteString("payload:\n")
			for _, rule := range tc.rules {
				text.WriteString("  - " + rule + "\n")
			}

			var mrs bytes.Buffer
			err := ConvertToMrs(text.Bytes(), P.IPCIDR, P.YamlRule, &mrs)
			require.NoError(test, err, "ConvertToMrs")

			strategy := newStrategy(P.IPCIDR, nil).(*ipcidrStrategy)
			n, err := rulesMrsParse(mrs.Bytes(), strategy)
			require.NoError(test, err, "parse mrs")
			parsed, ok := n.(*ipcidrStrategy)
			require.True(test, ok, "mrs parse returned an ipcidr strategy")
			assert.NotNil(test, parsed.ToIpCidr(), "ToIpCidr after mrs parse must not be nil")
			var got []string
			parsed.DumpMrs(func(prefix string) bool {
				got = append(got, prefix)
				return true
			})
			assert.ElementsMatch(test, tc.expected, got)
		})
	}
}

// TestIPCIDRStrategyToIpCidrFreshStrategy captures the exact condition issue
// #34 reports: a just-created ipcidr rule provider (before Initial completes)
// has a nil backing cidrSet, so ToIpCidr() returns nil and the eBPF
// bypass_rule_set collector warns "no IP-CIDR rules loaded". The warning is
// expected while the provider is still loading; the log firehose issue is that
// every rule-set update re-arms it.
func TestIPCIDRStrategyToIpCidrFreshStrategy(test *testing.T) {
	strategy := newStrategy(P.IPCIDR, nil).(*ipcidrStrategy)
	require.NotNil(test, strategy)
	// A fresh strategy has no rules yet; ToIpCidr must be nil, matching the
	// collector's "silently ignored" branch. After Insert/FinishInsert it must
	// become non-nil.
	assert.Nil(test, strategy.ToIpCidr(), "fresh ipcidr strategy exposes no IP set")

	strategy.Reset()
	strategy.Insert("10.0.0.0/8")
	strategy.FinishInsert()
	assert.NotNil(test, strategy.ToIpCidr(), "ipcidr strategy after load exposes an IP set")
}

// TestEmptyMrsRejected mirrors a user-converted empty rule list: an ipcidr list
// with no rules must not produce a readable mrs (ConvertToMrs refuses it).
func TestEmptyMrsRejected(test *testing.T) {
	text := []byte("payload:\n")
	var mrs bytes.Buffer
	err := ConvertToMrs(text, P.IPCIDR, P.YamlRule, &mrs)
	assert.Error(test, err, "empty ipcidr list must not convert to mrs")
}
