package provider_test

import (
	"testing"

	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/provider"
	"github.com/stretchr/testify/assert"
)

func TestDomainStrategyDumpMrs(test *testing.T) {
	tests := []struct {
		name     string
		domains  []string
		expected []string
		queries  map[string]bool
	}{
		{
			"suffix-only",
			[]string{".example.com"},
			[]string{".example.com"},
			map[string]bool{"example.com": false, "www.example.com": true},
		},
		{
			"exact-only",
			[]string{"example.com"},
			[]string{"example.com"},
			map[string]bool{"example.com": true, "www.example.com": false},
		},
		{
			"merge-terminals",
			[]string{"example.com", ".example.com"},
			[]string{"+.example.com"},
			map[string]bool{"example.com": true, "www.example.com": true},
		},
		{
			"deduplicate",
			[]string{"+.example.com", "+.example.com", "example.com", ".example.com"},
			[]string{"+.example.com"},
			map[string]bool{"example.com": true, "www.example.com": true},
		},
		{
			"mixed",
			[]string{".example.com", "example.net", "example.org", ".example.org"},
			[]string{"+.example.org", ".example.com", "example.net"},
			map[string]bool{
				"example.com":     false,
				"www.example.com": true,
				"example.net":     true,
				"www.example.net": false,
				"example.org":     true,
				"www.example.org": true,
			},
		},
		{
			"wildcards",
			[]string{"*.example.com", "+.example.org", "test.*.google.com", ".test.*.google.com", ".example.net"},
			[]string{"*.example.com", "+.example.org", "+.test.*.google.com", ".example.net"},
			map[string]bool{
				"example.com":             false,
				"www.example.com":         true,
				"example.org":             true,
				"www.example.org":         true,
				"test.www.google.com":     true,
				"www.test.www.google.com": true,
				"example.net":             false,
				"www.example.net":         true,
			},
		},
	}
	for _, testCase := range tests {
		test.Run(testCase.name, func(test *testing.T) {
			strategy := provider.NewDomainStrategy()
			for _, domain := range testCase.domains {
				strategy.Insert(domain)
			}
			strategy.FinishInsert()
			rebuilt := provider.NewDomainStrategy()
			var domains []string
			strategy.DumpMrs(func(domain string) bool {
				domains = append(domains, domain)
				rebuilt.Insert(domain)
				return true
			})
			rebuilt.FinishInsert()
			assert.Equal(test, testCase.expected, domains)
			for domain, expected := range testCase.queries {
				metadata := &constant.Metadata{Host: domain}
				assert.Equal(test, expected, strategy.Match(metadata, constant.RuleMatchHelper{}), domain)
				assert.Equal(test, expected, rebuilt.Match(metadata, constant.RuleMatchHelper{}), domain)
			}
		})
	}
}
