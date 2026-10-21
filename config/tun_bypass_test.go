package config

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTunRouteExcludeBypassSources(t *testing.T) {
	raw := RawTun{
		Enable:                 true,
		AutoRoute:              true,
		RouteExcludeAddressSet: []string{"geoip-cn", "geoip-lan"},
		RouteExcludeAddress:    []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
	}
	general := &General{}
	err := parseTun(raw, &DNS{FakeIPRange: netip.MustParsePrefix("198.18.0.1/16")}, general)
	assert.Nil(t, err)
	assert.Equal(t, []string{"geoip-cn", "geoip-lan"}, general.Tun.RouteExcludeAddressSet)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}, general.Tun.RouteExcludeAddress)
}

func TestParseTunRejectsDeprecatedBypassKeys(t *testing.T) {
	general := &General{}
	err := parseTun(RawTun{DeprecatedBypassRuleSet: []string{"geoip-cn"}}, &DNS{FakeIPRange: netip.MustParsePrefix("198.18.0.1/16")}, general)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "route-exclude-address-set"))

	err = parseTun(RawTun{DeprecatedBypassAddress: []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24")}}, &DNS{FakeIPRange: netip.MustParsePrefix("198.18.0.1/16")}, general)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "route-exclude-address"))
}
