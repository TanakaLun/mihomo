package config

import (
	"net/netip"
	"strings"
)

type EBPF struct {
	Mode          string     `json:"mode" yaml:"mode" inbound:"mode,omitempty"`
	Network       []string   `json:"network" yaml:"network"`
	UDPTimeout    int64      `json:"udp-timeout" yaml:"udp-timeout"`
	TCPriority    uint16     `json:"tc-priority" yaml:"tc-priority" inbound:"tc-priority,omitempty"`
	BypassRuleSet []string   `json:"bypass-rule-set" yaml:"bypass-rule-set"`
	Local         EBPFLocal  `json:"local" yaml:"local" inbound:"local,omitempty"`
	Shared        EBPFShared `json:"shared" yaml:"shared" inbound:"shared,omitempty"`
}

type EBPFLocal struct {
	Enabled              *bool    `json:"enabled" yaml:"enabled" inbound:"enabled,omitempty"`
	DataPlane            string   `json:"data-plane" yaml:"data-plane" inbound:"data-plane,omitempty"`
	CgroupPath           string   `json:"cgroup-path" yaml:"cgroup-path" inbound:"cgroup-path,omitempty"`
	DNSMode              string   `json:"dns-mode" yaml:"dns-mode" inbound:"dns-mode,omitempty"`
	IPv6                 *bool    `json:"ipv6" yaml:"ipv6" inbound:"ipv6,omitempty"`
	BypassPrivateAddress *bool    `json:"bypass-private-address" yaml:"bypass-private-address" inbound:"bypass-private-address,omitempty"`
	IncludeUID           []uint32 `json:"include-uid" yaml:"include-uid" inbound:"include-uid,omitempty"`
	IncludeUIDRange      []string `json:"include-uid-range" yaml:"include-uid-range" inbound:"include-uid-range,omitempty"`
	ExcludeUID           []uint32 `json:"exclude-uid" yaml:"exclude-uid" inbound:"exclude-uid,omitempty"`
	ExcludeUIDRange      []string `json:"exclude-uid-range" yaml:"exclude-uid-range" inbound:"exclude-uid-range,omitempty"`
	IncludeAndroidUser   []int    `json:"include-android-user" yaml:"include-android-user" inbound:"include-android-user,omitempty"`
	IncludePackage       []string `json:"include-package" yaml:"include-package" inbound:"include-package,omitempty"`
	ExcludePackage       []string `json:"exclude-package" yaml:"exclude-package" inbound:"exclude-package,omitempty"`
	BypassPort           []uint16 `json:"bypass-port" yaml:"bypass-port" inbound:"bypass-port,omitempty"`
	BypassPortRange      []string `json:"bypass-port-range" yaml:"bypass-port-range" inbound:"bypass-port-range,omitempty"`
}

type EBPFShared struct {
	Enabled              *bool          `json:"enabled" yaml:"enabled" inbound:"enabled,omitempty"`
	DataPlane            string         `json:"data-plane" yaml:"data-plane" inbound:"data-plane,omitempty"`
	DNSMode              string         `json:"dns-mode" yaml:"dns-mode" inbound:"dns-mode,omitempty"`
	Interface            []string       `json:"interface" yaml:"interface" inbound:"interface,omitempty"`
	IPv6                 *bool          `json:"ipv6" yaml:"ipv6" inbound:"ipv6,omitempty"`
	BypassPrivateAddress *bool          `json:"bypass-private-address" yaml:"bypass-private-address" inbound:"bypass-private-address,omitempty"`
	IncludeSourceCIDR    []netip.Prefix `json:"include-source-cidr" yaml:"include-source-cidr" inbound:"include-source-cidr,omitempty"`
	ExcludeSourceCIDR    []netip.Prefix `json:"exclude-source-cidr" yaml:"exclude-source-cidr" inbound:"exclude-source-cidr,omitempty"`
	IncludeMACAddress    []string       `json:"include-mac-address" yaml:"include-mac-address" inbound:"include-mac-address,omitempty"`
	ExcludeMACAddress    []string       `json:"exclude-mac-address" yaml:"exclude-mac-address" inbound:"exclude-mac-address,omitempty"`
	BypassPort           []uint16       `json:"bypass-port" yaml:"bypass-port" inbound:"bypass-port,omitempty"`
	BypassPortRange      []string       `json:"bypass-port-range" yaml:"bypass-port-range" inbound:"bypass-port-range,omitempty"`
}

func (c EBPF) String() string {
	builder := &strings.Builder{}
	builder.WriteString("mode=")
	builder.WriteString(c.Mode)
	builder.WriteString(", network=")
	builder.WriteString(strings.Join(c.Network, ","))
	return builder.String()
}
