package config

import (
	"net/netip"
	"strconv"
	"strings"
)

type EBPF struct {
	Network         []string          `json:"network" yaml:"network"`
	UDPTimeout      int64             `json:"udp-timeout" yaml:"udp-timeout"`
	DNSMode         string            `json:"dns-mode" yaml:"dns-mode"`
	CgroupPath      string            `json:"cgroup-path" yaml:"cgroup-path"`
	RedirectAddress []netip.Prefix    `json:"redirect-address" yaml:"redirect-address"`
	BypassRuleSet   []string          `json:"bypass-rule-set" yaml:"bypass-rule-set"`
	IncludeUID      []uint32          `json:"include-uid" yaml:"include-uid"`
	IncludeUIDRange []string          `json:"include-uid-range" yaml:"include-uid-range"`
	ExcludeUID      []uint32          `json:"exclude-uid" yaml:"exclude-uid"`
	ExcludeUIDRange []string          `json:"exclude-uid-range" yaml:"exclude-uid-range"`
	MapCapacity     EBPFMapCapacity   `json:"map-capacity" yaml:"map-capacity"`
	SharedNetwork   EBPFSharedNetwork `json:"shared-network" yaml:"shared-network"`
}

type EBPFSharedNetwork struct {
	Enabled          bool     `json:"enabled" yaml:"enabled" inbound:"enabled,omitempty"`
	IncludeInterface []string `json:"include-interface" yaml:"include-interface" inbound:"include-interface,omitempty"`
	MapCapacity      uint32   `json:"map-capacity" yaml:"map-capacity" inbound:"map-capacity,omitempty"`
}

type EBPFMapCapacity struct {
	TCPRedirect  uint32 `json:"tcp-redirect" yaml:"tcp-redirect" inbound:"tcp-redirect,omitempty"`
	UDPRedirect  uint32 `json:"udp-redirect" yaml:"udp-redirect" inbound:"udp-redirect,omitempty"`
	SocketBypass uint32 `json:"socket-bypass" yaml:"socket-bypass" inbound:"socket-bypass,omitempty"`
}

func (c EBPF) String() string {
	builder := &strings.Builder{}
	builder.WriteString("network=")
	builder.WriteString(strings.Join(c.Network, ","))
	if c.CgroupPath != "" {
		builder.WriteString(", cgroup_path=")
		builder.WriteString(c.CgroupPath)
	}
	builder.WriteString(", redirect_address=")
	for index, prefix := range c.RedirectAddress {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(prefix.String())
	}
	builder.WriteString(", dns_mode=")
	builder.WriteString(c.DNSMode)
	builder.WriteString(", map_capacity={tcp_redirect:")
	builder.WriteString(strconv.FormatUint(uint64(c.MapCapacity.TCPRedirect), 10))
	builder.WriteString(", udp_redirect:")
	builder.WriteString(strconv.FormatUint(uint64(c.MapCapacity.UDPRedirect), 10))
	builder.WriteString(", socket_bypass:")
	builder.WriteString(strconv.FormatUint(uint64(c.MapCapacity.SocketBypass), 10))
	builder.WriteByte('}')
	return builder.String()
}
