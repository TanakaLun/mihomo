package inbound

import (
	"context"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_ebpf"
	"github.com/metacubex/mihomo/log"
)

type EBPFOption struct {
	BaseOption
	Network         []string           `inbound:"network,omitempty"`
	UDPTimeout      int64              `inbound:"udp-timeout,omitempty"`
	DNSMode         string             `inbound:"dns-mode,omitempty"`
	CgroupPath      string             `inbound:"cgroup-path,omitempty"`
	RedirectAddress []netip.Prefix     `inbound:"redirect-address,omitempty"`
	BypassRuleSet   []string           `inbound:"bypass-rule-set,omitempty"`
	IncludeUID      []uint32           `inbound:"include-uid,omitempty"`
	IncludeUIDRange []string           `inbound:"include-uid-range,omitempty"`
	ExcludeUID      []uint32           `inbound:"exclude-uid,omitempty"`
	ExcludeUIDRange []string           `inbound:"exclude-uid-range,omitempty"`
	MapCapacity     LC.EBPFMapCapacity `inbound:"map-capacity,omitempty"`
}

func (o EBPFOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type EBPF struct {
	*Base
	config *EBPFOption
	ebpf   LC.EBPF
	l      sing_ebpf.Listener
}

func NewEBPF(options *EBPFOption) (*EBPF, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &EBPF{
		Base:   base,
		config: options,
		ebpf: LC.EBPF{
			Network:         options.Network,
			UDPTimeout:      options.UDPTimeout,
			DNSMode:         options.DNSMode,
			CgroupPath:      options.CgroupPath,
			RedirectAddress: options.RedirectAddress,
			BypassRuleSet:   options.BypassRuleSet,
			IncludeUID:      options.IncludeUID,
			IncludeUIDRange: options.IncludeUIDRange,
			ExcludeUID:      options.ExcludeUID,
			ExcludeUIDRange: options.ExcludeUIDRange,
			MapCapacity:     options.MapCapacity,
		},
	}, nil
}

// Config implements constant.InboundListener
func (e *EBPF) Config() C.InboundConfig {
	return e.config
}

// Address implements constant.InboundListener
func (e *EBPF) Address() string {
	if e.l == nil {
		return ""
	}
	return e.l.Address()
}

// RawAddress implements constant.InboundListener
func (e *EBPF) RawAddress() string {
	return ""
}

// Listen implements constant.InboundListener
func (e *EBPF) Listen(tunnel C.Tunnel) error {
	var err error
	e.l, err = sing_ebpf.New(context.Background(), e.ebpf, tunnel, e.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("EBPF[%s] proxy listening at: %s", e.Name(), e.Address())
	return nil
}

// Close implements constant.InboundListener
func (e *EBPF) Close() error {
	if e.l != nil {
		return e.l.Close()
	}
	return nil
}

var _ C.InboundListener = (*EBPF)(nil)
