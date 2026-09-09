package inbound

import (
	"context"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_ebpf"
	"github.com/metacubex/mihomo/log"
)

type EBPFOption struct {
	BaseOption
	Mode          string        `inbound:"mode,omitempty"`
	Network       []string      `inbound:"network,omitempty"`
	UDPTimeout    int64         `inbound:"udp-timeout,omitempty"`
	TCPriority    uint16        `inbound:"tc-priority,omitempty"`
	BypassRuleSet []string      `inbound:"bypass-rule-set,omitempty"`
	FakeIPICMP    string        `inbound:"fakeip-icmp,omitempty"`
	Local         LC.EBPFLocal  `inbound:"local,omitempty"`
	Shared        LC.EBPFShared `inbound:"shared,omitempty"`
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
			Mode:          options.Mode,
			Network:       options.Network,
			UDPTimeout:    options.UDPTimeout,
			TCPriority:    options.TCPriority,
			BypassRuleSet: options.BypassRuleSet,
			FakeIPICMP:    options.FakeIPICMP,
			Local:         options.Local,
			Shared:        options.Shared,
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
