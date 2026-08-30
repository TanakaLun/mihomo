package resolver

import "net/netip"

var DefaultHostMapper Enhancer

// EBFPFakeIPRanges holds the DNS fake-ip prefixes registered by the DNS
// enhancer and consumed by the TC eBPF inbound (TCConfig.FakeIPIPv4/6). It
// mirrors the EBFPBypassIPSet leaf-store pattern so the adapter does not need
// to import the config package.
var EBFPFakeIPRanges EBPPrefixStore

type EBPPrefixStore struct {
	ipv4 netip.Prefix
	ipv6 netip.Prefix
}

func (s *EBPPrefixStore) Set(ipv4, ipv6 netip.Prefix) {
	s.ipv4 = ipv4
	s.ipv6 = ipv6
}

func (s *EBPPrefixStore) Get() (netip.Prefix, netip.Prefix) {
	return s.ipv4, s.ipv6
}

type Enhancer interface {
	FakeIPEnabled() bool
	MappingEnabled() bool
	IsFakeIP(netip.Addr) bool
	IsFakeBroadcastIP(netip.Addr) bool
	IsExistFakeIP(netip.Addr) bool
	FindHostByIP(netip.Addr) (string, bool)
	FlushFakeIP() error
	InsertHostByIP(netip.Addr, string)
	StoreFakePoolState()
}

func FakeIPEnabled() bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.FakeIPEnabled()
	}

	return false
}

func MappingEnabled() bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.MappingEnabled()
	}

	return false
}

func IsFakeIP(ip netip.Addr) bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.IsFakeIP(ip)
	}

	return false
}

func IsFakeBroadcastIP(ip netip.Addr) bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.IsFakeBroadcastIP(ip)
	}

	return false
}

func IsExistFakeIP(ip netip.Addr) bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.IsExistFakeIP(ip)
	}

	return false
}

func InsertHostByIP(ip netip.Addr, host string) {
	if mapper := DefaultHostMapper; mapper != nil {
		mapper.InsertHostByIP(ip, host)
	}
}

func FindHostByIP(ip netip.Addr) (string, bool) {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.FindHostByIP(ip)
	}

	return "", false
}

func FlushFakeIP() error {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.FlushFakeIP()
	}
	return nil
}

func StoreFakePoolState() {
	if mapper := DefaultHostMapper; mapper != nil {
		mapper.StoreFakePoolState()
	}
}
