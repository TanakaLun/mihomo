//go:build with_ebpf && (linux || android) && !cgo

package ebpf

import (
	"net/netip"

	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"

	"go4.org/netipx"
)

type CgroupBackend struct{}

func PrepareCgroup(CgroupConfig) (*CgroupBackend, error) {
	return nil, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) LoadPrograms(uint16) error {
	return E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) Attach() error {
	return E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) Close() error {
	return nil
}

func (b *CgroupBackend) IsClosed() bool {
	return true
}

func (b *CgroupBackend) UpdateBypassCIDR([]netip.Prefix) (bool, error) {
	return false, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) BypassCIDRCount() (int, int) {
	return 0, 0
}

func (b *CgroupBackend) BypassIPSet() *netipx.IPSet {
	return nil
}

func (b *CgroupBackend) CgroupPath() string {
	return ""
}

func (b *CgroupBackend) AttachedPrograms() []string {
	return nil
}

func (b *CgroupBackend) UsesSocketRelease() bool {
	return false
}

func (b *CgroupBackend) SelfBypassMode() string {
	return ""
}

func (b *CgroupBackend) SocketProtectFunc() control.Func {
	return nil
}

func (b *CgroupBackend) LookupOriginal(uint8, netip.AddrPort) (OriginalDestination, error) {
	return OriginalDestination{}, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) TakeOriginal(uint8, netip.AddrPort) (OriginalDestination, error) {
	return OriginalDestination{}, E.New("eBPF inbound is not supported by this build: cgo is disabled")
}

func (b *CgroupBackend) DeleteRedirect(uint8, netip.AddrPort) error {
	return E.New("eBPF inbound is not supported by this build: cgo is disabled")
}
