//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"errors"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func (b *CgroupBackend) SocketProtectFunc() control.Func {
	if b == nil {
		return nil
	}
	return func(network string, address string, rawConn syscall.RawConn) error {
		return control.Raw(rawConn, func(fd uintptr) error {
			b.access.RLock()
			defer b.access.RUnlock()
			if b.runtime == nil {
				return errBackendClosed
			}
			cookie, err := readSocketCookie(fd)
			if err != nil {
				return E.Cause(err, "read socket cookie")
			}
			value := uint8(1)
			if err = updateMap(b.socketBypassMapFD, unsafe.Pointer(&cookie), unsafe.Pointer(&value)); err != nil {
				return E.Cause(err, "register eBPF bypass socket")
			}
			return nil
		})
	}
}

func (b *CgroupBackend) LookupOriginal(protocol uint8, listenerDestination netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, listenerDestination, false)
}

func (b *CgroupBackend) TakeOriginal(protocol uint8, listenerDestination netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, listenerDestination, true)
}

func (b *CgroupBackend) lookupOriginal(
	protocol uint8,
	listenerDestination netip.AddrPort,
	deleteAfterLookup bool,
) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, errBackendClosed
	}
	key, err := makeListenerLookupKey(protocol, listenerDestination)
	if err != nil {
		return OriginalDestination{}, err
	}
	var original originalDestinationValue
	redirectMap, err := b.redirectMap(protocol)
	if err != nil {
		return OriginalDestination{}, err
	}
	err = lookupMap(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup original destination")
	}
	var address netip.Addr
	switch original.Family {
	case addressFamilyIPv4:
		address = netip.AddrFrom4([4]byte(original.Addr[:4]))
	case addressFamilyIPv6:
		address = netip.AddrFrom16(original.Addr)
	default:
		return OriginalDestination{}, E.New("invalid original destination family: ", original.Family)
	}
	if deleteAfterLookup {
		err = deleteMap(redirectMap, unsafe.Pointer(&key))
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return OriginalDestination{}, E.Cause(err, "delete consumed redirect mapping")
		}
	}
	return OriginalDestination{
		Destination:  netip.AddrPortFrom(address.Unmap(), original.Port),
		ConnectedUDP: original.Flags&1 != 0,
		UID:          original.UID,
	}, nil
}

func (b *CgroupBackend) DeleteRedirect(protocol uint8, listenerDestination netip.AddrPort) error {
	if b == nil {
		return errBackendClosed
	}
	key, err := makeListenerLookupKey(protocol, listenerDestination)
	if err != nil {
		return err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	redirectMap, err := b.redirectMap(protocol)
	if err != nil {
		return err
	}
	err = deleteMap(redirectMap, unsafe.Pointer(&key))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "delete redirect mapping")
	}
	return nil
}

func (b *CgroupBackend) redirectMap(protocol uint8) (int, error) {
	switch protocol {
	case ProtocolTCP:
		return b.tcpRedirectMapFD, nil
	case ProtocolUDP:
		return b.udpRedirectMapFD, nil
	default:
		return -1, E.New("unsupported eBPF redirect protocol: ", protocol)
	}
}
