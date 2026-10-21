//go:build windows

package route

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows data types mirrored from netioapi.h / winioctl (public API). The
// layout must march the C declarations byte-for-byte; the row struct is pinned
// by component/route tests on the field offsets.

const (
	routeErrorObjectAlreadyExists = syscall.Errno(5010) // ERROR_OBJECT_ALREADY_EXISTS
)

var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetIpForwardTable2          = modiphlpapi.NewProc("GetIpForwardTable2")
	procInitializeIpForwardEntry    = modiphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2       = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2       = modiphlpapi.NewProc("DeleteIpForwardEntry2")
	procFreeMibTable                = modiphlpapi.NewProc("FreeMibTable")
	procConvertInterfaceAliasToLuid = modiphlpapi.NewProc("ConvertInterfaceAliasToLuid")
)

// sockaddrInet is the SOCKADDR_INET union (28 bytes).
type sockaddrInet [28]byte

func (s *sockaddrInet) setAddr(addr netip.Addr) {
	*s = sockaddrInet{}
	if addr.Is4() {
		s4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(s))
		s4.Family = windows.AF_INET
		s4.Addr = addr.As4()
		return
	}
	s6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(s))
	s6.Family = windows.AF_INET6
	s6.Addr = addr.As16()
}

func (s *sockaddrInet) addr() netip.Addr {
	family := *(*uint16)(unsafe.Pointer(s))
	switch family {
	case windows.AF_INET:
		s4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(s))
		return netip.AddrFrom4(s4.Addr)
	case windows.AF_INET6:
		s6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(s))
		return netip.AddrFrom16(s6.Addr)
	}
	return netip.Addr{}
}

// ipAddressPrefix is IP_ADDRESS_PREFIX (SOCKADDR_INET + PrefixLength), padded
// to 32 bytes so the enclosing MIB_IPFORWARD_ROW2 offsets match the C layout.
type ipAddressPrefix struct {
	sock         sockaddrInet
	prefixLength uint8
	_            [3]byte
}

func (p *ipAddressPrefix) set(prefix netip.Prefix) {
	prefix = prefix.Masked()
	p.sock.setAddr(prefix.Addr())
	p.prefixLength = uint8(prefix.Bits())
}

func (p *ipAddressPrefix) prefix() netip.Prefix {
	addr := p.sock.addr()
	if !addr.IsValid() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(addr, int(p.prefixLength)).Masked()
}

// mibIPForwardRow2 mirrors MIB_IPFORWARD_ROW2 (104 bytes).
type mibIPForwardRow2 struct {
	InterfaceLUID        uint64
	InterfaceIndex       uint32
	DestinationPrefix    ipAddressPrefix
	NextHop              sockaddrInet
	SitePrefixLength     uint8
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             bool
	AutoconfigureAddress bool
	Publish              bool
	Immortal             bool
	Age                  uint32
	Origin               uint32
}

type mibIPForwardTable2 struct {
	numEntries uint32
	table      [1]mibIPForwardRow2
}

func ipForwardTable(family uint16) ([]mibIPForwardRow2, error) {
	var table *mibIPForwardTable2
	status, _, _ := procGetIpForwardTable2.Call(uintptr(family), uintptr(unsafe.Pointer(&table)))
	if status != 0 {
		return nil, fmt.Errorf("route: GetIpForwardTable2 family=%d failed: %w", family, statusErr(status))
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))
	return unsafe.Slice(&table.table[0], int(table.numEntries)), nil
}

// statusErr converts a NETIOAPI_STATUS return value into an error. These
// iphlpapi functions return their status code directly instead of setting the
// thread's last error, so GetLastError must not be used.
func statusErr(status uintptr) error {
	if status == 0 {
		return nil
	}
	return syscall.Errno(status)
}

func newForwardRow(key Key) *mibIPForwardRow2 {
	row := &mibIPForwardRow2{}
	procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(row)))
	row.InterfaceLUID = key.InterfaceLUID
	row.DestinationPrefix.set(key.Prefix)
	row.NextHop.setAddr(key.NextHop)
	row.Metric = key.Metric
	return row
}

func createForwardEntry(row *mibIPForwardRow2) error {
	status, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if status == 0 {
		return nil
	}
	if statusErr(status) == routeErrorObjectAlreadyExists {
		return nil // already installed (e.g. by the operator); not an error
	}
	return fmt.Errorf("route: CreateIpForwardEntry2 %s via %s failed: %w", row.DestinationPrefix.prefix(), row.NextHop.addr(), statusErr(status))
}

func deleteForwardEntry(row *mibIPForwardRow2) error {
	status, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if status == 0 {
		return nil
	}
	return fmt.Errorf("route: DeleteIpForwardEntry2 %s via %s failed: %w", row.DestinationPrefix.prefix(), row.NextHop.addr(), statusErr(status))
}

// router is the Windows Router implementation. It is safe for concurrent use.
type router struct {
	tunInterface string
	tunLUID      uint64
	initialized  bool
	protected    []netip.Prefix

	mu      sync.Mutex
	applied map[Key]struct{}
}

// NewRouter returns a Router that installs bypass routes on physical
// interfaces. tunInterface is the TUN device alias whose routes must never be
// used as the physical next hop; protected lists prefixes that must always
// stay on the TUN path (for example the TUN's own addressing) and are never
// bypassed.
func NewRouter(tunInterface string, protected []netip.Prefix) (Router, error) {
	if tunInterface == "" {
		return nil, errors.New("route: empty tun interface name")
	}
	return &router{tunInterface: tunInterface, protected: protected, applied: make(map[Key]struct{})}, nil
}

func (r *router) ensureTunLUID() error {
	if r.initialized {
		return nil
	}
	name, err := syscall.UTF16PtrFromString(r.tunInterface)
	if err != nil {
		return err
	}
	var luid uint64
	status, _, _ := procConvertInterfaceAliasToLuid.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&luid)))
	if status != 0 {
		if statusErr(status) == windows.ERROR_FILE_NOT_FOUND {
			return fmt.Errorf("route: tun interface %q not found yet", r.tunInterface)
		}
		return fmt.Errorf("route: ConvertInterfaceAliasToLuid %q failed: %w", r.tunInterface, statusErr(status))
	}
	r.tunLUID = luid
	r.initialized = true
	return nil
}

func (r *router) Apply(prefixes []netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ensureTunLUID(); err != nil {
		return err
	}

	rows4, err := ipForwardTable(windows.AF_INET)
	if err != nil {
		return err
	}
	rows6, err := ipForwardTable(windows.AF_INET6)
	if err != nil {
		return err
	}
	view4 := toRows(rows4)
	view6 := toRows(rows6)

	desired := make(map[Key]struct{}, len(prefixes))
	for _, prefix := range FilterProtected(prefixes, r.protected) {
		prefix = prefix.Masked()
		if !prefix.IsValid() {
			continue
		}
		view := view4
		if prefix.Addr().Is6() {
			view = view6
		}
		row, ok := SelectBestPhysical(view, r.tunLUID, prefix)
		if !ok {
			// No physical route covers this prefix; leaving it in the TUN is
			// the safe fallback (it gets proxied as usual).
			continue
		}
		desired[Key{Prefix: prefix, NextHop: row.NextHop, InterfaceLUID: row.InterfaceLUID, Metric: row.Metric}] = struct{}{}
	}
	desiredKeys := make([]Key, 0, len(desired))
	for key := range desired {
		desiredKeys = append(desiredKeys, key)
	}
	currentKeys := make([]Key, 0, len(r.applied))
	for key := range r.applied {
		currentKeys = append(currentKeys, key)
	}
	adds, removes := Plan(currentKeys, desiredKeys)

	// Add first, then delete, so a changed next hop never black-holes.
	for _, key := range adds {
		if err := createForwardEntry(newForwardRow(key)); err != nil {
			return err
		}
	}
	var removalErr error
	for _, key := range removes {
		if err := deleteForwardEntry(newForwardRow(key)); err != nil && removalErr == nil {
			removalErr = err
		}
	}
	if removalErr != nil {
		// The applied map is only updated on success below; a failed removal
		// is retried on the next Apply.
		return removalErr
	}
	r.applied = desired
	return nil
}

func (r *router) Reset() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	keys := make([]Key, 0, len(r.applied))
	for key := range r.applied {
		keys = append(keys, key)
	}
	removalErr := error(nil)
	for _, key := range keys {
		if err := deleteForwardEntry(newForwardRow(key)); err != nil && removalErr == nil {
			removalErr = err
		}
	}
	r.applied = make(map[Key]struct{})
	return removalErr
}

func toRows(table []mibIPForwardRow2) []Row {
	rows := make([]Row, 0, len(table))
	for i := range table {
		row := &table[i]
		prefix := row.DestinationPrefix.prefix()
		nextHop := row.NextHop.addr()
		if !prefix.IsValid() || !nextHop.IsValid() {
			continue
		}
		rows = append(rows, Row{
			InterfaceLUID: row.InterfaceLUID,
			Prefix:        prefix,
			NextHop:       nextHop,
			Metric:        row.Metric,
		})
	}
	return rows
}
