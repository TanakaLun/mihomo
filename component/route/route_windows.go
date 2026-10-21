//go:build windows

package route

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
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

// setScope fills the IPv6 scope identifier (the interface index). Link-local
// next hops require it, otherwise CreateIpForwardEntry2 rejects the route.
func (s *sockaddrInet) setScope(scope uint32) {
	if *(*uint16)(unsafe.Pointer(s)) == windows.AF_INET6 {
		s6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(s))
		s6.Scope_id = scope
	}
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
	// GetIpForwardTable2 returns a heap buffer that must be released with
	// FreeMibTable. Copy the rows into Go-owned memory before freeing it;
	// returning a slice over the C buffer would be a use-after-free once
	// the deferred free runs (the crashes seen after the empty-set bootstrap
	// landed were exactly this).
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))
	n := int(table.numEntries)
	if n < 0 || n > 1<<20 {
		return nil, fmt.Errorf("route: GetIpForwardTable2 family=%d returned implausible row count %d", family, n)
	}
	raw := unsafe.Slice(&table.table[0], n)
	rows := make([]mibIPForwardRow2, n)
	copy(rows, raw)
	return rows, nil
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
	row.InterfaceIndex = key.ScopeID
	row.DestinationPrefix.set(key.Prefix)
	row.NextHop.setAddr(key.NextHop)
	if key.NextHop.Is6() && key.NextHop.IsLinkLocalUnicast() {
		row.NextHop.setScope(key.ScopeID)
	}
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

// createForwardEntryFallback installs the route through the legacy route.exe
// command. It is only used when CreateIpForwardEntry2 keeps failing; route.exe
// talks to the same FIB but its error output is far more specific, which
// helps both diagnosis and edge cases where the WinAPI path misbehaves.
func createForwardEntryFallback(key Key) error {
	if !key.Prefix.Addr().Is4() {
		// route.exe IPv6 syntax differs; keep the WinAPI path there.
		return syscall.Errno(windows.ERROR_NOT_SUPPORTED)
	}
	mask := ipv4MaskString(key.Prefix.Bits())
	args := []string{
		"add",
		key.Prefix.Addr().String(),
		"mask", mask,
		key.NextHop.String(),
		"metric", strconv.FormatUint(uint64(key.Metric), 10),
		"if", strconv.FormatUint(uint64(key.ScopeID), 10),
	}
	out, err := exec.Command("route", args...).CombinedOutput()
	if err == nil {
		return nil
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		text = err.Error()
	}
	// An identical route already installed (by us or the operator) is fine.
	if strings.Contains(text, "already exists") || strings.Contains(text, "已存在") {
		return nil
	}
	return fmt.Errorf("route: route add %s via %s failed: %s", key.Prefix, key.NextHop, text)
}

// ipv4MaskString renders the dotted netmask for a /bits prefix.
func ipv4MaskString(bits int) string {
	var mask [4]byte
	for i := 0; i < 4; i++ {
		n := bits - i*8
		if n > 8 {
			n = 8
		}
		if n <= 0 {
			break
		}
		mask[i] = byte(0xff << (8 - n))
	}
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
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

func (r *router) Apply(prefixes []netip.Prefix) (int, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Nothing to install and nothing installed: skip the routing-table reads
	// entirely. The listener calls Apply at startup with an empty set (rule
	// providers load asynchronously), and reading the FIB during interface
	// churn is exactly where the earlier faults happened.
	if len(prefixes) == 0 && len(r.applied) == 0 {
		return 0, 0, nil
	}
	if err := r.ensureTunLUID(); err != nil {
		return 0, 0, err
	}

	rows4, err := ipForwardTable(windows.AF_INET)
	if err != nil {
		return 0, 0, err
	}
	rows6, err := ipForwardTable(windows.AF_INET6)
	if err != nil {
		return 0, 0, err
	}
	view4 := toRows(rows4)
	view6 := toRows(rows6)

	var skipped int
	desired := make(map[Key]struct{}, len(prefixes))
	for _, prefix := range FilterProtected(prefixes, r.protected) {
		prefix = prefix.Masked()
		if !prefix.IsValid() {
			skipped++
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
			skipped++
			continue
		}
		desired[Key{Prefix: prefix, NextHop: row.NextHop, InterfaceLUID: row.InterfaceLUID, ScopeID: row.InterfaceIndex, Metric: row.Metric}] = struct{}{}
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
	// A single add must not abort the whole batch: routes are read from a FIB
	// snapshot that can go stale during interface churn (for example right
	// after the default interface changes), so retry once and otherwise skip
	// the prefix, log a sample, and keep installing the rest.
	installed := 0
	var failed int
	var failedSamples []string
	const maxFailedSamples = 3
	failedKeys := make(map[Key]struct{})
	for _, key := range adds {
		err := createForwardEntry(newForwardRow(key))
		if err != nil {
			time.Sleep(50 * time.Millisecond) // let the interface settle
			err = createForwardEntry(newForwardRow(key))
		}
		if err != nil {
			err = createForwardEntryFallback(key)
		}
		if err == nil {
			installed++
			continue
		}
		failed++
		failedKeys[key] = struct{}{}
		if len(failedSamples) < maxFailedSamples {
			failedSamples = append(failedSamples,
				fmt.Sprintf("%s via %s (iface luid=%d index=%d metric=%d): %s", key.Prefix, key.NextHop, key.InterfaceLUID, key.ScopeID, key.Metric, err))
		}
	}
	var removalErr error
	for _, key := range removes {
		if err := deleteForwardEntry(newForwardRow(key)); err != nil && removalErr == nil {
			removalErr = err
		}
	}

	// Record only the routes that were actually installed; failed adds stay
	// out of applied so the next Apply retries them.
	applied := make(map[Key]struct{}, len(desired))
	for key := range desired {
		applied[key] = struct{}{}
	}
	for key := range failedKeys {
		delete(applied, key)
	}
	r.applied = applied

	if failed > 0 {
		msg := fmt.Sprintf("failed to install %d bypass routes; first %d: %s", failed, len(failedSamples), strings.Join(failedSamples, "; "))
		if installed == 0 {
			return 0, skipped, errors.New(msg)
		}
		return installed, skipped, errors.New(msg)
	}
	if removalErr != nil {
		// A failed removal is retried on the next Apply.
		return installed, skipped, removalErr
	}
	return installed, skipped, nil
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
			InterfaceLUID:  row.InterfaceLUID,
			InterfaceIndex: row.InterfaceIndex,
			Prefix:         prefix,
			NextHop:        nextHop,
			Metric:         row.Metric,
		})
	}
	return rows
}
