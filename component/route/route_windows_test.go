//go:build windows

package route

import (
	"net/netip"
	"testing"
	"unsafe"
)

// The MIB_IPFORWARD_ROW2 layout is pinned so a future refactor cannot
// silently misread the route table. Offsets must match netioapi.h:
//
//	LUID(0) UINT32(8) IP_ADDRESS_PREFIX(12, 32B) SOCKADDR_INET(44, 28B)
//	UINT8(72) ULONG(76) ULONG(80) ULONG(84) ULONG(88)
//	BOOL(92) BOOL(93) BOOL(94) BOOL(95) ULONG Age(96) ULONG Origin(100)
func TestMibIPForwardRow2Layout(t *testing.T) {
	var row mibIPForwardRow2
	if size := unsafe.Sizeof(row); size != 104 {
		t.Fatalf("mibIPForwardRow2 size = %d, want 104", size)
	}
	check := func(what string, got, want uintptr) {
		if got != want {
			t.Fatalf("mibIPForwardRow2.%s offset = %d, want %d", what, got, want)
		}
	}
	check("InterfaceLUID", unsafe.Offsetof(row.InterfaceLUID), 0)
	check("InterfaceIndex", unsafe.Offsetof(row.InterfaceIndex), 8)
	check("DestinationPrefix", unsafe.Offsetof(row.DestinationPrefix), 12)
	check("NextHop", unsafe.Offsetof(row.NextHop), 44)
	check("SitePrefixLength", unsafe.Offsetof(row.SitePrefixLength), 72)
	check("ValidLifetime", unsafe.Offsetof(row.ValidLifetime), 76)
	check("Metric", unsafe.Offsetof(row.Metric), 84)
	check("Protocol", unsafe.Offsetof(row.Protocol), 88)
	check("Age", unsafe.Offsetof(row.Age), 96)
	check("Origin", unsafe.Offsetof(row.Origin), 100)

	if size := unsafe.Sizeof(ipAddressPrefix{}); size != 32 {
		t.Fatalf("ipAddressPrefix size = %d, want 32", size)
	}
	if size := unsafe.Sizeof(sockaddrInet{}); size != 28 {
		t.Fatalf("sockaddrInet size = %d, want 28", size)
	}
}

func TestSockaddrInetRoundTrip(t *testing.T) {
	for _, addr := range []string{"10.1.2.3", "fc00::1", "2001:db8::9"} {
		want := mustParseAddr(t, addr)
		var s sockaddrInet
		s.setAddr(want)
		got := s.addr()
		if got != want {
			t.Fatalf("round trip %s -> %s", want, got)
		}
	}
}

func mustParseAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}
