//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestCgroupRedirectABI(t *testing.T) {
	if size := unsafe.Sizeof(listenerLookupKey{}); size != 20 {
		t.Fatalf("unexpected redirect key size: %d", size)
	}
	if size := unsafe.Sizeof(originalDestinationValue{}); size != 32 {
		t.Fatalf("unexpected original destination size: %d", size)
	}
	if size := unsafe.Sizeof(udpFlowKey{}); size != 32 {
		t.Fatalf("unexpected UDP flow key size: %d", size)
	}
}

func TestMakeUDPFlowKey(t *testing.T) {
	original := originalDestinationValue{
		Family:       addressFamilyIPv4,
		Protocol:     ProtocolUDP,
		Port:         0x1234,
		Addr:         [16]byte{192, 168, 1, 1},
		Flags:        1,
		SocketCookie: 0x0102030405060708,
	}
	key := makeUDPFlowKey(original)
	if key.SocketCookie != original.SocketCookie {
		t.Fatalf("unexpected socket cookie: %#x", key.SocketCookie)
	}
	if key.Family != original.Family {
		t.Fatalf("unexpected family: %d", key.Family)
	}
	if key.Protocol != ProtocolUDP {
		t.Fatalf("unexpected protocol: %d", key.Protocol)
	}
	if key.Port != original.Port {
		t.Fatalf("unexpected port: %d", key.Port)
	}
	if key.Addr != original.Addr {
		t.Fatalf("unexpected address: %v", key.Addr)
	}
}

func TestEncodeAddress(t *testing.T) {
	var family uint8
	var address [16]byte
	if err := encodeAddress(&family, &address, netip.MustParseAddr("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	if family != addressFamilyIPv4 {
		t.Fatalf("unexpected family: %d", family)
	}
	if netip.AddrFrom4([4]byte(address[:4])) != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("unexpected IPv4 address: %v", address)
	}
	family = 0
	address = [16]byte{}
	if err := encodeAddress(&family, &address, netip.MustParseAddr("fd53::1")); err != nil {
		t.Fatal(err)
	}
	if family != addressFamilyIPv6 {
		t.Fatalf("unexpected family: %d", family)
	}
	if netip.AddrFrom16(address) != netip.MustParseAddr("fd53::1") {
		t.Fatalf("unexpected IPv6 address: %v", address)
	}
}
