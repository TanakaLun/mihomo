package bypass

import (
	"net/netip"
	"testing"
)

func mustPrefix(s string) netip.Prefix {
	return netip.MustParsePrefix(s)
}

func TestRegistryUnionAndClose(t *testing.T) {
	reg := NewRegistry()
	if reg.Snapshot() != nil {
		t.Fatal("expected nil snapshot on empty registry")
	}

	a := reg.Register("a")
	b := reg.Register("b")

	a.Publish([]netip.Prefix{mustPrefix("10.0.0.0/8")})
	if set := reg.Snapshot(); set == nil || !set.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("snapshot should contain 10.0.0.0/8 after a publishes")
	}

	b.Publish([]netip.Prefix{mustPrefix("172.16.0.0/12"), mustPrefix("10.0.0.0/8")})
	set := reg.Snapshot()
	if set == nil {
		t.Fatal("snapshot should not be nil")
	}
	for _, ip := range []string{"10.1.2.3", "172.16.5.5", "172.31.255.255"} {
		if !set.Contains(netip.MustParseAddr(ip)) {
			t.Fatalf("snapshot should contain %s", ip)
		}
	}
	if set.Contains(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("snapshot should not contain 192.168.1.1")
	}

	b.Close()
	set = reg.Snapshot()
	if set == nil || !set.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("snapshot should keep a's union after b closes")
	}
	if set.Contains(netip.MustParseAddr("172.16.5.5")) {
		t.Fatal("snapshot should drop 172.16.0.0/12 after b closes")
	}

	a.Publish(nil)
	if reg.Snapshot() != nil {
		t.Fatal("snapshot should be nil after last publisher publishes nothing")
	}

	a.Close()
	if reg.Snapshot() != nil {
		t.Fatal("snapshot should stay nil after close")
	}
}

func TestPublisherCloseIdempotent(t *testing.T) {
	reg := NewRegistry()
	p := reg.Register("x")
	p.Publish([]netip.Prefix{mustPrefix("192.168.0.0/16")})
	p.Close()
	// closing twice must not panic or corrupt the registry
	p.Close()
	if reg.Snapshot() != nil {
		t.Fatal("snapshot should be nil after close")
	}
	// a new publisher after close still works
	q := reg.Register("y")
	q.Publish([]netip.Prefix{mustPrefix("10.0.0.0/8")})
	if set := reg.Snapshot(); set == nil || !set.Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("new publisher should be visible")
	}
	q.Close()
}

func TestGlobalRegistry(t *testing.T) {
	if Global() != global {
		t.Fatal("Global() must return the package registry")
	}
}
