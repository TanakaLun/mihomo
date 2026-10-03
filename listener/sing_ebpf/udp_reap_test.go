//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"testing"
	"time"
)

func TestUDPClientTableSweepIdle(t *testing.T) {
	table := &udpClientTable{}
	client := netip.MustParseAddrPort("192.168.1.10:40000")
	state := table.loadOrCreate(client)
	now := time.Now()
	state.lastActive.Store(now.UnixNano())

	if _, available := table.sweepIdleAt(now.Add(10*time.Second), 5*time.Minute); !available {
		t.Fatal("active entry should leave a pending expiry")
	}
	if _, loaded := table.load(client); !loaded {
		t.Fatal("active client state should not be reaped")
	}
	if table.count() != 1 {
		t.Fatalf("table count = %d, want 1", table.count())
	}

	state.lastActive.Store(now.Add(-10 * time.Minute).UnixNano())
	if _, available := table.sweepIdleAt(now, 5*time.Minute); available {
		t.Fatal("reaping the only entry should leave no pending expiry")
	}
	if _, loaded := table.load(client); loaded {
		t.Fatal("idle client state should be reaped")
	}
	if table.count() != 0 {
		t.Fatalf("table count = %d, want 0", table.count())
	}
}

func TestSharedUDPClientTableSweepIdle(t *testing.T) {
	table := &sharedUDPClientTable{}
	client := netip.MustParseAddrPort("192.168.1.20:40001")
	destination := netip.MustParseAddrPort("93.184.216.34:443")
	redirect := netip.MustParseAddr("127.128.0.1")
	table.setBinding(client, destination, redirect, false)
	state, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state missing after setBinding")
	}

	state.lastActive.Store(time.Now().Add(-10 * time.Minute).UnixNano())
	if _, available := table.sweepIdleAt(time.Now(), 5*time.Minute); available {
		t.Fatal("reaping the only entry should leave no pending expiry")
	}
	if _, loaded := table.load(client); loaded {
		t.Fatal("idle shared client state should be reaped")
	}
	if len(table.redirectReferences) != 0 {
		t.Fatalf("redirectReferences = %d, want 0", len(table.redirectReferences))
	}
}