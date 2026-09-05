//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
)

func boolPtr(v bool) *bool { return &v }

func TestEnablementModeLocal(t *testing.T) {
	// mode: local only -> local enabled, shared disabled
	sel, err := normalizeDataPlanes(LC.EBPF{Mode: "local"})
	if err != nil {
		t.Fatal(err)
	}
	if !sel.localEnabled || sel.sharedEnabled {
		t.Fatalf("mode=local: local=%v shared=%v", sel.localEnabled, sel.sharedEnabled)
	}
	if sel.localDataPlane != localDataPlaneCgroup {
		t.Fatalf("mode=local default data plane = %q", sel.localDataPlane)
	}
}

func TestEnablementLocalEnabledField(t *testing.T) {
	// local.enabled: true, no shared -> local only
	sel, err := normalizeDataPlanes(LC.EBPF{
		Local: LC.EBPFLocal{Enabled: boolPtr(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sel.localEnabled || sel.sharedEnabled {
		t.Fatalf("local.enabled=true: local=%v shared=%v", sel.localEnabled, sel.sharedEnabled)
	}
}

func TestEnablementSharedEnabledField(t *testing.T) {
	// shared.enabled: true + interface -> shared only (no local)
	sel, err := normalizeDataPlanes(LC.EBPF{
		Shared: LC.EBPFShared{Enabled: boolPtr(true), Interface: []string{"wlan2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sel.localEnabled || !sel.sharedEnabled {
		t.Fatalf("shared.enabled=true: local=%v shared=%v", sel.localEnabled, sel.sharedEnabled)
	}
	if sel.sharedDataPlane != sharedDataPlanePacketRewrite {
		t.Fatalf("shared default data plane = %q", sel.sharedDataPlane)
	}
}

func TestValidateSharedDisabledNoConfig(t *testing.T) {
	// mode=local with empty shared block should NOT error
	var shared LC.EBPFShared
	if err := validateSharedOptions(false, shared); err != nil {
		t.Fatalf("empty shared config with shared disabled should pass: %v", err)
	}
}

func TestValidateSharedDisabledWithIPv6(t *testing.T) {
	// mode=local but shared.ipv6 set -> error (matches upstream intent)
	shared := LC.EBPFShared{IPv6: boolPtr(true)}
	if err := validateSharedOptions(false, shared); err == nil {
		t.Fatal("shared.ipv6 with shared disabled should error")
	}
}
