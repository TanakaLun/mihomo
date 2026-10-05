//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	LC "github.com/metacubex/mihomo/listener/config"
)

func boolPtr(v bool) *bool { return &v }

func TestEnablementDefaultLocal(t *testing.T) {
	// No local.enable / shared.enable -> local only by default.
	sel, err := normalizeDataPlanes(LC.EBPF{})
	if err != nil {
		t.Fatal(err)
	}
	if !sel.localEnabled || sel.sharedEnabled {
		t.Fatalf("default enablement: local=%v shared=%v", sel.localEnabled, sel.sharedEnabled)
	}
	if sel.localDataPlane != localDataPlaneCgroup {
		t.Fatalf("default data plane = %q", sel.localDataPlane)
	}
}

func TestEnablementLocalEnableField(t *testing.T) {
	// local.enable: true, no shared -> local only
	sel, err := normalizeDataPlanes(LC.EBPF{
		Local: LC.EBPFLocal{Enable: boolPtr(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sel.localEnabled || sel.sharedEnabled {
		t.Fatalf("local.enable=true: local=%v shared=%v", sel.localEnabled, sel.sharedEnabled)
	}
}

func TestEnablementSharedEnableField(t *testing.T) {
	// shared.enable: true + interface -> shared only (no local)
	sel, err := normalizeDataPlanes(LC.EBPF{
		Shared: LC.EBPFShared{Enable: boolPtr(true), Interface: []string{"wlan2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sel.localEnabled || !sel.sharedEnabled {
		t.Fatalf("shared.enable=true: local=%v shared=%v", sel.localEnabled, sel.sharedEnabled)
	}
	if sel.sharedDataPlane != sharedDataPlanePacketRewrite {
		t.Fatalf("shared default data plane = %q", sel.sharedDataPlane)
	}
}

func TestEnablementHybridEnableFields(t *testing.T) {
	// local.enable + shared.enable -> both
	sel, err := normalizeDataPlanes(LC.EBPF{
		Local:  LC.EBPFLocal{Enable: boolPtr(true)},
		Shared: LC.EBPFShared{Enable: boolPtr(true), Interface: []string{"wlan2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sel.localEnabled || !sel.sharedEnabled {
		t.Fatalf("hybrid enablement: local=%v shared=%v", sel.localEnabled, sel.sharedEnabled)
	}
}

func TestEnablementBothDisabled(t *testing.T) {
	// local.enable=false and shared.enable=false -> error
	if _, err := normalizeDataPlanes(LC.EBPF{
		Local:  LC.EBPFLocal{Enable: boolPtr(false)},
		Shared: LC.EBPFShared{Enable: boolPtr(false)},
	}); err == nil {
		t.Fatal("both disabled should error")
	}
}

func TestDisabledScopeDataPlaneInert(t *testing.T) {
	// A disabled data plane is inert: its block (data-plane, interface,
	// dns-mode, ...) is ignored rather than validated, so a kept-as-template
	// disabled scope cannot reject startup.
	sel, err := normalizeDataPlanes(LC.EBPF{
		Local: LC.EBPFLocal{Enable: boolPtr(true)},
		Shared: LC.EBPFShared{
			Enable:    boolPtr(false),
			DataPlane: "bogus",
			Interface: []string{"wlan2"},
			DNSMode:   "hijack",
		},
	})
	if err != nil {
		t.Fatalf("disabled shared scope with populated template should pass: %v", err)
	}
	if sel.sharedEnabled {
		t.Fatal("shared.enable=false must leave shared disabled")
	}
	if sel.sharedDataPlane != sharedDataPlanePacketRewrite {
		t.Fatalf("disabled shared data plane default = %q, want packet_rewrite", sel.sharedDataPlane)
	}

	phantom, err := normalizeDataPlanes(LC.EBPF{
		Local:  LC.EBPFLocal{Enable: boolPtr(true), DataPlane: "bogus"},
		Shared: LC.EBPFShared{Enable: boolPtr(true), DataPlane: "also-bogus"},
	})
	if err == nil {
		t.Fatal("enabled scopes must still validate their data-plane value")
	}
	_ = phantom
}

func TestEnableJSONTag(t *testing.T) {
	cases := []struct {
		name  string
		json  string
		check func(e LC.EBPF) bool
	}{
		{
			"local enable true",
			`{"local":{"enable":true}}`,
			func(e LC.EBPF) bool { return e.Local.Enable != nil && *e.Local.Enable },
		},
		{
			"shared enable true",
			`{"shared":{"enable":true,"interface":["wlan2"]}}`,
			func(e LC.EBPF) bool { return e.Shared.Enable != nil && *e.Shared.Enable },
		},
		{
			"shared enable false with data-plane",
			`{"shared":{"enable":false,"interface":["wlan2"]}}`,
			func(e LC.EBPF) bool { return e.Shared.Enable != nil && !*e.Shared.Enable },
		},
		{
			"local bypass rule set",
			`{"local":{"bypass-rule-set":["geoip-cn"]}}`,
			func(e LC.EBPF) bool { return len(e.Local.BypassRuleSet) == 1 && e.Local.BypassRuleSet[0] == "geoip-cn" },
		},
		{
			"shared bypass rule set",
			`{"shared":{"bypass-rule-set":["geoip-cn"]}}`,
			func(e LC.EBPF) bool {
				return len(e.Shared.BypassRuleSet) == 1 && e.Shared.BypassRuleSet[0] == "geoip-cn"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var e LC.EBPF
			if err := json.Unmarshal([]byte(tc.json), &e); err != nil {
				t.Fatal(err)
			}
			if !tc.check(e) {
				t.Fatalf("parse failed: %+v", e)
			}
		})
	}
}

func TestEnableViaStructureDecoder(t *testing.T) {
	// Reproduce the ParseListener decode path (common/structure with the
	// "inbound" tag) to prove local.enable / shared.enable and the per-scope
	// bypass-rule-set survive the full YAML-to-option mapping.
	decoder := structure.NewDecoder(structure.Option{TagName: "inbound", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	type option struct {
		Local  LC.EBPFLocal  `inbound:"local,omitempty"`
		Shared LC.EBPFShared `inbound:"shared,omitempty"`
	}
	mapping := map[string]any{
		"local": map[string]any{
			"enable":          true,
			"data-plane":      "cgroup",
			"ipv6":            true,
			"bypass-rule-set": []string{"geoip-cn"},
			"bypass-exclude":  []string{"100.64.0.0/10"},
		},
		"shared": map[string]any{
			"enable":          true,
			"interface":       []string{"wlan2"},
			"bypass-rule-set": []string{"geoip-lan"},
		},
	}
	var o option
	if err := decoder.Decode(mapping, &o); err != nil {
		t.Fatal(err)
	}
	if o.Local.Enable == nil || !*o.Local.Enable {
		t.Fatalf("local.enable not decoded: %+v", o.Local)
	}
	if o.Local.DataPlane != "cgroup" {
		t.Fatalf("local.data-plane not decoded: %+v", o.Local)
	}
	if len(o.Local.BypassRuleSet) != 1 || o.Local.BypassRuleSet[0] != "geoip-cn" {
		t.Fatalf("local.bypass-rule-set not decoded: %+v", o.Local)
	}
	if len(o.Local.BypassExclude) != 1 || o.Local.BypassExclude[0].String() != "100.64.0.0/10" {
		t.Fatalf("local.bypass-exclude not decoded: %+v", o.Local.BypassExclude)
	}
	if o.Shared.Enable == nil || !*o.Shared.Enable {
		t.Fatalf("shared.enable not decoded: %+v", o.Shared)
	}
	if len(o.Shared.BypassRuleSet) != 1 || o.Shared.BypassRuleSet[0] != "geoip-lan" {
		t.Fatalf("shared.bypass-rule-set not decoded: %+v", o.Shared)
	}
}
