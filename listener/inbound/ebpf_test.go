package inbound

import (
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	LC "github.com/metacubex/mihomo/listener/config"
)

func TestNewEBPFRejectsRemovedTopLevelMode(t *testing.T) {
	_, err := NewEBPF(&EBPFOption{
		BaseOption:     BaseOption{NameStr: "ebpf-in"},
		DeprecatedMode: "local",
	})
	if err == nil {
		t.Fatal("top-level mode should be rejected")
	}
}

func TestNewEBPFRejectsRemovedTopLevelBypassRuleSet(t *testing.T) {
	_, err := NewEBPF(&EBPFOption{
		BaseOption:              BaseOption{NameStr: "ebpf-in"},
		DeprecatedBypassRuleSet: []string{"CN_IP"},
	})
	if err == nil {
		t.Fatal("top-level bypass-rule-set should be rejected")
	}
}

func TestNewEBPFAcceptsNestedBypassRuleSet(t *testing.T) {
	listener, err := NewEBPF(&EBPFOption{
		BaseOption: BaseOption{NameStr: "ebpf-in"},
		Local: LC.EBPFLocal{
			BypassRuleSet: []string{"CN_IP"},
		},
	})
	if err != nil {
		t.Fatalf("nested bypass-rule-set should be accepted: %v", err)
	}
	if listener == nil {
		t.Fatal("nil listener")
	}
}

// TestRemovedTopLevelKeysDecodeIntoDeprecatedFields proves the structure
// decoder (the ParseListener path) still captures the removed keys, so NewEBPF
// can reject them instead of silently dropping them and disabling bypass.
func TestRemovedTopLevelKeysDecodeIntoDeprecatedFields(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "inbound", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	mapping := map[string]any{
		"name":            "ebpf-in",
		"mode":            "hybrid",
		"bypass-rule-set": []string{"CN_IP"},
		"local": map[string]any{
			"enable": true,
		},
	}
	var option EBPFOption
	if err := decoder.Decode(mapping, &option); err != nil {
		t.Fatal(err)
	}
	if option.DeprecatedMode != "hybrid" {
		t.Fatalf("top-level mode not decoded: %q", option.DeprecatedMode)
	}
	if len(option.DeprecatedBypassRuleSet) != 1 || option.DeprecatedBypassRuleSet[0] != "CN_IP" {
		t.Fatalf("top-level bypass-rule-set not decoded: %+v", option.DeprecatedBypassRuleSet)
	}
	if option.Local.Enable == nil || !*option.Local.Enable {
		t.Fatal("nested local.enable not decoded")
	}
}
