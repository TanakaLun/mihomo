//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"testing"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	LC "github.com/metacubex/mihomo/listener/config"

	tun "github.com/metacubex/sing-tun"
)

func TestValidateAndroidUIDOptions(t *testing.T) {
	androidOptions := LC.EBPFLocal{
		IncludeAndroidUser: []int{0, 10},
		IncludePackage:     []string{"com.example.include"},
		ExcludePackage:     []string{"com.example.exclude"},
	}
	if err := validateAndroidUIDOptions("android", androidOptions); err != nil {
		t.Fatal(err)
	}
	if err := validateAndroidUIDOptions("linux", androidOptions); err == nil {
		t.Fatal("expected Android UID options to be rejected on Linux")
	}
	androidOptions.IncludeAndroidUser = []int{-1}
	if err := validateAndroidUIDOptions("android", androidOptions); err == nil {
		t.Fatal("expected a negative Android user ID to be rejected")
	}
	androidOptions.IncludeAndroidUser = []int{42949}
	if err := validateAndroidUIDOptions("android", androidOptions); err == nil {
		t.Fatal("expected an overflowing Android user ID to be rejected")
	}
}

func TestResolveAndroidUIDRanges(t *testing.T) {
	packageManager := &testPackageManager{
		idByPackage: map[string]uint32{
			"com.example.include": 10001,
			"com.example.shared":  10002,
			"com.example.peer":    10002,
			"com.example.exclude": 10003,
		},
		packagesByID: map[uint32][]string{
			10001: {"com.example.include"},
			10002: {"com.example.shared", "com.example.peer"},
			10003: {"com.example.exclude"},
		},
	}
	policy := ECommon.LocalPolicy{
		IncludeUID: []ECommon.UIDRange{{Start: 2000, End: 2000}},
		ExcludeUID: []ECommon.UIDRange{{Start: 3000, End: 3000}},
	}
	options := &androidUIDOptions{
		includeAndroidUser: []int{0, 10},
		includePackage:     []string{"com.example.include", "com.example.shared"},
		excludePackage:     []string{"com.example.exclude"},
	}
	includeUID, excludeUID := resolveAndroidUIDRanges(policy, options, packageManager)
	for _, uid := range []uint32{2000, 10001, 10002, 1010001, 1010002} {
		if !uidInRanges(uid, includeUID) {
			t.Fatalf("expected UID %d in include policy: %+v", uid, includeUID)
		}
	}
	for _, uid := range []uint32{3000, 10003, 1010003, 500000, 1100000} {
		if !uidInRanges(uid, excludeUID) {
			t.Fatalf("expected UID %d in exclude policy: %+v", uid, excludeUID)
		}
	}
	for _, uid := range []uint32{10001, 1010001} {
		if uidInRanges(uid, excludeUID) {
			t.Fatalf("included package UID %d was unexpectedly excluded", uid)
		}
	}
}

func uidInRanges(uid uint32, uidRanges []ECommon.UIDRange) bool {
	for _, uidRange := range uidRanges {
		if uid >= uidRange.Start && uid <= uidRange.End {
			return true
		}
	}
	return false
}

var _ tun.PackageManager = (*testPackageManager)(nil)

type testPackageManager struct {
	idByPackage     map[string]uint32
	idByShared      map[string]uint32
	packagesByID    map[uint32][]string
	sharedPackageID map[uint32]string
}

func (m *testPackageManager) Start() error { return nil }
func (m *testPackageManager) Close() error { return nil }

func (m *testPackageManager) IDByPackage(packageName string) (uint32, bool) {
	uid, loaded := m.idByPackage[packageName]
	return uid, loaded
}

func (m *testPackageManager) IDBySharedPackage(packageName string) (uint32, bool) {
	uid, loaded := m.idByShared[packageName]
	return uid, loaded
}

func (m *testPackageManager) PackageByID(uid uint32) (string, bool) {
	packages, loaded := m.packagesByID[uid]
	if !loaded || len(packages) == 0 {
		return "", false
	}
	return packages[0], true
}

func (m *testPackageManager) PackagesByID(uid uint32) ([]string, bool) {
	packages, loaded := m.packagesByID[uid]
	return packages, loaded
}

func (m *testPackageManager) SharedPackageByID(uid uint32) (string, bool) {
	packageName, loaded := m.sharedPackageID[uid]
	return packageName, loaded
}
