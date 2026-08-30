//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"slices"
	"strings"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"
	ranges "github.com/metacubex/sing/common/ranges"

	tun "github.com/metacubex/sing-tun"
)

const androidUserRange = 100000

type androidUIDOptions struct {
	includeAndroidUser []int
	includePackage     []string
	excludePackage     []string
}

func newAndroidUIDOptions(options LC.EBPFLocal) *androidUIDOptions {
	if !hasAndroidUIDOptions(options) {
		return nil
	}
	return &androidUIDOptions{
		includeAndroidUser: slices.Clone(options.IncludeAndroidUser),
		includePackage:     slices.Clone(options.IncludePackage),
		excludePackage:     slices.Clone(options.ExcludePackage),
	}
}

func (i *Inbound) resolveAndroidUIDPolicy() error {
	packageManager, err := androidPackageManager()
	if (len(i.androidUIDOptions.includePackage) > 0 || len(i.androidUIDOptions.excludePackage) > 0) && err != nil {
		return E.Cause(err, "Android package manager is unavailable")
	}
	warnSharedUID := make(map[uint32]struct{})
	i.inspectAndroidPackages(packageManager, "include", i.androidUIDOptions.includePackage, warnSharedUID)
	i.inspectAndroidPackages(packageManager, "exclude", i.androidUIDOptions.excludePackage, warnSharedUID)
	includeUID, excludeUID := resolveAndroidUIDRanges(i.localPolicy, i.androidUIDOptions, packageManager)
	i.localPolicy.IncludeUID = includeUID
	i.localPolicy.ExcludeUID = excludeUID
	log.Infoln("[EBPF] resolved Android UID policy at startup: include_ranges=%d, exclude_ranges=%d",
		len(i.localPolicy.IncludeUID),
		len(i.localPolicy.ExcludeUID),
	)
	return nil
}

// resolveAndroidUIDRanges expands the Android user/package policy into concrete
// UID ranges, preserving any pre-existing include/exclude UID ranges.
func resolveAndroidUIDRanges(
	policy ECommon.LocalPolicy,
	options *androidUIDOptions,
	packageManager tun.PackageManager,
) ([]ECommon.UIDRange, []ECommon.UIDRange) {
	tunOptions := tun.Options{
		IncludeUID:         toTunUIDRanges(policy.IncludeUID),
		ExcludeUID:         toTunUIDRanges(policy.ExcludeUID),
		IncludeAndroidUser: slices.Clone(options.includeAndroidUser),
		IncludePackage:     slices.Clone(options.includePackage),
		ExcludePackage:     slices.Clone(options.excludePackage),
	}
	tunOptions.BuildAndroidRules(packageManager, androidUIDErrorHandler{})
	return fromTunUIDRanges(tunOptions.IncludeUID), fromTunUIDRanges(tunOptions.ExcludeUID)
}

func (i *Inbound) inspectAndroidPackages(packageManager tun.PackageManager, mode string, packageNames []string, warnedSharedUID map[uint32]struct{}) {
	if packageManager == nil {
		return
	}
	for _, packageName := range packageNames {
		packageID, loaded := packageManager.IDBySharedPackage(packageName)
		if !loaded {
			packageID, loaded = packageManager.IDByPackage(packageName)
		}
		if !loaded {
			log.Warnln("[EBPF] %s_package not found at startup: %s; restart mihomo after the package is installed or its UID changes", mode, packageName)
			continue
		}
		if _, warned := warnedSharedUID[packageID]; warned {
			continue
		}
		sharedPackages, loaded := packageManager.PackagesByID(packageID)
		if !loaded || len(sharedPackages) < 2 {
			continue
		}
		warnedSharedUID[packageID] = struct{}{}
		log.Warnln("[EBPF] Android packages [%s] share UID %d; eBPF UID policy applies to all of them", strings.Join(sharedPackages, ", "), packageID)
	}
}

type androidUIDErrorHandler struct{}

func (androidUIDErrorHandler) NewError(ctx context.Context, err error) {
	log.Errorln("[EBPF] resolve Android UID policy: %s", err.Error())
}

func toTunUIDRanges(uidRanges []ECommon.UIDRange) []ranges.Range[uint32] {
	converted := make([]ranges.Range[uint32], 0, len(uidRanges))
	for _, uidRange := range uidRanges {
		converted = append(converted, ranges.New(uidRange.Start, uidRange.End))
	}
	return converted
}

func fromTunUIDRanges(uidRanges []ranges.Range[uint32]) []ECommon.UIDRange {
	converted := make([]ECommon.UIDRange, 0, len(uidRanges))
	for _, uidRange := range uidRanges {
		converted = append(converted, ECommon.UIDRange{Start: uidRange.Start, End: uidRange.End})
	}
	return converted
}
