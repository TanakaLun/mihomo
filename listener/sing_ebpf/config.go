//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	LC "github.com/metacubex/mihomo/listener/config"

	E "github.com/metacubex/sing/common/exceptions"
)

const (
	androidTetheringDNSUID = 1052
	dnsModeHijack          = "hijack"
	dnsModeOff             = "off"
)

var defaultRedirectIPv4Prefix = netip.MustParsePrefix("127.128.0.0/9")

func normalizeDNSMode(mode string) (string, error) {
	switch mode {
	case "", dnsModeHijack:
		return dnsModeHijack, nil
	case dnsModeOff:
		return dnsModeOff, nil
	default:
		return "", E.New("unknown eBPF dns_mode: ", mode)
	}
}

func normalizeCgroupMapCapacity(options LC.EBPFMapCapacity) (ECommon.CgroupMapCapacity, error) {
	capacity := ECommon.DefaultCgroupMapCapacity()
	var err error
	capacity.TCPRedirect, err = normalizeMapCapacityValue("map_capacity.tcp_redirect", options.TCPRedirect, capacity.TCPRedirect)
	if err != nil {
		return ECommon.CgroupMapCapacity{}, err
	}
	capacity.UDPRedirect, err = normalizeMapCapacityValue("map_capacity.udp_redirect", options.UDPRedirect, capacity.UDPRedirect)
	if err != nil {
		return ECommon.CgroupMapCapacity{}, err
	}
	capacity.SocketBypass, err = normalizeMapCapacityValue("map_capacity.socket_bypass", options.SocketBypass, capacity.SocketBypass)
	if err != nil {
		return ECommon.CgroupMapCapacity{}, err
	}
	return capacity, nil
}

func normalizeMapCapacityValue(name string, configured uint32, defaultValue uint32) (uint32, error) {
	if configured == 0 {
		return defaultValue, nil
	}
	if configured > ECommon.MaxConfigurableMapCapacity {
		return 0, E.New(name, " must be between 1 and ", ECommon.MaxConfigurableMapCapacity)
	}
	return configured, nil
}

func normalizeCgroupPath(cgroupPath string) (string, error) {
	if cgroupPath == "" {
		return "", nil
	}
	if !filepath.IsAbs(cgroupPath) {
		return "", E.New("eBPF cgroup_path must be absolute")
	}
	return filepath.Clean(cgroupPath), nil
}

func normalizeRedirectAddresses(addresses []netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	if len(addresses) == 0 {
		return defaultRedirectIPv4Prefix, netip.Prefix{}, nil
	}
	var ipv4Prefix netip.Prefix
	var ipv6Prefix netip.Prefix
	for _, address := range addresses {
		if !address.IsValid() {
			return netip.Prefix{}, netip.Prefix{}, E.New("invalid eBPF redirect address")
		}
		address = address.Masked()
		if err := ECommon.ValidateRedirectPrefix(address); err != nil {
			return netip.Prefix{}, netip.Prefix{}, err
		}
		switch {
		case address.Addr().Is4():
			if ipv4Prefix.IsValid() {
				return netip.Prefix{}, netip.Prefix{}, E.New("duplicate IPv4 eBPF redirect address")
			}
			ipv4Prefix = address
		case address.Addr().Is6() && !address.Addr().Is4In6():
			if ipv6Prefix.IsValid() {
				return netip.Prefix{}, netip.Prefix{}, E.New("duplicate IPv6 eBPF redirect address")
			}
			ipv6Prefix = address
		default:
			return netip.Prefix{}, netip.Prefix{}, E.New("invalid eBPF redirect address family: ", address)
		}
	}
	return ipv4Prefix, ipv6Prefix, nil
}

func parseUIDRanges(uidList []uint32, rangeList []string) ([]ECommon.UIDRange, error) {
	uidRanges := make([]ECommon.UIDRange, 0, len(uidList)+len(rangeList))
	for _, uid := range uidList {
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uid, End: uid})
	}
	for _, uidRange := range rangeList {
		separator := strings.IndexByte(uidRange, ':')
		if separator < 0 {
			return nil, E.New("missing ':' in range: ", uidRange)
		}
		if separator == 0 {
			return nil, E.New("missing range start: ", uidRange)
		}
		if separator == len(uidRange)-1 {
			return nil, E.New("missing range end: ", uidRange)
		}
		start, err := strconv.ParseUint(uidRange[:separator], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err := strconv.ParseUint(uidRange[separator+1:], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		if start > end {
			return nil, E.New("range start is greater than range end: ", uidRange)
		}
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uint32(start), End: uint32(end)})
	}
	return uidRanges, nil
}

func platformExcludedUIDRanges(goos string) []ECommon.UIDRange {
	if goos != "android" {
		return nil
	}
	return []ECommon.UIDRange{{Start: androidTetheringDNSUID, End: androidTetheringDNSUID}}
}
