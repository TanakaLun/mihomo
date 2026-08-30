//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"strings"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	LC "github.com/metacubex/mihomo/listener/config"

	E "github.com/metacubex/sing/common/exceptions"
)

const (
	ebpfModeLocal  = "local"
	ebpfModeShared = "shared"
	ebpfModeHybrid = "hybrid"

	dnsModeHijack        = "hijack"
	dnsModeRespectPolicy = "respect_policy"
	dnsModeRespectBypass = "respect_bypass"
	dnsModeOff           = "off"

	defaultTCPriority = 1
)

func normalizeMode(mode string) (string, bool, bool, error) {
	switch mode {
	case "", ebpfModeLocal:
		return ebpfModeLocal, true, false, nil
	case ebpfModeShared:
		return ebpfModeShared, false, true, nil
	case ebpfModeHybrid:
		return ebpfModeHybrid, true, true, nil
	default:
		return "", false, false, E.New("unknown eBPF mode: ", mode)
	}
}

func normalizeDNSMode(mode string) (string, error) {
	switch mode {
	case "", dnsModeHijack:
		return dnsModeHijack, nil
	case dnsModeRespectPolicy, dnsModeRespectBypass, dnsModeOff:
		return mode, nil
	default:
		return "", E.New("unknown eBPF dns_mode: ", mode)
	}
}

func toCommonDNSMode(mode string) ECommon.DNSMode {
	switch mode {
	case dnsModeRespectPolicy, dnsModeRespectBypass:
		return ECommon.DNSModeRespectPolicy
	case dnsModeOff:
		return ECommon.DNSModeOff
	default:
		return ECommon.DNSModeHijack
	}
}

func enabledByDefault(value *bool) bool {
	return value == nil || *value
}

func validateLocalOptions(enabled bool, options LC.EBPFLocal) error {
	if enabled {
		return nil
	}
	if options.DNSMode != "" {
		return E.New("local.dns_mode requires local or hybrid mode")
	}
	if options.IPv6 != nil {
		return E.New("local.ipv6 requires local or hybrid mode")
	}
	if options.BypassPrivateAddress != nil {
		return E.New("local.bypass_private_address requires local or hybrid mode")
	}
	if len(options.IncludeUID) > 0 || len(options.IncludeUIDRange) > 0 ||
		len(options.ExcludeUID) > 0 || len(options.ExcludeUIDRange) > 0 ||
		len(options.IncludeAndroidUser) > 0 || len(options.IncludePackage) > 0 ||
		len(options.ExcludePackage) > 0 {
		return E.New("local UID policy requires local or hybrid mode")
	}
	return nil
}

func validateAndroidUIDOptions(goos string, options LC.EBPFLocal) error {
	if !hasAndroidUIDOptions(options) {
		return nil
	}
	if goos != "android" {
		return E.New("include_android_user, include_package, and exclude_package are only supported on Android")
	}
	const maxAndroidUserID = (uint64(^uint32(0)-1) - (androidUserRange - 1)) / androidUserRange
	for _, userID := range options.IncludeAndroidUser {
		if userID < 0 || uint64(userID) > maxAndroidUserID {
			return E.New("invalid include_android_user: ", userID)
		}
	}
	return nil
}

func hasAndroidUIDOptions(options LC.EBPFLocal) bool {
	return len(options.IncludeAndroidUser) > 0 || len(options.IncludePackage) > 0 ||
		len(options.ExcludePackage) > 0
}

func parseUIDRanges(includeUID []uint32, includeUIDRange []string) ([]ECommon.UIDRange, error) {
	uidRanges := make([]ECommon.UIDRange, 0, len(includeUID)+len(includeUIDRange))
	for _, uid := range includeUID {
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uid, End: uid})
	}
	for _, text := range includeUIDRange {
		start, end, found := strings.Cut(text, ":")
		if !found {
			parsed, err := parseUint32(start)
			if err != nil {
				return nil, E.New("invalid UID range: ", text)
			}
			uidRanges = append(uidRanges, ECommon.UIDRange{Start: parsed, End: parsed})
			continue
		}
		startValue, err := parseUint32(start)
		if err != nil {
			return nil, E.New("invalid UID range: ", text)
		}
		endValue, err := parseUint32(end)
		if err != nil {
			return nil, E.New("invalid UID range: ", text)
		}
		if startValue > endValue {
			return nil, E.New("invalid UID range: ", text)
		}
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: startValue, End: endValue})
	}
	return uidRanges, nil
}

func parseUint32(text string) (uint32, error) {
	var value uint32
	for _, char := range text {
		if char < '0' || char > '9' {
			return 0, E.New("invalid number: ", text)
		}
		next := value*10 + uint32(char-'0')
		if next < value {
			return 0, E.New("number overflows: ", text)
		}
		value = next
	}
	return value, nil
}

func parseSharedMACAddresses(name string, values []string) ([]ECommon.MACAddress, error) {
	addresses := make([]ECommon.MACAddress, 0, len(values))
	for _, text := range values {
		var address ECommon.MACAddress
		parsed, err := parseMAC(text)
		if err != nil {
			return nil, E.New("invalid ", name, ": ", text)
		}
		copy(address[:], parsed)
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func parseMAC(text string) ([]byte, error) {
	parts := strings.Split(text, ":")
	if len(parts) != 6 {
		return nil, E.New("invalid MAC address")
	}
	address := make([]byte, 6)
	for index, part := range parts {
		if len(part) != 2 {
			return nil, E.New("invalid MAC address")
		}
		value, err := parseHexByte(part)
		if err != nil {
			return nil, err
		}
		address[index] = value
	}
	return address, nil
}

func parseHexByte(text string) (byte, error) {
	var value byte
	for _, char := range text {
		var digit byte
		switch {
		case char >= '0' && char <= '9':
			digit = byte(char - '0')
		case char >= 'a' && char <= 'f':
			digit = byte(char-'a') + 10
		case char >= 'A' && char <= 'F':
			digit = byte(char-'A') + 10
		default:
			return 0, E.New("invalid hex digit: ", string(char))
		}
		value = value<<4 | digit
	}
	return value, nil
}

func normalizeSharedOptions(options LC.EBPFShared) (LC.EBPFShared, error) {
	if len(options.Interface) == 0 {
		return LC.EBPFShared{}, E.New("shared.interface must not be empty")
	}
	seen := make(map[string]struct{}, len(options.Interface))
	interfaces := make([]string, 0, len(options.Interface))
	for _, interfaceName := range options.Interface {
		interfaceName = strings.TrimSpace(interfaceName)
		if interfaceName == "" {
			return LC.EBPFShared{}, E.New("shared.interface contains an empty interface name")
		}
		if interfaceName == "lo" {
			return LC.EBPFShared{}, E.New("shared.interface must not contain lo")
		}
		if _, loaded := seen[interfaceName]; loaded {
			continue
		}
		seen[interfaceName] = struct{}{}
		interfaces = append(interfaces, interfaceName)
	}
	options.Interface = interfaces
	return options, nil
}

func validateSharedOptions(enabled bool, options LC.EBPFShared) error {
	if enabled {
		return nil
	}
	if options.DNSMode != "" {
		return E.New("shared.dns_mode requires shared or hybrid mode")
	}
	if options.IPv6 != nil {
		return E.New("shared.ipv6 requires shared or hybrid mode")
	}
	if options.BypassPrivateAddress != nil {
		return E.New("shared.bypass_private_address requires shared or hybrid mode")
	}
	if len(options.Interface) > 0 {
		return E.New("shared.interface requires shared or hybrid mode")
	}
	if len(options.IncludeSourceCIDR) > 0 || len(options.ExcludeSourceCIDR) > 0 ||
		len(options.IncludeMACAddress) > 0 || len(options.ExcludeMACAddress) > 0 {
		return E.New("shared source policy requires shared or hybrid mode")
	}
	return nil
}
