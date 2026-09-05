//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/component/resolver"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"

	"go4.org/netipx"
)

type toIpCidr interface {
	ToIpCidr() *netipx.IPSet
}

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.bypassRuleSetStarted {
		return nil
	}
	rp, ok := i.tunnel.(P.Tunnel)
	if !ok {
		return E.New("tunnel does not expose rule providers")
	}
	i.bypassRuleSetCallback = rp.RuleUpdateCallback().Register(i.updateBypassRuleSet)
	i.bypassRuleSetStarted = true
	err := i.refreshBypassCIDRsLocked()
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
	if !i.bypassRuleSetStarted {
		return
	}
	if i.bypassRuleSetCallback != nil {
		_ = i.bypassRuleSetCallback.Close()
		i.bypassRuleSetCallback = nil
	}
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(P.RuleProvider) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	if err := i.refreshBypassCIDRsLocked(); err != nil {
		if backend := i.tcBackend(); backend != nil {
			log.Errorln("[EBPF] refresh TC eBPF bypass_rule_set; keeping previous policy: %s", err.Error())
		}
	}
}

func (i *Inbound) refreshBypassCIDRsLocked() error {
	var prefixes []netip.Prefix
	for _, ruleSet := range i.bypassRuleSet {
		strategy := ruleSet.Strategy()
		ipCidrStrategy, ok := strategy.(toIpCidr)
		if !ok {
			continue
		}
		ipSet := ipCidrStrategy.ToIpCidr()
		if ipSet == nil {
			continue
		}
		prefixes = append(prefixes, ipSet.Prefixes()...)
	}
	if conflicts := i.fakeIPBypassConflictCount(prefixes); conflicts > 0 {
		log.Warnln("[EBPF] FakeIP force interception overrides bypass_rule_set CIDRs: overlaps=%d", conflicts)
	}
	policy, err := ECommon.CompileBypassCIDRPolicy(prefixes)
	if err != nil {
		return err
	}
	i.bypassRuleSetPolicy = policy
	i.bypassCIDR = policy.Prefixes()
	if backend := i.tcBackend(); backend != nil {
		if _, err = backend.UpdateCompiledBypassCIDR(policy); err != nil {
			return err
		}
	}
	if backend := i.cgroupBackendInstance(); backend != nil {
		if _, err = backend.UpdateCompiledBypassCIDR(policy); err != nil {
			return err
		}
	}
	if i.sharedRewrite != nil {
		if backend := i.sharedRewrite.sharedBackendInstance(); backend != nil {
			if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
				ipv4Count, ipv6Count := cgroupBackend.BypassCIDRCount()
				if err = backend.SetBypassCIDRState(ipv4Count, ipv6Count); err != nil {
					return err
				}
			} else if _, err = backend.UpdateCompiledBypassCIDR(policy); err != nil {
				return err
			}
		}
	}
	// Publish the effective bypass CIDR set to the DNS fake-ip middleware so
	// domains whose real addresses fall inside it keep their real IP and the
	// kernel eBPF bypass can engage.
	if len(i.bypassRuleSet) > 0 {
		var builder netipx.IPSetBuilder
		for _, prefix := range i.bypassCIDR {
			builder.AddPrefix(prefix)
		}
		if bypassSet, buildErr := builder.IPSet(); buildErr == nil {
			resolver.EBFPBypassIPSet.Store(bypassSet)
		}
	} else {
		resolver.EBFPBypassIPSet.Store(nil)
	}
	return nil
}
