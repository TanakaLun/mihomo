//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"net/netip"
	"slices"

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
	updated, err := i.refreshBypassCIDRsLocked()
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	if updated {
		i.logBypassCIDRUpdate()
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
	updated, err := i.refreshBypassCIDRsLocked()
	if err != nil {
		if backend := i.backendInstance(); backend != nil && !backend.IsClosed() {
			log.Errorln("[EBPF] refresh bypass_rule_set: %s", err.Error())
		}
		return
	}
	if updated {
		i.logBypassCIDRUpdate()
	}
}

func (i *Inbound) currentBypassCIDR() []netip.Prefix {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	return slices.Clone(i.bypassCIDR)
}

func (i *Inbound) refreshBypassCIDRsLocked() (bool, error) {
	prefixes := localInterfacePrefixes()
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
	backend := i.backendInstance()
	if backend == nil {
		return false, E.New("eBPF backend is not initialized")
	}
	updated, err := backend.UpdateBypassCIDR(prefixes)
	if err != nil {
		return false, err
	}
	i.bypassCIDR = prefixes
	// Publish the effective bypass CIDR set to the DNS fake-ip middleware so
	// domains whose real addresses fall inside it keep their real IP and the
	// kernel eBPF bypass can engage. Only publish when bypass_rule_set is used.
	if len(i.bypassRuleSet) > 0 {
		resolver.EBFPBypassIPSet.Store(backend.BypassIPSet())
	} else {
		resolver.EBFPBypassIPSet.Store(nil)
	}
	return updated, nil
}
