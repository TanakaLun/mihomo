//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"io"
	"net/netip"

	ECommon "github.com/CHIZI-0618/sing-ebpf"
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
	if i.localBypassRuleSetStarted && i.sharedBypassRuleSetStarted {
		return nil
	}
	rp, ok := i.tunnel.(P.Tunnel)
	if !ok {
		return E.New("tunnel does not expose rule providers")
	}
	register := func(started *bool, callback *io.Closer) {
		if *started {
			return
		}
		*started = true
		*callback = rp.RuleUpdateCallback().Register(i.updateBypassRuleSet)
	}
	register(&i.localBypassRuleSetStarted, &i.localBypassRuleSetCB)
	register(&i.sharedBypassRuleSetStarted, &i.sharedBypassRuleSetCB)
	if err := i.refreshBypassCIDRsLocked(); err != nil {
		// Roll the registrations back on failure so a later retry does not
		// leave the inbound marked started with callbacks still registered.
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
	for _, current := range []struct {
		started  *bool
		callback *io.Closer
	}{
		{&i.localBypassRuleSetStarted, &i.localBypassRuleSetCB},
		{&i.sharedBypassRuleSetStarted, &i.sharedBypassRuleSetCB},
	} {
		if *current.callback != nil {
			_ = (*current.callback).Close()
			*current.callback = nil
		}
		*current.started = false
	}
}

func (i *Inbound) updateBypassRuleSet(P.RuleProvider) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.localBypassRuleSetStarted && !i.sharedBypassRuleSetStarted {
		return
	}
	if err := i.refreshBypassCIDRsLocked(); err != nil {
		log.Errorln("[EBPF] refresh eBPF bypass_rule_set; keeping previous policy: %s", err.Error())
		i.bypassRuleSetNeedsRetry = true
		i.notifyTCInterfaceUpdate()
		return
	}
	i.bypassRuleSetNeedsRetry = false
}

func collectBypassPrefixes(ruleSets []P.RuleProvider) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, ruleSet := range ruleSets {
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
	return prefixes
}

func (i *Inbound) refreshBypassCIDRsLocked() error {
	localPrefixes := collectBypassPrefixes(i.localBypassRuleSet)
	sharedPrefixes := collectBypassPrefixes(i.sharedBypassRuleSet)
	allPrefixes := make([]netip.Prefix, 0, len(localPrefixes)+len(sharedPrefixes))
	allPrefixes = append(allPrefixes, localPrefixes...)
	allPrefixes = append(allPrefixes, sharedPrefixes...)
	if conflicts := i.fakeIPBypassConflictCount(allPrefixes); conflicts > 0 {
		log.Warnln("[EBPF] FakeIP force interception overrides bypass_rule_set CIDRs: overlaps=%d", conflicts)
	}
	i.bypassCIDR = allPrefixes
	decisions := func(prefixes []netip.Prefix) []ECommon.CIDRDecision {
		decisions := make([]ECommon.CIDRDecision, 0, len(prefixes))
		for _, prefix := range prefixes {
			decisions = append(decisions, ECommon.CIDRDecision{Prefix: prefix, Action: ECommon.DecisionPass})
		}
		return decisions
	}
	localDecisions := decisions(localPrefixes)
	sharedDecisions := decisions(sharedPrefixes)
	if backend := i.tcBackend(); backend != nil {
		if i.localTCEnabled() {
			if _, err := backend.UpdateLocalDestinationDecisions(localDecisions); err != nil {
				return err
			}
		}
		if i.sharedSocketAssignEnabled() {
			if _, err := backend.UpdateSharedDestinationDecisions(sharedDecisions); err != nil {
				return err
			}
		}
	}
	if backend := i.cgroupBackendInstance(); backend != nil {
		if _, err := backend.UpdateDestinationDecisions(localDecisions); err != nil {
			return err
		}
	}
	if i.sharedRewrite != nil {
		if backend := i.sharedRewrite.sharedBackendInstance(); backend != nil {
			if _, err := backend.UpdateDestinationDecisions(sharedDecisions); err != nil {
				return err
			}
		}
	}
	// Publish the effective bypass CIDR set to the DNS fake-ip middleware so
	// domains whose real addresses fall inside it keep their real IP and the
	// kernel eBPF bypass can engage.
	if len(i.bypassCIDR) > 0 {
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

type bypassCIDRBackendVersion struct {
	version uint64
	known   bool
}

// retryBypassRuleSetIfNeededLocked retries a previously failed bypass
// rule-set refresh on the scheduler's next round.
func (i *Inbound) retryBypassRuleSetIfNeededLocked() tcSharedRewriteOutcome {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.localBypassRuleSetStarted && !i.sharedBypassRuleSetStarted {
		return tcSharedRewriteSettled
	}
	if i.bypassRuleSetBackendRequiresRebuildLocked() {
		i.bypassRuleSetNeedsRetry = false
		return tcSharedRewriteUnrecoverable
	}
	if !i.bypassRuleSetNeedsRetry {
		return tcSharedRewriteSettled
	}
	i.bypassRuleSetRetryCount++
	if err := i.refreshBypassCIDRsLocked(); err != nil {
		log.Errorln("[EBPF] retry eBPF bypass_rule_set refresh: %s", err.Error())
		return tcSharedRewriteRecoverable
	}
	i.bypassRuleSetNeedsRetry = false
	return tcSharedRewriteSettled
}

func (i *Inbound) bypassRuleSetBackendRequiresRebuildLocked() bool {
	if backend := i.tcBackend(); backend != nil && backend.RequiresRebuild() {
		return true
	}
	if backend := i.cgroupBackendInstance(); backend != nil && backend.RequiresRebuild() {
		return true
	}
	if shared := i.sharedRewriteInstance(); shared != nil {
		if backend := shared.sharedBackendInstance(); backend != nil && backend.RequiresRebuild() {
			return true
		}
	}
	return false
}
