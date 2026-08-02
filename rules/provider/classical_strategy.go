package provider

import (
	"fmt"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules/common"

	"go4.org/netipx"
)

type classicalStrategy struct {
	rules []C.Rule
	count int
	parse common.ParseRuleFunc
}

func (c *classicalStrategy) Behavior() P.RuleBehavior {
	return P.Classical
}

func (c *classicalStrategy) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	for _, rule := range c.rules {
		if m, _ := rule.Match(metadata, helper); m {
			return true
		}
	}

	return false
}

func (c *classicalStrategy) Count() int {
	return c.count
}

func (c *classicalStrategy) Reset() {
	c.rules = nil
	c.count = 0
}

func (c *classicalStrategy) Insert(rule string) {
	r, err := c.payloadToRule(rule)
	if err != nil {
		log.Warnln("parse classical rule [%s] error: %s", rule, err.Error())
	} else {
		c.rules = append(c.rules, r)
		c.count++
	}
}

func (c *classicalStrategy) payloadToRule(rule string) (C.Rule, error) {
	tp, payload, target, params := common.ParseRulePayload(rule, false)
	switch tp {
	case "MATCH", "RULE-SET", "SUB-RULE":
		return nil, fmt.Errorf("unsupported rule type on classical rule-set: %s", tp)
	}
	return c.parse(tp, payload, target, params, nil)
}

func (c *classicalStrategy) FinishInsert() {}

// ToIpCidr extracts the destination IP-CIDR rules of a classical rule-set into
// an IPSet, matching sing-box's ExtractIPSet behavior for the eBPF inbound
// bypass_rule_set.
func (c *classicalStrategy) ToIpCidr() *netipx.IPSet {
	var builder netipx.IPSetBuilder
	for _, rule := range c.rules {
		if rule.RuleType() != C.IPCIDR {
			continue
		}
		if prefix, err := netip.ParsePrefix(rule.Payload()); err == nil {
			builder.AddPrefix(prefix)
		}
	}
	set, _ := builder.IPSet()
	return set
}

func NewClassicalStrategy(parse common.ParseRuleFunc) *classicalStrategy {
	return &classicalStrategy{rules: []C.Rule{}, parse: parse}
}
