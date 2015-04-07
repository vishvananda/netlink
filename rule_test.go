package netlink

import (
	"net"
	"syscall"
	"testing"
)

// TODO:
// add test for FLOW && PRIORITY together
// add test for SuppressIfgroup && SuppressPrefixlen together
// add test for Goto
func TestRuleAddDel(t *testing.T) {
	srcIp, srcNet, err := net.ParseCIDR("172.16.0.1/16")
	if err != nil {
		t.Fatal(err)
	}
	srcNet.IP = srcIp

	dstIp, dstNet, err := net.ParseCIDR("172.16.1.1/24")
	if err != nil {
		t.Fatal(err)
	}
	dstNet.IP = dstIp

	rules_begin, err := RuleList(syscall.AF_INET)
	if err != nil {
		t.Fatal(err)
	}

	rule := &Rule{
		Table:    syscall.RT_TABLE_MAIN,
		Src:      srcNet,
		Dst:      dstNet,
		Priority: 5,
		OifName:  "lo",
		IifName:  "lo",
		FlagMask: RULE_TABLE_MASK |
			RULE_IIFNAME_MASK |
			RULE_PRIORITY_MASK |
			RULE_OIFNAME_MASK,
	}
	if err := RuleAdd(rule); err != nil {
		t.Fatal(err)
	}

	rules, err := RuleList(syscall.AF_INET)
	if err != nil {
		t.Fatal(err)
	}

	if len(rules) != len(rules_begin)+1 {
		t.Fatal("Rule not added properly")
	}

	// find this rule
	var found bool
	for i := range rules {
		if rules[i].Table == rule.Table &&
			rules[i].Src != nil && rules[i].Src.String() == srcNet.String() &&
			rules[i].Dst != nil && rules[i].Dst.String() == dstNet.String() &&
			rules[i].OifName == rule.OifName &&
			rules[i].Priority == rule.Priority &&
			rules[i].IifName == rule.IifName {
			found = true
		}
	}

	if err := RuleDel(rule); err != nil {
		t.Fatal(err)
	}

	rules_end, err := RuleList(syscall.AF_INET)
	if err != nil {
		t.Fatal(err)
	}

	if len(rules_end) != len(rules_begin) {
		t.Fatal("Rule not removed properly")
	}

	if !found {
		t.Fatal("Rule has diffrent options than one added")
	}
}
