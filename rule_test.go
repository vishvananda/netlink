//go:build linux
// +build linux

package netlink

import (
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRuleAddDel(t *testing.T) {
	skipUnlessRoot(t)
	t.Cleanup(setUpNetlinkTest(t))

	srcNet := &net.IPNet{IP: net.IPv4(172, 16, 0, 1), Mask: net.CIDRMask(16, 32)}
	dstNet := &net.IPNet{IP: net.IPv4(172, 16, 1, 1), Mask: net.CIDRMask(24, 32)}

	rulesBegin, err := RuleList(FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	rule := NewRule()
	rule.Family = FAMILY_V4
	rule.Table = unix.RT_TABLE_MAIN
	rule.Src = srcNet
	rule.Dst = dstNet
	rule.Priority = 5
	rule.OifName = "lo"
	rule.IifName = "lo"
	rule.Invert = true
	rule.Tos = 0x10
	rule.Dport = NewRulePortRange(80, 80)
	rule.Sport = NewRulePortRange(1000, 1024)
	rule.IPProto = unix.IPPROTO_UDP
	rule.UIDRange = NewRuleUIDRange(100, 100)
	rule.Protocol = unix.RTPROT_KERNEL
	if err := RuleAdd(rule); err != nil {
		t.Fatal(err)
	}

	rules, err := RuleList(FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	if len(rules) != len(rulesBegin)+1 {
		t.Fatal("Rule not added properly")
	}

	// find this rule
	found := ruleExists(rules, *rule)
	if !found {
		t.Fatal("Rule has diffrent options than one added")
	}

	if err := RuleDel(rule); err != nil {
		t.Fatal(err)
	}

	rulesEnd, err := RuleList(FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	if len(rulesEnd) != len(rulesBegin) {
		t.Fatal("Rule not removed properly")
	}
}

func TestRuleListFiltered(t *testing.T) {
	skipUnlessRoot(t)

	t.Run("IPv4", testRuleListFilteredIPv4)
	t.Run("IPv6", testRuleListFilteredIPv6)
}

func testRuleListFilteredIPv4(t *testing.T) {
	srcNet := &net.IPNet{IP: net.IPv4(172, 16, 0, 1), Mask: net.CIDRMask(16, 32)}
	dstNet := &net.IPNet{IP: net.IPv4(172, 16, 1, 1), Mask: net.CIDRMask(24, 32)}
	runRuleListFiltered(t, FAMILY_V4, srcNet, dstNet)
}

func testRuleListFilteredIPv6(t *testing.T) {
	ip1 := net.ParseIP("fd56:6b58:db28:2913::")
	ip2 := net.ParseIP("fde9:379f:3b35:6635::")

	srcNet := &net.IPNet{IP: ip1, Mask: net.CIDRMask(64, 128)}
	dstNet := &net.IPNet{IP: ip2, Mask: net.CIDRMask(96, 128)}
	runRuleListFiltered(t, FAMILY_V6, srcNet, dstNet)
}

func runRuleListFiltered(t *testing.T, family int, srcNet, dstNet *net.IPNet) {
	tests := []struct {
		name       string
		ruleFilter *Rule
		filterMask uint64
		preRun     func() *Rule // Creates sample rule harness
		postRun    func(*Rule)  // Deletes sample rule harness
		setupWant  func(*Rule) ([]Rule, bool)
	}{
		{
			name:       "returns all rules",
			ruleFilter: nil,
			filterMask: 0,
			preRun:     func() *Rule { return nil },
			postRun:    func(r *Rule) {},
			setupWant: func(_ *Rule) ([]Rule, bool) {
				rules, err := RuleList(family)
				if err != nil {
					t.Fatalf("Failed to list rules: %v", err)
				}
				return rules, false
			},
		},
		{
			name:       "returns one rule filtered by Src",
			ruleFilter: &Rule{Src: srcNet},
			filterMask: RT_FILTER_SRC,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Family = family
				r.Table = 1
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns one rule filtered by Dst",
			ruleFilter: &Rule{Dst: dstNet},
			filterMask: RT_FILTER_DST,
			preRun: func() *Rule {
				r := NewRule()
				r.Dst = dstNet
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Family = family
				r.Table = 1
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns two rules filtered by Dst",
			ruleFilter: &Rule{Dst: dstNet},
			filterMask: RT_FILTER_DST,
			preRun: func() *Rule {
				r := NewRule()
				r.Dst = dstNet
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Family = family
				r.Table = 1
				RuleAdd(r)

				rc := *r // Create almost identical copy
				rc.Src = srcNet
				RuleAdd(&rc)

				return r
			},
			postRun: func(r *Rule) {
				RuleDel(r)

				rc := *r // Delete the almost identical copy
				rc.Src = srcNet
				RuleDel(&rc)
			},
			setupWant: func(r *Rule) ([]Rule, bool) {
				rs := []Rule{}
				rs = append(rs, *r)

				rc := *r // Append the almost identical copy
				rc.Src = srcNet
				rs = append(rs, rc)

				return rs, false
			},
		},
		{
			name:       "returns one rule filtered by Src when two rules exist",
			ruleFilter: &Rule{Src: srcNet},
			filterMask: RT_FILTER_SRC,
			preRun: func() *Rule {
				r := NewRule()
				r.Dst = dstNet
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Family = family
				r.Table = 1
				RuleAdd(r)

				rc := *r // Create almost identical copy
				rc.Src = srcNet
				RuleAdd(&rc)

				return r
			},
			postRun: func(r *Rule) {
				RuleDel(r)

				rc := *r // Delete the almost identical copy
				rc.Src = srcNet
				RuleDel(&rc)
			},
			setupWant: func(r *Rule) ([]Rule, bool) {
				rs := []Rule{}
				// Do not append `r`

				rc := *r // Append the almost identical copy
				rc.Src = srcNet
				rs = append(rs, rc)

				return rs, false
			},
		},
		{
			name:       "returns one rule filtered by Priority(0) and Table",
			ruleFilter: &Rule{Priority: 0, Table: 1},
			filterMask: RT_FILTER_PRIORITY | RT_FILTER_TABLE,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 0
				r.Family = family
				r.Table = 1
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) {
				RuleDel(r)
			},
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns one rule filtered by Priority preceding main-table rule",
			ruleFilter: &Rule{Priority: 32765},
			filterMask: RT_FILTER_PRIORITY,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Family = family
				r.Table = 1
				RuleAdd(r)

				r.Priority = 32765 // Set priority for assertion
				return r
			},
			postRun: func(r *Rule) {
				RuleDel(r)
			},
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules with specific priority",
			ruleFilter: &Rule{Priority: 5},
			filterMask: RT_FILTER_PRIORITY,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 5
				r.Family = family
				r.Table = 1
				RuleAdd(r)

				for i := 2; i < 5; i++ {
					rc := *r // Create almost identical copy
					rc.Table = i
					RuleAdd(&rc)
				}

				return r
			},
			postRun: func(r *Rule) {
				RuleDel(r)

				for i := 2; i < 5; i++ {
					rc := *r // Delete the almost identical copy
					rc.Table = -1
					RuleDel(&rc)
				}
			},
			setupWant: func(r *Rule) ([]Rule, bool) {
				rs := []Rule{}
				rs = append(rs, *r)

				for i := 2; i < 5; i++ {
					rc := *r // Append the almost identical copy
					rc.Table = i
					rs = append(rs, rc)
				}

				return rs, false
			},
		},
		{
			name:       "returns rules filtered by Table",
			ruleFilter: &Rule{Table: 199},
			filterMask: RT_FILTER_TABLE,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1 // Must add priority otherwise it's auto-assigned
				r.Family = family
				r.Table = 199
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by Mask",
			ruleFilter: &Rule{Mask: &[]uint32{0x5}[0]},
			filterMask: RT_FILTER_MASK,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1 // Must add priority and table otherwise it's auto-assigned
				r.Family = family
				r.Table = 1
				r.Mask = &[]uint32{0x5}[0]
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by Mark",
			ruleFilter: &Rule{Mark: 0xbb},
			filterMask: RT_FILTER_MARK,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1 // Must add priority, table, mask otherwise it's auto-assigned
				r.Family = family
				r.Table = 1
				r.Mask = &[]uint32{0xff}[0]
				r.Mark = 0xbb
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by fwmark 0",
			ruleFilter: &Rule{Mark: 0, Mask: nil, Table: 100},
			filterMask: RT_FILTER_MARK | RT_FILTER_MASK | RT_FILTER_TABLE,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1
				r.Family = family
				r.Table = 100
				r.Mark = 0
				r.Mask = nil
				if err := RuleAdd(r); err != nil {
					t.Fatal(err)
				}
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by fwmark 0/0xFFFFFFFF",
			ruleFilter: &Rule{Mark: 0, Mask: &[]uint32{0xFFFFFFFF}[0], Table: 100},
			filterMask: RT_FILTER_MARK | RT_FILTER_MASK | RT_FILTER_TABLE,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1
				r.Family = family
				r.Table = 100
				r.Mark = 0
				r.Mask = &[]uint32{0xFFFFFFFF}[0]
				if err := RuleAdd(r); err != nil {
					t.Fatal(err)
				}
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by fwmark 0x1234/0",
			ruleFilter: &Rule{Mark: 0x1234, Mask: &[]uint32{0}[0], Table: 100},
			filterMask: RT_FILTER_MARK | RT_FILTER_MASK | RT_FILTER_TABLE,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1
				r.Family = family
				r.Table = 100
				r.Mark = 0x1234
				r.Mask = &[]uint32{0}[0]
				if err := RuleAdd(r); err != nil {
					t.Fatal(err)
				}
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by fwmark 0/0xFFFFFFFF",
			ruleFilter: &Rule{Mark: 0, Mask: &[]uint32{0xFFFFFFFF}[0], Table: 100},
			filterMask: RT_FILTER_MARK | RT_FILTER_MASK | RT_FILTER_TABLE,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1
				r.Family = family
				r.Table = 100
				r.Mark = 0
				r.Mask = &[]uint32{0xFFFFFFFF}[0]
				if err := RuleAdd(r); err != nil {
					t.Fatal(err)
				}
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by fwmark 0xFFFFFFFF",
			ruleFilter: &Rule{Mark: 0xFFFFFFFF, Mask: &[]uint32{0xFFFFFFFF}[0], Table: 100},
			filterMask: RT_FILTER_MARK | RT_FILTER_MASK | RT_FILTER_TABLE,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1
				r.Family = family
				r.Table = 100
				r.Mark = 0xFFFFFFFF
				r.Mask = nil
				if err := RuleAdd(r); err != nil {
					t.Fatal(err)
				}
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by fwmark 0x1234",
			ruleFilter: &Rule{Mark: 0x1234, Mask: &[]uint32{0xFFFFFFFF}[0], Table: 100},
			filterMask: RT_FILTER_MARK | RT_FILTER_MASK | RT_FILTER_TABLE,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1
				r.Family = family
				r.Table = 100
				r.Mark = 0x1234
				r.Mask = nil
				if err := RuleAdd(r); err != nil {
					t.Fatal(err)
				}
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by fwmark 0x12345678",
			ruleFilter: &Rule{Mark: 0x12345678, Mask: &[]uint32{0xFFFFFFFF}[0], Table: 100},
			filterMask: RT_FILTER_MARK | RT_FILTER_MASK | RT_FILTER_TABLE,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1
				r.Family = family
				r.Table = 100
				r.Mark = 0x12345678
				r.Mask = nil
				if err := RuleAdd(r); err != nil {
					t.Fatal(err)
				}
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by fwmark 0xFFFFFFFF/0",
			ruleFilter: &Rule{Mark: 0xFFFFFFFF, Mask: &[]uint32{0}[0], Table: 100},
			filterMask: RT_FILTER_MARK | RT_FILTER_MASK | RT_FILTER_TABLE,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1
				r.Family = family
				r.Table = 100
				r.Mark = 0xFFFFFFFF
				r.Mask = &[]uint32{0}[0]
				if err := RuleAdd(r); err != nil {
					t.Fatal(err)
				}
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by fwmark 0xFFFFFFFF/0xFFFFFFFF",
			ruleFilter: &Rule{Mark: 0xFFFFFFFF, Mask: &[]uint32{0xFFFFFFFF}[0], Table: 100},
			filterMask: RT_FILTER_MARK | RT_FILTER_MASK | RT_FILTER_TABLE,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1
				r.Family = family
				r.Table = 100
				r.Mark = 0xFFFFFFFF
				r.Mask = &[]uint32{0xFFFFFFFF}[0]
				if err := RuleAdd(r); err != nil {
					t.Fatal(err)
				}
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
		{
			name:       "returns rules filtered by Tos",
			ruleFilter: &Rule{Tos: 12},
			filterMask: RT_FILTER_TOS,
			preRun: func() *Rule {
				r := NewRule()
				r.Src = srcNet
				r.Priority = 1 // Must add priority, table, mask otherwise it's auto-assigned
				r.Family = family
				r.Table = 12
				r.Tos = 12 // Tos must equal table
				RuleAdd(r)
				return r
			},
			postRun: func(r *Rule) { RuleDel(r) },
			setupWant: func(r *Rule) ([]Rule, bool) {
				return []Rule{*r}, false
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(setUpNetlinkTest(t))
			rule := tt.preRun()
			wantRules, wantErr := tt.setupWant(rule)

			rules, err := RuleListFiltered(family, tt.ruleFilter, tt.filterMask)
			for i := 0; i < len(wantRules); i++ {
				if len(wantRules) == len(rules) {
					break
				}
				time.Sleep(1 * time.Second) // wait rule take effect
				rules, err = RuleListFiltered(family, tt.ruleFilter, tt.filterMask)
			}
			tt.postRun(rule)

			if len(wantRules) != len(rules) {
				t.Errorf("Expected len: %d, got: %d", len(wantRules), len(rules))
			} else {
				for i := range wantRules {
					if !wantRules[i].Equal(rules[i]) {
						t.Errorf("Rules mismatch, want %v, got %v", wantRules[i], rules[i])
					}
				}
			}

			if (err != nil) != wantErr {
				t.Errorf("Error expectation not met, want %v, got %v", (err != nil), wantErr)
			}
		})
	}
}

func TestRuleString(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		r Rule
		s string
	}{
		"empty rule": {
			s: "ip rule 0: from all to all table 0 ",
		},
		"rule with src and dst equivalent to <nil>": {
			r: Rule{
				Priority: 100,
				Src:      &net.IPNet{IP: net.IPv4(10, 0, 0, 0)},
				Dst:      &net.IPNet{IP: net.IPv4(20, 0, 0, 0)},
				Table:    99,
			},
			s: "ip rule 100: from all to all table 99 ",
		},
		"rule with src and dst": {
			r: Rule{
				Priority: 100,
				Src:      &net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)},
				Dst:      &net.IPNet{IP: net.IPv4(20, 0, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)},
				Table:    99,
			},
			s: "ip rule 100: from 10.0.0.0/24 to 20.0.0.0/24 table 99 ",
		},
		"rule with type": {
			r: Rule{
				Priority: 101,
				Type:     unix.RTN_UNREACHABLE,
			},
			s: "ip rule 101: from all to all table 0 unreachable",
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := testCase.r.String()

			if s != testCase.s {
				t.Errorf("expected %q but got %q", testCase.s, s)
			}
		})
	}
}

func ruleExists(rules []Rule, rule Rule) bool {
	for i := range rules {
		if rules[i].Equal(rule) {
			return true
		}
	}

	return false
}

func TestRuleEqual(t *testing.T) {
	cases := []Rule{
		{Priority: 1000},
		{Family: FAMILY_V6},
		{Table: 10},
		{Mark: 1},
		{Mask: &[]uint32{0x1}[0]},
		{Tos: 1},
		{TunID: 3},
		{Goto: 10},
		{Src: &net.IPNet{IP: net.IPv4(172, 16, 0, 1), Mask: net.CIDRMask(16, 32)}},
		{Dst: &net.IPNet{IP: net.IPv4(172, 16, 1, 1), Mask: net.CIDRMask(24, 32)}},
		{Flow: 3},
		{IifName: "IifName"},
		{OifName: "OifName"},
		{SuppressIfgroup: 7},
		{SuppressPrefixlen: 16},
		{Invert: true},
		{Dport: &RulePortRange{Start: 10, End: 20}},
		{Sport: &RulePortRange{Start: 1, End: 2}},
		{IPProto: unix.IPPROTO_TCP},
		{UIDRange: &RuleUIDRange{Start: 3, End: 5}},
		{Protocol: FAMILY_V6},
		{Type: unix.RTN_UNREACHABLE},
	}
	for i1 := range cases {
		for i2 := range cases {
			got := cases[i1].Equal(cases[i2])
			expected := i1 == i2
			if got != expected {
				t.Errorf("Equal(%q,%q) == %s but expected %s",
					cases[i1], cases[i2],
					strconv.FormatBool(got),
					strconv.FormatBool(expected))
			}
		}
	}
}

func TestRuleEqualMaskMark(t *testing.T) {
	a := Rule{Mark: 1, Mask: nil}
	b := Rule{Mark: 1, Mask: &[]uint32{0xFFFFFFFF}[0]}
	if !a.Equal(b) || !b.Equal(a) {
		t.Errorf("Rules are expected to be equal")
	}

	b = Rule{Mark: 2, Mask: &[]uint32{0xFFFFFFFF}[0]}
	if a.Equal(b) || b.Equal(a) {
		t.Errorf("Rules are not expected to be equal")
	}

	a = Rule{Mark: 0, Mask: nil}
	b = Rule{Mark: 0, Mask: &[]uint32{0xFFFFFFFF}[0]}
	if a.Equal(b) || b.Equal(a) {
		t.Errorf("Rules are not expected to be equal")
	}
}

func TestRulePortRangeEqual(t *testing.T) {
	cases := []RulePortRange{
		{Start: 10, End: 10},
		{Start: 10, End: 22},
		{Start: 11, End: 22},
	}
	for i1 := range cases {
		for i2 := range cases {
			got := cases[i1].Equal(cases[i2])
			expected := i1 == i2
			if got != expected {
				t.Errorf("Equal(%q,%q) == %s but expected %s",
					cases[i1], cases[i2],
					strconv.FormatBool(got),
					strconv.FormatBool(expected))
			}
		}
	}
}

func TestRuleUIDRangeEqual(t *testing.T) {
	cases := []RuleUIDRange{
		{Start: 10, End: 10},
		{Start: 10, End: 22},
		{Start: 11, End: 22},
	}
	for i1 := range cases {
		for i2 := range cases {
			got := cases[i1].Equal(cases[i2])
			expected := i1 == i2
			if got != expected {
				t.Errorf("Equal(%q,%q) == %s but expected %s",
					cases[i1], cases[i2],
					strconv.FormatBool(got),
					strconv.FormatBool(expected))
			}
		}
	}
}
