package netlink

import "net"

// Flag mask for rule options. Rule.FlagMask must be set to on for option to work.
const (
	RULE_PRIORITY_MASK = 1 << (1 + iota)
	RULE_FWMARK_MASK
	RULE_FWMASK_MASK
	RULE_FLOW_MASK
	RULE_TABLE_MASK
	RULE_SUPPRESS_PREFIXLEN_MASK
	RULE_SUPPRESS_IFGROUP_MASK
	RULE_IIFNAME_MASK
	RULE_OIFNAME_MASK
	RULE_GOTO_MASK
)

// Rule represents a netlink rule.
type Rule struct {
	Family            int
	Tos               int
	Scope             int
	Table             int
	Protocol          int
	Type              int
	Priority          int
	Mark              int
	Mask              int
	Goto              int
	Src               *net.IPNet
	Dst               *net.IPNet
	Flow              int // IPv4 only
	Flags             int
	IifName           string
	OifName           string
	SuppressIfgroup   int
	SuppressPrefixlen int

	FlagsMask uint64
}

//func (r Rule) String() string {
//	return fmt.Sprintf("ip rule %d: from %s table %s", r.Priority, r.Src, tableToString(r.Table))
//}
