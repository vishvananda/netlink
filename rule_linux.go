package netlink

import (
	"fmt"
	"net"
	"syscall"

	"git.spinoff.ovh.net/router/netlink/nl"
)

// RuleAdd adds a rule to the system.
// Equivalent to: ip rule add
func RuleAdd(rule *Rule) error {
	req := nl.NewNetlinkRequest(syscall.RTM_NEWRULE, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)
	return ruleHandle(rule, req)
}

// RuleDel deletes a rule from the system.
// Equivalent to: ip rule del
func RuleDel(rule *Rule) error {
	req := nl.NewNetlinkRequest(syscall.RTM_DELRULE, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)
	return ruleHandle(rule, req)
}

func ruleHandle(rule *Rule, req *nl.NetlinkRequest) error {
	msg := nl.NewRtMsg()
	family := syscall.AF_INET

	var rtAttrs []*nl.RtAttr
	if rule.Dst != nil && rule.Dst.IP != nil {
		dstLen, _ := rule.Dst.Mask.Size()
		msg.Dst_len = uint8(dstLen)
		family = nl.GetIPFamily(rule.Dst.IP)
		var dstData []byte
		if family == syscall.AF_INET {
			dstData = rule.Dst.IP.To4()
		} else {
			dstData = rule.Dst.IP.To16()
		}
		rtAttrs = append(rtAttrs, nl.NewRtAttr(syscall.RTA_DST, dstData))
	}

	if rule.Src != nil && rule.Src.IP != nil {
		srcFamily := nl.GetIPFamily(rule.Src.IP)
		if family != -1 && family != srcFamily {
			return fmt.Errorf("source and destination ip are not the same IP family")
		}
		srcLen, _ := rule.Src.Mask.Size()
		msg.Src_len = uint8(srcLen)
		family = srcFamily
		var srcData []byte
		if srcFamily == syscall.AF_INET {
			srcData = rule.Src.IP.To4()
		} else {
			srcData = rule.Src.IP.To16()
		}
		rtAttrs = append(rtAttrs, nl.NewRtAttr(syscall.RTA_SRC, srcData))
	}

	msg.Family = uint8(family)

	if rule.Type != 0 {
		msg.Type = uint8(rule.Type)
	}
	if rule.FlagMask&RULE_GOTO_MASK != 0 {
		msg.Type = nl.FR_ACT_NOP
	}
	if rule.FlagMask&RULE_TABLE_MASK != 0 {
		if rule.Table < 256 {
			msg.Table = uint8(rule.Table)
		} else {
			msg.Table = syscall.RT_TABLE_UNSPEC
		}
	}

	req.AddData(msg)
	for i := range rtAttrs {
		req.AddData(rtAttrs[i])
	}

	var (
		b      = make([]byte, 4)
		native = nl.NativeEndian()
	)

	if rule.FlagMask&RULE_PRIORITY_MASK != 0 {
		native.PutUint32(b, uint32(rule.Priority))
		req.AddData(nl.NewRtAttr(nl.FRA_PRIORITY, b))
	}
	if rule.FlagMask&RULE_FWMARK_MASK != 0 {
		native.PutUint32(b, uint32(rule.Mark))
		req.AddData(nl.NewRtAttr(nl.FRA_FWMARK, b))
	}
	if rule.FlagMask&RULE_FWMASK_MASK != 0 {
		native.PutUint32(b, uint32(rule.Mask))
		req.AddData(nl.NewRtAttr(nl.FRA_FWMASK, b))
	}
	if rule.FlagMask&RULE_FLOW_MASK != 0 {
		native.PutUint32(b, uint32(rule.Flow))
		req.AddData(nl.NewRtAttr(nl.FRA_FLOW, b))
	}
	if rule.FlagMask&RULE_TABLE_MASK != 0 && rule.Table >= 256 {
		native.PutUint32(b, uint32(rule.Table))
		req.AddData(nl.NewRtAttr(nl.FRA_TABLE, b))
	}
	if msg.Table != 0 {
		if rule.FlagMask&RULE_SUPPRESS_PREFIXLEN_MASK != 0 {
			native.PutUint32(b, uint32(rule.SuppressPrefixlen))
			req.AddData(nl.NewRtAttr(nl.FRA_SUPPRESS_PREFIXLEN, b))
		}
		if rule.FlagMask&RULE_SUPPRESS_IFGROUP_MASK != 0 {
			native.PutUint32(b, uint32(rule.SuppressIfgroup))
			req.AddData(nl.NewRtAttr(nl.FRA_SUPPRESS_IFGROUP, b))
		}
	}
	if rule.IifName != "" {
		req.AddData(nl.NewRtAttr(nl.FRA_IIFNAME, []byte(rule.IifName)))
	}
	if rule.OifName != "" {
		req.AddData(nl.NewRtAttr(nl.FRA_OIFNAME, []byte(rule.OifName)))
	}
	if rule.FlagMask&RULE_GOTO_MASK != 0 {
		native.PutUint32(b, uint32(rule.Goto))
		req.AddData(nl.NewRtAttr(nl.FRA_GOTO, b))
	}

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// RuleList lists rules in the system.
// Equivalent to: ip rule list
func RuleList(family int) ([]Rule, error) {
	req := nl.NewNetlinkRequest(syscall.RTM_GETRULE, syscall.NLM_F_DUMP|syscall.NLM_F_REQUEST)
	msg := nl.NewIfInfomsg(family)
	req.AddData(msg)

	msgs, err := req.Execute(syscall.NETLINK_ROUTE, syscall.RTM_NEWRULE)
	if err != nil {
		return nil, err
	}

	native := nl.NativeEndian()
	var res = make([]Rule, 0)
	for i := range msgs {
		msg := nl.DeserializeRtMsg(msgs[i])
		attrs, err := nl.ParseRouteAttr(msgs[i][msg.Len():])
		if err != nil {
			return nil, err
		}

		rule := Rule{
			Table:             int(msg.Table),
			Protocol:          int(msg.Protocol),
			Type:              int(msg.Type),
			Scope:             int(msg.Scope),
			Tos:               int(msg.Tos),
			Family:            int(msg.Family),
			Flags:             int(msg.Flags),
			SuppressPrefixlen: -1,
			SuppressIfgroup:   -1,
		}

		for j := range attrs {
			switch attrs[j].Attr.Type {
			case syscall.RTA_TABLE:
				rule.Table = int(native.Uint32(attrs[j].Value[0:4]))
				rule.FlagMask |= RULE_TABLE_MASK
			case nl.FRA_SRC:
				rule.Src = &net.IPNet{
					IP:   attrs[j].Value,
					Mask: net.CIDRMask(int(msg.Src_len), 8*len(attrs[j].Value)),
				}
			case nl.FRA_DST:
				rule.Dst = &net.IPNet{
					IP:   attrs[j].Value,
					Mask: net.CIDRMask(int(msg.Dst_len), 8*len(attrs[j].Value)),
				}
			case nl.FRA_FWMARK:
				rule.Mark = int(native.Uint32(attrs[j].Value[0:4]))
				rule.FlagMask |= RULE_FWMARK_MASK
			case nl.FRA_FWMASK:
				rule.Mask = int(native.Uint32(attrs[j].Value[0:4]))
				rule.FlagMask |= RULE_FWMASK_MASK
			case nl.FRA_IIFNAME:
				rule.IifName = string(attrs[j].Value[:len(attrs[j].Value)-1])
			case nl.FRA_OIFNAME:
				rule.OifName = string(attrs[j].Value[:len(attrs[j].Value)-1])
			case nl.FRA_SUPPRESS_PREFIXLEN:
				i := native.Uint32(attrs[j].Value[0:4])
				if i != 0xffffffff {
					rule.SuppressPrefixlen = int(i)
					rule.FlagMask |= RULE_SUPPRESS_PREFIXLEN_MASK
				}
			case nl.FRA_SUPPRESS_IFGROUP:
				i := native.Uint32(attrs[j].Value[0:4])
				if i != 0xffffffff {
					rule.SuppressIfgroup = int(i)
					rule.FlagMask |= RULE_SUPPRESS_IFGROUP_MASK
				}
			case nl.FRA_FLOW:
				rule.Flow = int(native.Uint32(attrs[j].Value[0:4]))
				rule.FlagMask |= RULE_FLOW_MASK
			case nl.FRA_GOTO:
				rule.Goto = int(native.Uint32(attrs[j].Value[0:4]))
				rule.FlagMask |= RULE_GOTO_MASK
			case nl.FRA_PRIORITY:
				rule.Priority = int(native.Uint32(attrs[j].Value[0:4]))
				rule.FlagMask |= RULE_PRIORITY_MASK
			}
		}
		res = append(res, rule)
	}

	return res, nil
}
