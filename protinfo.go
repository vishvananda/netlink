package netlink

import (
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink/nl"
)

type Protinfo struct {
	Hairpin   bool
	Guard     bool
	FastLeave bool
	RootBlock bool
	Learning  bool
	Flood     bool
}

func boolToByte(x bool) []byte {
	if x {
		return []byte{1}
	}
	return []byte{0}
}

func byteToBool(x byte) bool {
	if uint8(x) != 0 {
		return true
	}
	return false
}

func LinkGetProtinfo(link Link) (Protinfo, error) {
	base := link.Attrs()
	ensureIndex(base)
	var pi Protinfo
	req := nl.NewNetlinkRequest(syscall.RTM_GETLINK, syscall.NLM_F_DUMP)
	msg := nl.NewIfInfomsg(syscall.AF_BRIDGE)
	req.AddData(msg)
	msgs, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	if err != nil {
		return pi, err
	}

	for _, m := range msgs {
		ans := nl.DeserializeIfInfomsg(m)
		if int(ans.Index) != base.Index {
			continue
		}
		attrs, err := nl.ParseRouteAttr(m[ans.Len():])
		if err != nil {
			return pi, err
		}
		for _, attr := range attrs {
			if attr.Attr.Type != syscall.IFLA_PROTINFO|syscall.NLA_F_NESTED {
				continue
			}
			infos, err := nl.ParseRouteAttr(attr.Value)
			if err != nil {
				return pi, err
			}
			var pi Protinfo
			for _, info := range infos {
				switch info.Attr.Type {
				case nl.IFLA_BRPORT_MODE:
					pi.Hairpin = byteToBool(info.Value[0])
				case nl.IFLA_BRPORT_GUARD:
					pi.Guard = byteToBool(info.Value[0])
				case nl.IFLA_BRPORT_FAST_LEAVE:
					pi.FastLeave = byteToBool(info.Value[0])
				case nl.IFLA_BRPORT_PROTECT:
					pi.RootBlock = byteToBool(info.Value[0])
				case nl.IFLA_BRPORT_LEARNING:
					pi.Learning = byteToBool(info.Value[0])
				case nl.IFLA_BRPORT_UNICAST_FLOOD:
					pi.Flood = byteToBool(info.Value[0])
				}
			}
			return pi, nil
		}
	}
	return pi, fmt.Errorf("Device with index %d not found", base.Index)
}

func LinkSetProtinfo(link Link, p Protinfo) error {
	base := link.Attrs()
	ensureIndex(base)
	req := nl.NewNetlinkRequest(syscall.RTM_SETLINK, syscall.NLM_F_ACK)

	msg := nl.NewIfInfomsg(syscall.AF_BRIDGE)
	msg.Type = syscall.RTM_SETLINK
	msg.Flags = syscall.NLM_F_REQUEST
	msg.Index = int32(base.Index)
	msg.Change = nl.DEFAULT_CHANGE
	req.AddData(msg)

	br := nl.NewRtAttr(syscall.IFLA_PROTINFO|syscall.NLA_F_NESTED, nil)
	nl.NewRtAttrChild(br, nl.IFLA_BRPORT_MODE, boolToByte(p.Hairpin))
	nl.NewRtAttrChild(br, nl.IFLA_BRPORT_GUARD, boolToByte(p.Guard))
	nl.NewRtAttrChild(br, nl.IFLA_BRPORT_FAST_LEAVE, boolToByte(p.FastLeave))
	nl.NewRtAttrChild(br, nl.IFLA_BRPORT_PROTECT, boolToByte(p.RootBlock))
	nl.NewRtAttrChild(br, nl.IFLA_BRPORT_LEARNING, boolToByte(p.Learning))
	nl.NewRtAttrChild(br, nl.IFLA_BRPORT_UNICAST_FLOOD, boolToByte(p.Flood))
	req.AddData(br)
	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	if err != nil {
		return err
	}
	return nil
}
