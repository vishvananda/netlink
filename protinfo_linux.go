package netlink

import (
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink/nl"
)

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

	for i := range msgs {
		ans := nl.DeserializeIfInfomsg(msgs[i])
		if int(ans.Index) != base.Index {
			continue
		}
		attrs, err := nl.ParseRouteAttr(msgs[i][ans.Len():])
		if err != nil {
			return pi, err
		}
		for j := range attrs {
			if attrs[j].Attr.Type != syscall.IFLA_PROTINFO|syscall.NLA_F_NESTED {
				continue
			}
			infos, err := nl.ParseRouteAttr(attrs[j].Value)
			if err != nil {
				return pi, err
			}
			var pi Protinfo
			for k := range infos {
				switch infos[k].Attr.Type {
				case nl.IFLA_BRPORT_MODE:
					pi.Hairpin = byteToBool(infos[k].Value[0])
				case nl.IFLA_BRPORT_GUARD:
					pi.Guard = byteToBool(infos[k].Value[0])
				case nl.IFLA_BRPORT_FAST_LEAVE:
					pi.FastLeave = byteToBool(infos[k].Value[0])
				case nl.IFLA_BRPORT_PROTECT:
					pi.RootBlock = byteToBool(infos[k].Value[0])
				case nl.IFLA_BRPORT_LEARNING:
					pi.Learning = byteToBool(infos[k].Value[0])
				case nl.IFLA_BRPORT_UNICAST_FLOOD:
					pi.Flood = byteToBool(infos[k].Value[0])
				}
			}
			return pi, nil
		}
	}
	return pi, fmt.Errorf("Device with index %d not found", base.Index)
}
