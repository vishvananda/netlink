package netlink

import (
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink/nl"
)

// Protinfo is abstraction under IFLA_PROTINFO.
// Negative fields is treated as "unset" and won't be sent to netlink.
type Protinfo struct {
	Hairpin   int
	Guard     int
	FastLeave int
	RootBlock int
	Learning  int
	Flood     int
}

// NewProtinfo returns Protinfo with all fields unset
// Example of usage(enables hairpin, disables learning):
// pi := NewProtinfo()
// pi.Hairpin = 1
// pi.Learning = 0
func NewProtinfo() Protinfo {
	return Protinfo{
		Hairpin:   -1,
		Guard:     -1,
		FastLeave: -1,
		RootBlock: -1,
		Learning:  -1,
		Flood:     -1,
	}
}

func intToByte(x int) []byte {
	if x > 0 {
		return []byte{1}
	}
	return []byte{0}
}

func byteToInt(x []byte) int {
	if uint8(x[0]) != 0 {
		return 1
	}
	return 0
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
					pi.Hairpin = byteToInt(info.Value)
				case nl.IFLA_BRPORT_GUARD:
					pi.Guard = byteToInt(info.Value)
				case nl.IFLA_BRPORT_FAST_LEAVE:
					pi.FastLeave = byteToInt(info.Value)
				case nl.IFLA_BRPORT_PROTECT:
					pi.RootBlock = byteToInt(info.Value)
				case nl.IFLA_BRPORT_LEARNING:
					pi.Learning = byteToInt(info.Value)
				case nl.IFLA_BRPORT_UNICAST_FLOOD:
					pi.Flood = byteToInt(info.Value)
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
	if p.Hairpin >= 0 {
		nl.NewRtAttrChild(br, nl.IFLA_BRPORT_MODE, intToByte(p.Hairpin))
	}
	if p.Guard >= 0 {
		nl.NewRtAttrChild(br, nl.IFLA_BRPORT_GUARD, intToByte(p.Guard))
	}
	if p.FastLeave >= 0 {
		nl.NewRtAttrChild(br, nl.IFLA_BRPORT_FAST_LEAVE, intToByte(p.FastLeave))
	}
	if p.RootBlock >= 0 {
		nl.NewRtAttrChild(br, nl.IFLA_BRPORT_PROTECT, intToByte(p.RootBlock))
	}
	if p.Learning >= 0 {
		nl.NewRtAttrChild(br, nl.IFLA_BRPORT_LEARNING, intToByte(p.Learning))
	}
	if p.Flood >= 0 {
		nl.NewRtAttrChild(br, nl.IFLA_BRPORT_UNICAST_FLOOD, intToByte(p.Flood))
	}
	req.AddData(br)
	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	if err != nil {
		return err
	}
	return nil
}
