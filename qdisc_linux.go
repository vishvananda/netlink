package netlink

import (
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink/nl"
)

// // QdiscAdd will add a qdisc to the system.
// // Equivalent to: `tc qdisc add $qdisc`
// func QdiscAdd(qdisc *Qdisc) error {
// 	req := nl.NewNetlinkRequest(syscall.RTM_NEWROUTE, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)
// 	return qdiscHandle(qdisc, req, nl.NewRtMsg())
// }
//
// // QdiscAdd will delete a qdisc from the system.
// // Equivalent to: `tc qdisc del $qdisc`
// func QdiscDel(qdisc *Qdisc) error {
// 	req := nl.NewNetlinkRequest(syscall.RTM_DELROUTE, syscall.NLM_F_ACK)
// 	return qdiscHandle(qdisc, req, nl.NewRtDelMsg())
// }
//
// func qdiscHandle(qdisc *Qdisc, req *nl.NetlinkRequest, msg *nl.RtMsg) error {
// 	if (qdisc.Dst == nil || qdisc.Dst.IP == nil) && qdisc.Src == nil && qdisc.Gw == nil {
// 		return fmt.Errorf("one of Dst.IP, Src, or Gw must not be nil")
// 	}
//
// 	msg.Scope = uint8(qdisc.Scope)
// 	family := -1
// 	var rtAttrs []*nl.RtAttr
//
// 	if qdisc.Dst != nil && qdisc.Dst.IP != nil {
// 		dstLen, _ := qdisc.Dst.Mask.Size()
// 		msg.Dst_len = uint8(dstLen)
// 		dstFamily := nl.GetIPFamily(qdisc.Dst.IP)
// 		family = dstFamily
// 		var dstData []byte
// 		if dstFamily == FAMILY_V4 {
// 			dstData = qdisc.Dst.IP.To4()
// 		} else {
// 			dstData = qdisc.Dst.IP.To16()
// 		}
// 		rtAttrs = append(rtAttrs, nl.NewRtAttr(syscall.RTA_DST, dstData))
// 	}
//
// 	if qdisc.Src != nil {
// 		srcFamily := nl.GetIPFamily(qdisc.Src)
// 		if family != -1 && family != srcFamily {
// 			return fmt.Errorf("source and destination ip are not the same IP family")
// 		}
// 		family = srcFamily
// 		var srcData []byte
// 		if srcFamily == FAMILY_V4 {
// 			srcData = qdisc.Src.To4()
// 		} else {
// 			srcData = qdisc.Src.To16()
// 		}
// 		// The commonly used src ip for qdiscs is actually PREFSRC
// 		rtAttrs = append(rtAttrs, nl.NewRtAttr(syscall.RTA_PREFSRC, srcData))
// 	}
//
// 	if qdisc.Gw != nil {
// 		gwFamily := nl.GetIPFamily(qdisc.Gw)
// 		if family != -1 && family != gwFamily {
// 			return fmt.Errorf("gateway, source, and destination ip are not the same IP family")
// 		}
// 		family = gwFamily
// 		var gwData []byte
// 		if gwFamily == FAMILY_V4 {
// 			gwData = qdisc.Gw.To4()
// 		} else {
// 			gwData = qdisc.Gw.To16()
// 		}
// 		rtAttrs = append(rtAttrs, nl.NewRtAttr(syscall.RTA_GATEWAY, gwData))
// 	}
//
// 	msg.Family = uint8(family)
//
// 	req.AddData(msg)
// 	for _, attr := range rtAttrs {
// 		req.AddData(attr)
// 	}
//
// 	var (
// 		b      = make([]byte, 4)
// 		native = nl.NativeEndian()
// 	)
// 	native.PutUint32(b, uint32(qdisc.LinkIndex))
//
// 	req.AddData(nl.NewRtAttr(syscall.RTA_OIF, b))
//
// 	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
// 	return err
// }

// QdiscList gets a list of qdiscs in the system.
// Equivalent to: `tc qdisc show`.
// The list can be filtered by link.
func QdiscList(link Link) ([]Qdisc, error) {
	req := nl.NewNetlinkRequest(syscall.RTM_GETQDISC, syscall.NLM_F_DUMP)
	msg := &nl.TcMsg{
		Family: nl.FAMILY_ALL,
	}
	if link != nil {
		base := link.Attrs()
		ensureIndex(base)
		msg.Ifindex = int32(base.Index)
	}
	req.AddData(msg)

	msgs, err := req.Execute(syscall.NETLINK_ROUTE, syscall.RTM_NEWQDISC)
	if err != nil {
		return nil, err
	}

	//native := nl.NativeEndian()
	var res []Qdisc
	for _, m := range msgs {
		msg := nl.DeserializeTcMsg(m)

		attrs, err := nl.ParseRouteAttr(m[msg.Len():])
		if err != nil {
			return nil, err
		}

		base := QdiscAttrs{
			LinkIndex: int(msg.Ifindex),
			Handle:    msg.Handle,
			Parent:    msg.Parent,
		}
		var qdisc Qdisc
		qdiscType := ""
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case nl.TCA_KIND:
				qdiscType = string(attr.Value[:len(attr.Value)-1])
				switch qdiscType {
				case "pfifo_fast":
					fmt.Printf("found pfifo_fast\n")
					qdisc = &PfifoFast{}
				case "tbf":
					fmt.Printf("found tbf\n")
					qdisc = &TokenBucketFilter{}
				default:
					fmt.Printf("found generic\n")
					qdisc = &GenericQdisc{QdiscType: qdiscType}
				}
			case nl.TCA_OPTIONS:
				fmt.Printf("in options\n")
				fmt.Printf("Value %v\n", attr.Value)
				switch qdiscType {
				case "pfifo_fast":
					// pfifo returns TcPrioMap directly without wrapping it in rtattr
					fmt.Printf("parsing pfifo_fast\n")
					if err := parsePfifoFastData(qdisc, attr.Value); err != nil {
						return nil, err
					}
				case "tbf":
					data, err := nl.ParseRouteAttr(attr.Value)
					if err != nil {
						return nil, err
					}
					if err := parseTokenBucketFilterData(qdisc, data); err != nil {
						return nil, err
					}
				}
			}
		}
		*qdisc.Attrs() = base
		res = append(res, qdisc)
	}

	return res, nil
}

func parsePfifoFastData(qdisc Qdisc, value []byte) error {
	pfifo := qdisc.(*PfifoFast)
	tcmap := nl.DeserializeTcPrioMap(value)
	pfifo.PriorityMap = tcmap.Priomap
	pfifo.Bands = uint8(tcmap.Bands)
	return nil
}

func parseTokenBucketFilterData(qdisc Qdisc, data []syscall.NetlinkRouteAttr) error {
	tbf := qdisc.(*TokenBucketFilter)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.TCA_TBF_UNSPEC:
			tbf.Type()
		}
	}
	return nil
}
