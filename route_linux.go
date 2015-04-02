package netlink

import (
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink/nl"
)

// RtAttr is shared so it is in netlink_linux.go

// RouteFilter represents filter that can be apply to RouteList function.
type RouteFilter struct {
	Table    int
	Protocol int
	Scope    int
	Type     int
	Tos      int
	Iif      int // the device from which this packet is expected to arrive.
	Oif      int // force the output device on which this packet will be routed.

	Flagmask uint64

	// TODO: Implement rest of filter option
	// Mark         int
	// Realm        int
	// Src          *net.IPNet
	// RootVia      *net.IPNet
	// ToRootDst    *net.IPNet
	// ToMatchDst   *net.IPNet
	// FromRootSrc  *net.IPNet
	// FromMatchSrc *net.IPNet

	// TODO: Implement Flush filter when needed.
	// Flushed      int
	// Flushb       string
	// Flushp       int
	// Flushe       int
}

// Flag mask for router filters. RouterFilter.Flagmask must be set to on
// for filter to work.
const (
	FILTER_PROTOCOL uint64 = 1 << (1 + iota)
	FILTER_SCOPE
	FILTER_TYPE
	FILTER_TOS
	FILTER_IIF
	FILTER_OIF
	// FILTER_MARK
	// FILTER_REAL
)

// RouteAdd will add a route to the system.
// Equivalent to: `ip route add $route`
func RouteAdd(route *Route) error {
	req := nl.NewNetlinkRequest(syscall.RTM_NEWROUTE, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)
	return routeHandle(route, req)
}

// RouteDel will delete a route from the system.
// Equivalent to: `ip route del $route`
func RouteDel(route *Route) error {
	req := nl.NewNetlinkRequest(syscall.RTM_DELROUTE, syscall.NLM_F_ACK)
	return routeHandle(route, req)
}

func routeHandle(route *Route, req *nl.NetlinkRequest) error {
	if (route.Dst == nil || route.Dst.IP == nil) && route.Src == nil && route.Gateway == nil {
		return fmt.Errorf("one of Dst.IP, Src, or Gw must not be nil")
	}

	msg := nl.NewRtMsg()
	msg.Scope = uint8(route.Scope)
	family := -1
	var rtAttrs []*nl.RtAttr

	if route.Dst != nil && route.Dst.IP != nil {
		dstLen, _ := route.Dst.Mask.Size()
		msg.Dst_len = uint8(dstLen)
		dstFamily := nl.GetIPFamily(route.Dst.IP)
		family = dstFamily
		var dstData []byte
		if dstFamily == FAMILY_V4 {
			dstData = route.Dst.IP.To4()
		} else {
			dstData = route.Dst.IP.To16()
		}
		rtAttrs = append(rtAttrs, nl.NewRtAttr(syscall.RTA_DST, dstData))
	}

	if route.Src != nil {
		srcFamily := nl.GetIPFamily(route.Src)
		if family != -1 && family != srcFamily {
			return fmt.Errorf("source and destination ip are not the same IP family")
		}
		family = srcFamily
		var srcData []byte
		if srcFamily == FAMILY_V4 {
			srcData = route.Src.To4()
		} else {
			srcData = route.Src.To16()
		}
		// The commonly used src ip for routes is actually PREFSRC
		rtAttrs = append(rtAttrs, nl.NewRtAttr(syscall.RTA_PREFSRC, srcData))
	}

	if route.Gateway != nil {
		gwFamily := nl.GetIPFamily(route.Gateway)
		if family != -1 && family != gwFamily {
			return fmt.Errorf("gateway, source, and destination ip are not the same IP family")
		}
		family = gwFamily
		var gwData []byte
		if gwFamily == FAMILY_V4 {
			gwData = route.Gateway.To4()
		} else {
			gwData = route.Gateway.To16()
		}
		rtAttrs = append(rtAttrs, nl.NewRtAttr(syscall.RTA_GATEWAY, gwData))
	}

	msg.Family = uint8(family)

	req.AddData(msg)
	for i := range rtAttrs {
		req.AddData(rtAttrs[i])
	}

	var (
		b      = make([]byte, 4)
		native = nl.NativeEndian()
	)
	native.PutUint32(b, uint32(route.Oif))

	req.AddData(nl.NewRtAttr(syscall.RTA_OIF, b))

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// RouteList gets a list of routes in the system.
// Equivalent to: `ip route show`.
// The list can be filtered ip family and route filter.
// By default (like ip route show) only routes are dumped, that
// are in the MAIN table. To get all routes filter.Table has to be 0.
func RouteList(family int, filter *RouteFilter) ([]Route, error) {
	req := nl.NewNetlinkRequest(syscall.RTM_GETROUTE, syscall.NLM_F_DUMP)
	msg := nl.NewIfInfomsg(family)
	req.AddData(msg)

	msgs, err := req.Execute(syscall.NETLINK_ROUTE, syscall.RTM_NEWROUTE)
	if err != nil {
		return nil, err
	}

	native := nl.NativeEndian()
	var res []Route
	for i := range msgs {
		msg := nl.DeserializeRtMsg(msgs[i])
		if msg.Flags&syscall.RTM_F_CLONED != 0 {
			// Ignore cloned routes
			continue
		}

		if filter == nil && msg.Table != syscall.RT_TABLE_MAIN {
			// Ignore non-main tables
			continue
		}

		attrs, err := nl.ParseRouteAttr(msgs[i][msg.Len():])
		if err != nil {
			return nil, err
		}

		if filter != nil {
			if msg.Table != uint8(filter.Table) {
				continue
			}
			f := filter.Flagmask
			switch {
			case f&FILTER_PROTOCOL != 0:
				if msg.Protocol != uint8(filter.Protocol) {
					continue
				}
			case f&FILTER_SCOPE != 0:
				if msg.Scope != uint8(filter.Scope) {
					continue
				}
			case f&FILTER_TYPE != 0:
				if msg.Type != uint8(filter.Type) {
					continue
				}
			case f&FILTER_TOS != 0:
				if msg.Tos != uint8(filter.Tos) {
					continue
				}
			}
		}

		route := Route{
			Scope:    int(msg.Scope),
			Table:    int(msg.Table),
			Protocol: int(msg.Protocol),
			Type:     int(msg.Type),
			Tos:      int(msg.Tos),
			Family:   int(msg.Family),
			Flags:    int(msg.Flags),
		}

		for j := range attrs {
			switch attrs[j].Attr.Type {
			case syscall.RTA_GATEWAY:
				route.Gateway = net.IP(attrs[j].Value)
			case syscall.RTA_PREFSRC:
				route.Src = net.IP(attrs[j].Value)
			case syscall.RTA_DST:
				route.Dst = &net.IPNet{
					IP:   attrs[j].Value,
					Mask: net.CIDRMask(int(msg.Dst_len), 8*len(attrs[j].Value)),
				}
			case syscall.RTA_SRC:
				route.From = &net.IPNet{
					IP:   attrs[j].Value,
					Mask: net.CIDRMask(int(msg.Dst_len), 8*len(attrs[j].Value)),
				}
			case syscall.RTA_OIF:
				routeIndex := int(native.Uint32(attrs[j].Value[0:4]))
				if filter != nil && filter.Flagmask&FILTER_OIF != 0 && filter.Oif != routeIndex {
					// Ignore routes from other interfaces
					continue
				}
				route.Oif = routeIndex
			case syscall.RTA_IIF:
				routeIndex := int(native.Uint32(attrs[j].Value[0:4]))
				if filter != nil && filter.Flagmask&FILTER_IIF != 0 && filter.Iif != routeIndex {
					continue
				}
				route.Iif = routeIndex
			case syscall.RTA_PRIORITY:
				route.Priority = int(native.Uint32(attrs[j].Value[0:4]))
			case syscall.RTA_TABLE:
				// no action, table is storead already in msg.Table
			default:
				// Not Implemented
				// TODO: Implement RTA_CACHEINFO, RTA_FLOW, RTA_MARK, flags&RTM_F_CLONED,
				// RTA_METRICS, RTA_MULTIPATH
			}

		}
		res = append(res, route)
	}

	return res, nil
}

// RouteGet gets a route to a specific destination from the host system.
// Equivalent to: 'ip route get'.
func RouteGet(destination net.IP) ([]Route, error) {
	req := nl.NewNetlinkRequest(syscall.RTM_GETROUTE, syscall.NLM_F_REQUEST)
	family := nl.GetIPFamily(destination)
	var destinationData []byte
	var bitlen uint8
	if family == FAMILY_V4 {
		destinationData = destination.To4()
		bitlen = 32
	} else {
		destinationData = destination.To16()
		bitlen = 128
	}
	msg := &nl.RtMsg{}
	msg.Family = uint8(family)
	msg.Dst_len = bitlen
	req.AddData(msg)

	rtaDst := nl.NewRtAttr(syscall.RTA_DST, destinationData)
	req.AddData(rtaDst)

	msgs, err := req.Execute(syscall.NETLINK_ROUTE, syscall.RTM_NEWROUTE)
	if err != nil {
		return nil, err
	}

	native := nl.NativeEndian()
	var res []Route
	for i := range msgs {
		msg := nl.DeserializeRtMsg(msgs[i])
		attrs, err := nl.ParseRouteAttr(msgs[i][msg.Len():])
		if err != nil {
			return nil, err
		}

		route := Route{}
		for j := range attrs {
			switch attrs[j].Attr.Type {
			case syscall.RTA_GATEWAY:
				route.Gateway = net.IP(attrs[j].Value)
			case syscall.RTA_PREFSRC:
				route.Src = net.IP(attrs[j].Value)
			case syscall.RTA_DST:
				route.Dst = &net.IPNet{
					IP:   attrs[j].Value,
					Mask: net.CIDRMask(int(msg.Dst_len), 8*len(attrs[j].Value)),
				}
			case syscall.RTA_OIF:
				routeIndex := int(native.Uint32(attrs[j].Value[0:4]))
				route.Oif = routeIndex
			}
		}
		res = append(res, route)
	}
	return res, nil

}
