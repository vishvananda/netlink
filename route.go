package netlink

import (
	"fmt"
	"net"
	"strings"
	"syscall"
)

// Route represents a netlink route. A route is associated with a link,
// has a destination network, an optional source ip, and optional
// gateway. Advanced route parameters and non-main routing tables are
// currently not supported.
type Route struct {
	Iif      int
	Oif      int
	Scope    int
	Protocol int
	Table    int
	Type     int
	Family   int
	Tos      int
	Flags    int
	Priority int
	From     *net.IPNet
	Dst      *net.IPNet
	Src      net.IP
	Gateway  net.IP
}

func (r Route) String() string {
	s := fmt.Sprintf("ip route %s via %s %s %s %s %s ",
		dstAndSrcToString(r.Dst, r.Src), r.Gateway, indexToString(r.Oif),
		scopeToString(r.Scope), protocolToString(r.Protocol), tableToString(r.Table))
	// remove multiple spaces
	return strings.Join(strings.Fields(s), " ")
}

func indexToString(idx int) string {
	if idx == 0 {
		return ""
	}
	return fmt.Sprintf("via index %d", idx)
}

func dstAndSrcToString(dst *net.IPNet, src net.IP) string {
	if dst == nil && src == nil {
		return "default"
	}

	var s string
	if src != nil {
		s += fmt.Sprintf("src %s", src)
	}

	if dst != nil {
		s += fmt.Sprintf(" dst %s", dst)
	}
	return s
}

var scopesString = map[int]string{
	syscall.RT_SCOPE_HOST:     "host",
	syscall.RT_SCOPE_LINK:     "link",
	syscall.RT_SCOPE_SITE:     "site",
	syscall.RT_SCOPE_NOWHERE:  "nowhere",
	syscall.RT_SCOPE_UNIVERSE: "universe",
}

func scopeToString(scope int) string {
	if scope == syscall.RT_SCOPE_UNIVERSE {
		return ""
	}
	if s, ok := scopesString[scope]; ok {
		return "scope " + s
	}
	return fmt.Sprintf("scope unknown(%d)", scope)
}

var tablesString = map[int]string{
	syscall.RT_TABLE_MAIN:    "main",
	syscall.RT_TABLE_LOCAL:   "local",
	syscall.RT_TABLE_DEFAULT: "default",
	syscall.RT_TABLE_COMPAT:  "compat",
	syscall.RT_TABLE_UNSPEC:  "unspec",
}

func tableToString(table int) string {
	if table == syscall.RT_TABLE_MAIN {
		return ""
	}
	if s, ok := tablesString[table]; ok {
		return "table " + s
	}
	return fmt.Sprintf("table unknown(%d)", table)
}

var protocolsString = map[int]string{
	syscall.RTPROT_UNSPEC:   "unspec",
	syscall.RTPROT_REDIRECT: "redirect",
	syscall.RTPROT_KERNEL:   "kernel",
	syscall.RTPROT_BOOT:     "boot",
	syscall.RTPROT_STATIC:   "static",
	syscall.RTPROT_GATED:    "gated",
	syscall.RTPROT_RA:       "ra",
	syscall.RTPROT_MRT:      "mrt",
	syscall.RTPROT_ZEBRA:    "zebra",
	syscall.RTPROT_BIRD:     "bird",
	syscall.RTPROT_DNROUTED: "dnrouted",
	syscall.RTPROT_XORP:     "xorp",
	syscall.RTPROT_NTK:      "ntk",
	syscall.RTPROT_DHCP:     "dhcp",
}

func protocolToString(protocol int) string {
	if protocol == syscall.RTPROT_KERNEL {
		return ""
	}
	if s, ok := protocolsString[protocol]; ok {
		return "protocol " + s
	}
	return fmt.Sprintf("protocol unknown(%d)", protocol)
}
