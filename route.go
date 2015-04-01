package netlink

import (
	"fmt"
	"net"
)

// Route represents a netlink route. A route is associated with a link,
// has a destination network, an optional source ip, and optional
// gateway. Advanced route parameters and non-main routing tables are
// currently not supported.
type Route struct {
	LinkIndex int
	Scope     int
	Protocol  int
	Table     int
	Type      int
	Dst       *net.IPNet
	Src       net.IP
	Gw        net.IP
}

func (r Route) String() string {
	return fmt.Sprintf("{Ifindex: %d Proto: %d Scope: %d Table: %d Type: %d Dst: %s Src: %s Gw: %s}",
		r.LinkIndex, r.Protocol, r.Scope, r.Table, r.Type, r.Dst, r.Src, r.Gw)
}
