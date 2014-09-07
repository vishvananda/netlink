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
	Link *Link
	Dst  *net.IPNet
	Src  net.IP
	Gw   net.IP
}

func (r Route) String() string {
	return fmt.Sprintf("{%s Dst: %s Src: %s Gw: %s}", r.Link.Name, r.Dst.String(),
		r.Src, r.Gw)
}
