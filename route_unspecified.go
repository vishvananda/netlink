// +build !linux

package netlink

import "net"

const (
	SCOPE_UNIVERSE Scope = 0
	SCOPE_SITE     Scope = 0
	SCOPE_LINK     Scope = 0
	SCOPE_HOST     Scope = 0
	SCOPE_NOWHERE  Scope = 0
)

const (
	RT_FILTER_PROTOCOL uint64 = 1 << (1 + iota)
	RT_FILTER_SCOPE
	RT_FILTER_TYPE
	RT_FILTER_TOS
	RT_FILTER_IIF
	RT_FILTER_OIF
	RT_FILTER_DST
	RT_FILTER_SRC
	RT_FILTER_GW
	RT_FILTER_TABLE
)

const (
	FLAG_ONLINK    NextHopFlag = 0
	FLAG_PERVASIVE NextHopFlag = 0
)

func (r *Route) ListFlags() []string {
	return []string{}
}

func (n *NexthopInfo) ListFlags() []string {
	return []string{}
}

// RouteListFiltered gets a list of routes in the system filtered with specified rules.
// All rules must be defined in RouteFilter struct
func RouteListFiltered(family int, filter *Route, filterMask uint64) ([]Route, error) {
	return nil, ErrNotImplemented
}

// RouteGet gets a route to a specific destination from the host system.
// Equivalent to: 'ip route get'.
func RouteGet(destination net.IP) ([]Route, error) {
	return nil, ErrNotImplemented
}
