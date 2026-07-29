package netlink

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
        // NEXTHOP_GRP_TYPE_MPATH is default multi-path hash threshold
        NEXTHOP_GRP_TYPE_MPATH uint16 = iota

        // NEXTHOP_GRP_TYPE_RES is Resilient nexthop group
        NEXTHOP_GRP_TYPE_RES
)

// NexthopGroupMpath represents one member of a nexthtop group
type NexthopGroupMpath struct {
        // ID of an existing nexthop to include in the group
        ID uint16
        // Relative weight, 1-256. Zero is treated as 1
        Weight uint16
}

type NexthopResGroup struct {
        Buckets uint16
        IdleTimer uint32
        UnbalancedTimer uint32
        UnbalancedTime uint64
}

type Nexthop struct {
	ID        uint32
	Blackhole bool
	OIF       uint32
	Gateway   net.IP
	Protocol  RouteProtocol
	Group []NexthopGroupMpath
	GroupType uint16
	ResGroup *NexthopResGroup
}

func (h *Nexthop) String() string {
	elems := []string{
		"ID: " + strconv.FormatUint(uint64(h.ID), 10),
		"Blackhole: " + strconv.FormatBool(h.Blackhole),
		"OIF: " + strconv.FormatUint(uint64(h.OIF), 10),
		"Gateway: " + h.Gateway.String(),
		"Protocol: " + h.Protocol.String(),
	}
	return fmt.Sprintf("{%s}", strings.Join(elems, " "))
}
