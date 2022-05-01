package netlink

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	XFRM_PROTO_ROUTE2    Proto = unix.IPPROTO_ROUTING
	XFRM_PROTO_ESP       Proto = unix.IPPROTO_ESP
	XFRM_PROTO_AH        Proto = unix.IPPROTO_AH
	XFRM_PROTO_HAO       Proto = unix.IPPROTO_DSTOPTS
	XFRM_PROTO_COMP      Proto = 0x6c // NOTE not defined on darwin
	XFRM_PROTO_IPSEC_ANY Proto = unix.IPPROTO_RAW
)

func (p Proto) String() string {
	switch p {
	case XFRM_PROTO_ROUTE2:
		return "route2"
	case XFRM_PROTO_ESP:
		return "esp"
	case XFRM_PROTO_AH:
		return "ah"
	case XFRM_PROTO_HAO:
		return "hao"
	case XFRM_PROTO_COMP:
		return "comp"
	case XFRM_PROTO_IPSEC_ANY:
		return "ipsec-any"
	}
	return fmt.Sprintf("%d", p)
}
