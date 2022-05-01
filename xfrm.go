package netlink

import (
	"fmt"
)

// Proto is an enum representing an ipsec protocol.
type Proto uint8

// Mode is an enum representing an ipsec transport.
type Mode uint8

const (
	XFRM_MODE_TRANSPORT Mode = iota
	XFRM_MODE_TUNNEL
	XFRM_MODE_ROUTEOPTIMIZATION
	XFRM_MODE_IN_TRIGGER
	XFRM_MODE_BEET
	XFRM_MODE_MAX
)

func (m Mode) String() string {
	switch m {
	case XFRM_MODE_TRANSPORT:
		return "transport"
	case XFRM_MODE_TUNNEL:
		return "tunnel"
	case XFRM_MODE_ROUTEOPTIMIZATION:
		return "ro"
	case XFRM_MODE_IN_TRIGGER:
		return "in_trigger"
	case XFRM_MODE_BEET:
		return "beet"
	}
	return fmt.Sprintf("%d", m)
}

// XfrmMark represents the mark associated to the state or policy
type XfrmMark struct {
	Value uint32
	Mask  uint32
}

func (m *XfrmMark) String() string {
	return fmt.Sprintf("(0x%x,0x%x)", m.Value, m.Mask)
}
