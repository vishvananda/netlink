package netlink

import (
	"fmt"
	"net"
)

// Dir is an enum representing an ipsec template direction.
type Dir uint8

const (
	XFRM_DIR_IN  = iota
	XFRM_DIR_OUT = iota
)

func (d Dir) String() string {
	switch d {
	case XFRM_DIR_IN:
		return "in"
	case XFRM_DIR_OUT:
		return "out"
	}
	return fmt.Sprintf("%d", d)
}

// XfrmPolicyTmpl encapsulates a rule for the base addresses of an ipsec
// policy. These rules are matched with XfrmState to determine encryption
// and authentication algorithms.
type XfrmPolicyTmpl struct {
	Dst   net.IP
	Src   net.IP
	Proto Proto
	Mode  Mode
	Reqid int
}

// XfrmPolicy represents an ipsec policy. It represents the overlay network
// and has a list of XfrmPolicyTmpls representing the base addresses of
// the policy.
type XfrmPolicy struct {
	Dst      *net.IPNet
	Src      *net.IPNet
	Dir      Dir
	Priority int
	Index    int
	Tmpls    []XfrmPolicyTmpl
}
