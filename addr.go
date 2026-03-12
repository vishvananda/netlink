package netlink

import (
	"fmt"
	"net/netip"
	"strings"
)

// Addr represents an IP address from netlink. Netlink ip addresses
// include a mask, so it stores the address as a netip.Prefix.
type Addr struct {
	netip.Prefix
	Label       string
	Flags       int
	Scope       int
	Peer        netip.Prefix
	Broadcast   netip.Addr
	PreferedLft int
	ValidLft    int
	LinkIndex   int
	Protocol    int // IFA_PROTO: address protocol/origin (kernel 5.18+)
}

// String returns $ip/$netmask $label
func (a Addr) String() string {
	return strings.TrimSpace(fmt.Sprintf("%s %s", a.Prefix, a.Label))
}

// ParseAddr parses the string representation of an address in the
// form $ip/$netmask $label. The label portion is optional
func ParseAddr(s string) (*Addr, error) {
	label := ""
	parts := strings.Split(s, " ")
	if len(parts) > 1 {
		s = parts[0]
		label = parts[1]
	}
	m, err := ParseIPNet(s)
	if err != nil {
		return nil, err
	}
	return &Addr{Prefix: m, Label: label}, nil
}

// Equal returns true if both Addrs have the same netip.Prefix value.
func (a Addr) Equal(x Addr) bool {
	return a.Prefix == x.Prefix
}

func (a Addr) PeerEqual(x Addr) bool {
	return a.Peer == x.Peer
}
