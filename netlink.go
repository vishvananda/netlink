// Package netlink provides a simple library for netlink. Netlink is
// the interface a user-space program in linux uses to communicate with
// the kernel. It can be used to add and remove interfaces, set up ip
// addresses and routes, and confiugre ipsec. Netlink communication
// requires elevated privileges, so in most cases this code needs to
// be run as root. The low level primitives for netlink are contained
// in the nl subpackage. This package attempts to provide a high-level
// interface that is loosly modeled on the iproute2 cli.
package netlink

import (
	"errors"
	"net/netip"
)

var (
	// ErrNotImplemented is returned when a requested feature is not implemented.
	ErrNotImplemented = errors.New("not implemented")
)

// ParsePrefix parses a string in ip/net format and returns a netip.Prefix.
// This is valuable because addresses in netlink are often IPNets and
// ParseCIDR returns an IPNet with the IP part set to the base IP of the
// range.
func ParsePrefix(s string) (netip.Prefix, error) {
	return netip.ParsePrefix(s)
}

// NewPrefix generates a Prefix from an ip address using a netmask of 32 or 128.
func NewPrefix(ip netip.Addr) netip.Prefix {
	return netip.PrefixFrom(ip, ip.BitLen())
}

var (
	v4zero = netip.MustParseAddr("0.0.0.0")
	v6zero = netip.MustParseAddr("::0")
)
