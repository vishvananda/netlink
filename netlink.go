// Package netlink provides a simple library for netlink. Netlink is
// the interface a user-space program in linux uses to communicate with
// the kernel. It can be used to add and remove interfaces, set up ip
// addresses and routes, and confiugre ipsec. Netlink communication
// requires elevated privileges, so in most cases this code needs to
// be run as root. In addition to dealing with netlink primitives, the
// library attempts to provide an high-level interface that is loosly
// modeled on the iproute2 command line interface.
package netlink

import (
	"net"
	"syscall"
)

const (
	// Family type definitions
	FAMILY_ALL = syscall.AF_UNSPEC
	FAMILY_V4  = syscall.AF_INET
	FAMILY_V6  = syscall.AF_INET6
)

// GetIPFamily returns the family type of a net.IP.
func GetIPFamily(ip net.IP) int {
	if len(ip) <= net.IPv4len {
		return FAMILY_V4
	}
	if ip.To4() != nil {
		return FAMILY_V4
	}
	return FAMILY_V6
}

// ParseIPNet parses a string in ip/net format and returns a net.IPNet.
// This is valuable because addresses in netlink are often IPNets and
// ParseCIDR returns an IPNet with the IP part set to the base IP of the
// range.
func ParseIPNet(s string) (*net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return &net.IPNet{ip, ipNet.Mask}, nil
}

// NewIPNet generates an IPNet from an ip address using a netmask of 32.
func NewIPNet(ip net.IP) *net.IPNet {
	return &net.IPNet{ip, net.CIDRMask(32, 32)}
}
