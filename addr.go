package netlink

import (
	"fmt"
	"net"
	"strings"
)

// Addr represents an IP address from netlink. Netlink ip addresses
// include a mask, so it stores the address as a net.IPNet.
type Addr struct {
	*net.IPNet
	Label     string
	Broadcast *net.IPNet
	Anycast   *net.IPNet
	Multicast *net.IPNet
	Local     *net.IPNet
	Flags     int
}

// String returns $ip/$netmask $label
func (a Addr) String() string {
	return fmt.Sprintf("%s %s", a.IPNet, a.Label)
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
	return &Addr{IPNet: m, Label: label}, nil
}

// ParseAddrWithDefaultNetmask parses the string representation of an address in the
// form $ip/$netmask $label where the /$netmask and the label portion is optional.
// If the $netmask dosen't occur then default one is used (/32 for IPv4 and /128 for IPv6)
func ParseAddrWithDefaultNetmask(s string) (*Addr, error) {
	label := ""
	parts := strings.SplitN(s, " ", 1)
	if len(parts) > 1 {
		s, label = parts[0], parts[1]
	}
	if ip := net.ParseIP(s); ip != nil {
		return &Addr{IPNet: NewIPNet(ip), Label: label}, nil
	}
	m, err := ParseIPNet(s)
	if err != nil {
		return nil, err
	}
	return &Addr{IPNet: m, Label: label}, nil
}

// NewAddr returns new Addr with no label.
func NewAddr(ipnet *net.IPNet) *Addr {
	return &Addr{IPNet: ipnet}
}

// Equal returns true if both Addrs have the same net.IPNet value.
func (a Addr) Equal(x Addr) bool {
	sizea, _ := a.Mask.Size()
	sizeb, _ := x.Mask.Size()
	// ignore label for comparison
	return a.IP.Equal(x.IP) && sizea == sizeb
}
