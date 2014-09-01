package netlink

import (
	"net"
)

// Link represents a link device from netlink. The Type is a string
// representing the type of device. Currently supported types include:
// "dummy", "bridge", "vlan", "macvlan", and "veth". Some of the
// members of Link only apply to some types of link devices.
type Link struct {
	Type         string
	Index        int
	MTU          int
	Name         string
	HardwareAddr net.HardwareAddr
	Flags        net.Flags
	Parent       *Link  // vlan and macvlan
	Master       *Link  // bridge only
	VlanId       int    // vlan only
	PeerName     string // veth on create only
}

// iproute2 supported devices;
// vlan | veth | vcan | dummy | ifb | macvlan | macvtap |
// can | bridge | bond | ipoib | ip6tnl | ipip | sit |
// vxlan | gre | gretap | ip6gre | ip6gretap | vti
