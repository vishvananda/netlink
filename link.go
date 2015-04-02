package netlink

import "net"

// Link represents a link device from netlink. Shared link attributes
// like name may be retrieved using the Attrs() method. Unique data
// can be retrieved by casting the object to the proper type.
type Link interface {
	Attrs() *LinkAttrs
	Type() string
}

// Possible types of Namespace in LinkAttrs struct
type (
	// NsPid is process id running in namespace.
	NsPid int
	// NsFd is open file descriptor for namespace.
	NsFd int
)

// LinkAttrs represents data shared by most link types
type LinkAttrs struct {
	Index        int
	MTU          int
	TxQLen       int64 // Transmit Queue Length
	Name         string
	HardwareAddr net.HardwareAddr
	Flags        net.Flags
	ParentIndex  int         // index of the parent link device
	MasterIndex  int         // must be the index of a bridge
	Namespace    interface{} // nil | NsPid | NsFd
}

// NewLinkAttrs returns LinkAttrs structure filled with default values
func NewLinkAttrs() LinkAttrs {
	return LinkAttrs{
		TxQLen: -1,
	}
}

// Device links cannot be created via netlink. These links
// are links created by udev like 'lo' and 'etho0'
type Device struct {
	LinkAttrs
}

// Attrs implementation.
func (device *Device) Attrs() *LinkAttrs {
	return &device.LinkAttrs
}

// Type implementation fro Device.
func (device *Device) Type() string {
	return "device"
}

// Dummy links are dummy ethernet devices
type Dummy struct {
	LinkAttrs
}

// Attrs implementation.
func (dummy *Dummy) Attrs() *LinkAttrs {
	return &dummy.LinkAttrs
}

// Type implementation fro Dummy.
func (dummy *Dummy) Type() string {
	return "dummy"
}

// Bridge links are simple linux bridges
type Bridge struct {
	LinkAttrs
}

// Attrs implementation.
func (bridge *Bridge) Attrs() *LinkAttrs {
	return &bridge.LinkAttrs
}

// Type implementation fro Bridge.
func (bridge *Bridge) Type() string {
	return "bridge"
}

// Vlan links have ParentIndex set in their Attrs()
type Vlan struct {
	LinkAttrs
	VlanId int
}

// Attrs implementation.
func (vlan *Vlan) Attrs() *LinkAttrs {
	return &vlan.LinkAttrs
}

// Type implementation fro vlan.
func (vlan *Vlan) Type() string {
	return "vlan"
}

// MacvlanMode type
type MacvlanMode uint16

// MacvlanMode possible values
const (
	MACVLAN_MODE_DEFAULT MacvlanMode = iota
	MACVLAN_MODE_PRIVATE
	MACVLAN_MODE_VEPA
	MACVLAN_MODE_BRIDGE
	MACVLAN_MODE_PASSTHRU
	MACVLAN_MODE_SOURCE
)

// Macvlan links have ParentIndex set in their Attrs()
type Macvlan struct {
	LinkAttrs
	Mode MacvlanMode
}

// Attrs implementation.
func (macvlan *Macvlan) Attrs() *LinkAttrs {
	return &macvlan.LinkAttrs
}

// Type implementation fro Macvlan.
func (macvlan *Macvlan) Type() string {
	return "macvlan"
}

// Veth devices must specify PeerName on create
type Veth struct {
	LinkAttrs
	PeerName string // veth on create only
}

// Attrs implementation.
func (veth *Veth) Attrs() *LinkAttrs {
	return &veth.LinkAttrs
}

// Type implementation fro Veth.
func (veth *Veth) Type() string {
	return "veth"
}

// Generic links represent types that are not currently understood
// by this netlink library.
type Generic struct {
	LinkAttrs
	LinkType string
}

// Attrs implementation.
func (generic *Generic) Attrs() *LinkAttrs {
	return &generic.LinkAttrs
}

// Type implementation fro Generic.
func (generic *Generic) Type() string {
	return generic.LinkType
}

// Vxlan representation
type Vxlan struct {
	LinkAttrs
	VxlanId      int
	VtepDevIndex int
	SrcAddr      net.IP
	Group        net.IP
	TTL          int
	TOS          int
	Learning     bool
	Proxy        bool
	RSC          bool
	L2miss       bool
	L3miss       bool
	NoAge        bool
	Age          int
	Limit        int
	Port         int
	PortLow      int
	PortHigh     int
}

// Attrs implementation.
func (vxlan *Vxlan) Attrs() *LinkAttrs {
	return &vxlan.LinkAttrs
}

// Type implementation fro Vxlan.
func (vxlan *Vxlan) Type() string {
	return "vxlan"
}

// IPVlanMode type
type IPVlanMode uint16

// Possible IPVlanMode
const (
	IPVLAN_MODE_L2 IPVlanMode = iota
	IPVLAN_MODE_L3
	IPVLAN_MODE_MAX
)

// IPVlan representation
type IPVlan struct {
	LinkAttrs
	Mode IPVlanMode
}

// Attrs implementation.
func (ipvlan *IPVlan) Attrs() *LinkAttrs {
	return &ipvlan.LinkAttrs
}

// Type implementation fro IPVlan.
func (ipvlan *IPVlan) Type() string {
	return "ipvlan"
}

// iproute2 supported devices;
// vlan | veth | vcan | dummy | ifb | macvlan | macvtap |
// bridge | bond | ipoib | ip6tnl | ipip | sit | vxlan |
// gre | gretap | ip6gre | ip6gretap | vti | nlmon |
// bond_slave | ipvlan
