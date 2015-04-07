package netlink

import (
	"net"

	"git.spinoff.ovh.net/librouter/netlink/nl"
)

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
	Id       int
	Link     int
	Local    net.IP
	Group    net.IP
	TTL      int
	TOS      int
	Learning bool
	Proxy    bool
	RSC      bool
	L2miss   bool
	L3miss   bool
	NoAge    bool
	Age      int
	Limit    int
	Port     int
	PortLow  int
	PortHigh int
}

// Attrs implementation.
func (vxlan *Vxlan) Attrs() *LinkAttrs {
	return &vxlan.LinkAttrs
}

// Type implementation fro Vxlan.
func (vxlan *Vxlan) Type() string {
	return "vxlan"
}

// BondMode type
type BondMode int

// Possible BondMode
const (
	BOND_MODE_BALANCE_RR BondMode = iota
	BOND_MODE_ACTIVE_BACKUP
	BOND_MODE_BALANCE_XOR
	BOND_MODE_BROADCAST
	BOND_MODE_802_3AD
	BOND_MODE_BALANCE_TLB
	BOND_MODE_BALANCE_ALB
)

// BondArpValidate type
type BondArpValidate int

// Possible BondArpValidate value
const (
	BOND_ARP_VALIDATE_NONE BondArpValidate = iota
	BOND_ARP_VALIDATE_ACTIVE
	BOND_ARP_VALIDATE_BACKUP
	BOND_ARP_VALIDATE_ALL
)

// BondPrimaryReselect type
type BondPrimaryReselect int

// Possible BondPrimaryReselect value
const (
	BOND_PRIMARY_RESELECT_ALWAYS BondPrimaryReselect = iota
	BOND_PRIMARY_RESELECT_BETTER
	BOND_PRIMARY_RESELECT_FAILURE
)

// BondArpAllTargets type
type BondArpAllTargets int

// Possible BondArpAllTargets value
const (
	BOND_ARP_ALL_TARGETS_ANY BondArpAllTargets = iota
	BOND_ARP_ALL_TARGETS_ALL
)

// BondFailOverMac type
type BondFailOverMac int

// Possible BondFailOverMac value
const (
	BOND_FAIL_OVER_MAC_NONE BondFailOverMac = iota
	BOND_FAIL_OVER_MAC_ACTIVE
	BOND_FAIL_OVER_MAC_FOLLOW
)

// BondXmitHashPolicy type
type BondXmitHashPolicy int

// Possible BondXmitHashPolicy value
const (
	BOND_XMIT_HASH_POLICY_LAYER2 BondXmitHashPolicy = iota
	BOND_XMIT_HASH_POLICY_LAYER3_4
	BOND_XMIT_HASH_POLICY_LAYER2_3
	BOND_XMIT_HASH_POLICY_ENCAP2_3
	BOND_XMIT_HASH_POLICY_ENCAP3_4
)

// BondLacpRate type
type BondLacpRate int

// Possible BondLacpRate value
const (
	BOND_LACP_RATE_SLOW BondLacpRate = iota
	BOND_LACP_RATE_FAST
)

// BondAdSelect type
type BondAdSelect int

// Possible BondAdSelect value
const (
	BOND_AD_SELECT_STABLE BondAdSelect = iota
	BOND_AD_SELECT_BANDWIDTH
	BOND_AD_SELECT_COUNT
)

// Bond representation
type Bond struct {
	LinkAttrs
	Mode            BondMode
	ActiveSlave     int
	Miimon          int
	UpDelay         int
	DownDelay       int
	UseCarrier      int
	ArpInterval     int
	ArpIpTargets    []net.IP
	ArpValidate     BondArpValidate
	ArpAllTargets   BondArpAllTargets
	Primary         int
	PrimaryReselect BondPrimaryReselect
	FailOverMac     BondFailOverMac
	XmitHashPolicy  BondXmitHashPolicy
	ResendIgmp      int
	NumPeerNotif    int
	AllSlavesActive int
	MinLinks        int
	LpInterval      int
	PackersPerSlave int
	LacpRate        BondLacpRate
	AdSelect        BondAdSelect
	// looking at iproute tool AdInfo can only be retrived. It can't be set.
	AdInfo struct {
		AggregatorId int
		NumPorts     int
		ActorKey     int
		PartnerKey   int
		PartnerMac   [nl.ETH_ALEN]int
	}

	FlagMask uint64
}

// Flag mask for bond options. Bond.Flagmask must be set to on for option to work.
const (
	BOND_MODE_MASK uint64 = 1 << (1 + iota)
	BOND_ACTIVE_SLAVE_MASK
	BOND_MIIMON_MASK
	BOND_UPDELAY_MASK
	BOND_DOWNDELAY_MASK
	BOND_USE_CARRIER_MASK
	BOND_ARP_INTERVAL_MASK
	BOND_ARP_VALIDATE_MASK
	BOND_ARP_ALL_TARGETS_MASK
	BOND_PRIMARY_MASK
	BOND_PRIMARY_RESELECT_MASK
	BOND_FAIL_OVER_MAC_MASK
	BOND_XMIT_HASH_POLICY_MASK
	BOND_RESEND_IGMP_MASK
	BOND_NUM_PEER_NOTIF_MASK
	BOND_ALL_SLAVES_ACTIVE_MASK
	BOND_MIN_LINKS_MASK
	BOND_LP_INTERVAL_MASK
	BOND_PACKETS_PER_SLAVE_MASK
	BOND_LACP_RATE_MASK
	BOND_AD_SELECT_MASK
)

// Attrs implementation.
func (bond *Bond) Attrs() *LinkAttrs {
	return &bond.LinkAttrs
}

// Type implementation fro Vxlan.
func (bond *Bond) Type() string {
	return "bond"
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
