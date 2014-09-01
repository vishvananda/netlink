package netlink

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

const (
	DEFAULT_CHANGE = 0xFFFFFFFF
)

const (
	IFLA_INFO_UNSPEC = iota
	IFLA_INFO_KIND   = iota
	IFLA_INFO_DATA   = iota
	IFLA_INFO_XSTATS = iota
	IFLA_INFO_MAX    = IFLA_INFO_XSTATS
)

const (
	IFLA_VLAN_UNSPEC      = iota
	IFLA_VLAN_ID          = iota
	IFLA_VLAN_FLAGS       = iota
	IFLA_VLAN_EGRESS_QOS  = iota
	IFLA_VLAN_INGRESS_QOS = iota
	IFLA_VLAN_PROTOCOL    = iota
	IFLA_VLAN_MAX         = IFLA_VLAN_PROTOCOL
)

const (
	VETH_INFO_UNSPEC = iota
	VETH_INFO_PEER   = iota
	VETH_INFO_MAX    = VETH_INFO_PEER
)

const (
	// not defined in syscall
	IFLA_NET_NS_FD = 28
)

func ensureIndex(link *Link) {
	if link != nil && link.Index == 0 {
		newlink, _ := LinkByName(link.Name)
		if newlink != nil {
			link.Index = newlink.Index
		}
	}
}

// LinkSetUp enables the link device.
// Equivalent to: `ip link set $link up`
func LinkSetUp(link *Link) error {
	ensureIndex(link)
	req := newNetlinkRequest(syscall.RTM_NEWLINK, syscall.NLM_F_ACK)

	msg := newIfInfomsg(syscall.AF_UNSPEC)
	msg.Change = syscall.IFF_UP
	msg.Flags = syscall.IFF_UP
	msg.Index = int32(link.Index)
	req.AddData(msg)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LinkSetUp disables link device.
// Equivalent to: `ip link set $link down`
func LinkSetDown(link *Link) error {
	ensureIndex(link)
	req := newNetlinkRequest(syscall.RTM_NEWLINK, syscall.NLM_F_ACK)

	msg := newIfInfomsg(syscall.AF_UNSPEC)
	msg.Change = syscall.IFF_UP
	msg.Flags = 0 & ^syscall.IFF_UP
	msg.Index = int32(link.Index)
	req.AddData(msg)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LinkSetMTU sets the mtu of the link device.
// Equivalent to: `ip link set $link mtu $mtu`
func LinkSetMTU(link *Link, mtu int) error {
	ensureIndex(link)
	req := newNetlinkRequest(syscall.RTM_SETLINK, syscall.NLM_F_ACK)

	msg := newIfInfomsg(syscall.AF_UNSPEC)
	msg.Type = syscall.RTM_SETLINK
	msg.Flags = syscall.NLM_F_REQUEST
	msg.Index = int32(link.Index)
	msg.Change = DEFAULT_CHANGE
	req.AddData(msg)

	var (
		b      = make([]byte, 4)
		native = nativeEndian()
	)
	native.PutUint32(b, uint32(mtu))

	data := newRtAttr(syscall.IFLA_MTU, b)
	req.AddData(data)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LinkSetMTU sets the master of the link device. This only works
// for bridges.
// Equivalent to: `ip link set $link master $master`
func LinkSetMaster(link *Link, master *Link) error {
	ensureIndex(link)
	ensureIndex(master)
	req := newNetlinkRequest(syscall.RTM_SETLINK, syscall.NLM_F_ACK)

	msg := newIfInfomsg(syscall.AF_UNSPEC)
	msg.Type = syscall.RTM_SETLINK
	msg.Flags = syscall.NLM_F_REQUEST
	msg.Index = int32(link.Index)
	msg.Change = DEFAULT_CHANGE
	req.AddData(msg)

	var (
		b      = make([]byte, 4)
		native = nativeEndian()
		index  = 0
	)

	if master != nil {
		index = master.Index
	}

	native.PutUint32(b, uint32(index))

	data := newRtAttr(syscall.IFLA_MASTER, b)
	req.AddData(data)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LinkSetNsPid puts the device into a new network namespace. The
// pid must be a pid of a running process.
// Equivalent to: `ip link set $link netns $pid`
func LinkSetNsPid(link *Link, nspid int) error {
	req := newNetlinkRequest(syscall.RTM_SETLINK, syscall.NLM_F_ACK)

	msg := newIfInfomsg(syscall.AF_UNSPEC)
	msg.Type = syscall.RTM_SETLINK
	msg.Flags = syscall.NLM_F_REQUEST
	msg.Index = int32(link.Index)
	msg.Change = DEFAULT_CHANGE
	req.AddData(msg)

	var (
		b      = make([]byte, 4)
		native = nativeEndian()
	)
	native.PutUint32(b, uint32(nspid))

	data := newRtAttr(syscall.IFLA_NET_NS_PID, b)
	req.AddData(data)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LinkSetNsPid puts the device into a new network namespace. The
// fd must be an open file descriptor to a network namespace.
// Similar to: `ip link set $link netns $ns`
func LinkSetNsFd(link *Link, fd int) error {
	req := newNetlinkRequest(syscall.RTM_SETLINK, syscall.NLM_F_ACK)

	msg := newIfInfomsg(syscall.AF_UNSPEC)
	msg.Type = syscall.RTM_SETLINK
	msg.Flags = syscall.NLM_F_REQUEST
	msg.Index = int32(link.Index)
	msg.Change = DEFAULT_CHANGE
	req.AddData(msg)

	var (
		b      = make([]byte, 4)
		native = nativeEndian()
	)
	native.PutUint32(b, uint32(fd))

	data := newRtAttr(IFLA_NET_NS_FD, b)
	req.AddData(data)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

func newIfInfomsgChild(parent *RtAttr, family int) *IfInfomsg {
	msg := newIfInfomsg(family)
	parent.children = append(parent.children, msg)
	return msg
}

// LinkAdd adds a new link device. The type and features of the device
// are taken fromt the parameters in the link object.
// Equivalent to: `ip link add $link`
func LinkAdd(link *Link) error {
	// TODO: set mtu and hardware address
	// TODO: support extra data for macvlan

	if link.Type == "" || link.Name == "" {
		return fmt.Errorf("Neither link.Name nor link.Type can be empty!")
	}

	req := newNetlinkRequest(syscall.RTM_NEWLINK, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)

	msg := newIfInfomsg(syscall.AF_UNSPEC)
	req.AddData(msg)

	native := nativeEndian()

	if link.Parent != nil {
		ensureIndex(link.Parent)
		b := make([]byte, 4)
		native.PutUint32(b, uint32(link.Parent.Index))
		data := newRtAttr(syscall.IFLA_LINK, b)
		req.AddData(data)
	}

	nameData := newRtAttr(syscall.IFLA_IFNAME, zeroTerminated(link.Name))
	req.AddData(nameData)

	linkInfo := newRtAttr(syscall.IFLA_LINKINFO, nil)
	newRtAttrChild(linkInfo, IFLA_INFO_KIND, nonZeroTerminated(link.Type))

	if link.Type == "vlan" {
		b := make([]byte, 2)
		native.PutUint16(b, uint16(link.VlanId))
		data := newRtAttrChild(linkInfo, IFLA_INFO_DATA, nil)
		newRtAttrChild(data, IFLA_VLAN_ID, b)
	} else if link.Type == "veth" {
		data := newRtAttrChild(linkInfo, IFLA_INFO_DATA, nil)
		peer := newRtAttrChild(data, VETH_INFO_PEER, nil)
		newIfInfomsgChild(peer, syscall.AF_UNSPEC)
		newRtAttrChild(peer, syscall.IFLA_IFNAME, zeroTerminated(link.PeerName))
	}

	req.AddData(linkInfo)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	if err != nil {
		return err
	}

	// can't set master during create, so set it afterwards
	if link.Master != nil {
		return LinkSetMaster(link, link.Master)
	}
	return nil
}

// LinkAdd adds a new link device. Either Index or Name must be set in
// the link object for it to be deleted. The other values are ignored.
// Equivalent to: `ip link del $link`
func LinkDel(link *Link) error {
	ensureIndex(link)

	req := newNetlinkRequest(syscall.RTM_DELLINK, syscall.NLM_F_ACK)

	msg := newIfInfomsg(syscall.AF_UNSPEC)
	msg.Index = int32(link.Index)
	req.AddData(msg)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LikByName finds a link by name and returns a pointer to the object.
func LinkByName(name string) (*Link, error) {
	links, err := LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		if link.Name == name {
			return &link, nil
		}
	}
	return nil, fmt.Errorf("Link %s not found", name)
}

// LikByName finds a link by index and returns a pointer to the object.
func LinkByIndex(index int) (*Link, error) {
	links, err := LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		if link.Index == index {
			return &link, nil
		}
	}
	return nil, fmt.Errorf("Link with index %d not found", index)
}

// LinkList gets a list of link devices.
// Equivalent to: `ip link show`
func LinkList() ([]Link, error) {
	// NOTE(vish): This duplicates functionality in net/iface_linux.go, but we need
	//             to get the message ourselves to parse link type.
	req := newNetlinkRequest(syscall.RTM_GETLINK, syscall.NLM_F_DUMP)

	msg := newIfInfomsg(syscall.AF_UNSPEC)
	req.AddData(msg)

	msgs, err := req.Execute(syscall.NETLINK_ROUTE, syscall.RTM_NEWLINK)
	if err != nil {
		return nil, err
	}

	native := nativeEndian()
	res := make([]Link, 0)

	for _, m := range msgs {
		msg := DeserializeIfInfomsg(m)

		attrs, err := parseRouteAttr(m[msg.Len():])
		if err != nil {
			return nil, err
		}

		link := Link{Index: int(msg.Index), Flags: linkFlags(msg.Flags)}
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.IFLA_LINKINFO:
				infos, err := parseRouteAttr(attr.Value)
				if err != nil {
					return nil, err
				}
				for _, info := range infos {
					switch info.Attr.Type {
					case IFLA_INFO_KIND:
						link.Type = string(info.Value[:len(info.Value)-1])
					case IFLA_INFO_DATA:
						data, err := parseRouteAttr(info.Value)
						if err != nil {
							return nil, err
						}
						switch link.Type {
						case "vlan":
							parseVlanData(&link, data, native)
						}
					}
				}
			case syscall.IFLA_ADDRESS:
				var nonzero bool
				for _, b := range attr.Value {
					if b != 0 {
						nonzero = true
					}
				}
				if nonzero {
					link.HardwareAddr = attr.Value[:]
				}
			case syscall.IFLA_IFNAME:
				link.Name = string(attr.Value[:len(attr.Value)-1])
			case syscall.IFLA_MTU:
				link.MTU = int(native.Uint32(attr.Value[0:4]))
			case syscall.IFLA_LINK:
				link.Parent = &Link{Index: int(native.Uint32(attr.Value[0:4]))}
			case syscall.IFLA_MASTER:
				link.Master = &Link{Index: int(native.Uint32(attr.Value[0:4]))}
			}
		}
		res = append(res, link)
	}

	return res, nil
}

func parseVlanData(link *Link, data []syscall.NetlinkRouteAttr, native binary.ByteOrder) {
	for _, datum := range data {
		switch datum.Attr.Type {
		case IFLA_VLAN_ID:
			link.VlanId = int(native.Uint16(datum.Value[0:2]))
		}
	}
}

// copied from pkg/net_linux.go
func linkFlags(rawFlags uint32) net.Flags {
	var f net.Flags
	if rawFlags&syscall.IFF_UP != 0 {
		f |= net.FlagUp
	}
	if rawFlags&syscall.IFF_BROADCAST != 0 {
		f |= net.FlagBroadcast
	}
	if rawFlags&syscall.IFF_LOOPBACK != 0 {
		f |= net.FlagLoopback
	}
	if rawFlags&syscall.IFF_POINTOPOINT != 0 {
		f |= net.FlagPointToPoint
	}
	if rawFlags&syscall.IFF_MULTICAST != 0 {
		f |= net.FlagMulticast
	}
	return f
}
