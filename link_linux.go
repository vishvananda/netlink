package netlink

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink/nl"
)

func ensureIndex(link *LinkAttrs) {
	if link != nil && link.Index == 0 {
		newlink, _ := LinkByName(link.Name)
		if newlink != nil {
			link.Index = newlink.Attrs().Index
		}
	}
}

// LinkSetUp enables the link device.
// Equivalent to: `ip link set $link up`
func LinkSetUp(link Link) error {
	base := link.Attrs()
	ensureIndex(base)
	req := nl.NewNetlinkRequest(syscall.RTM_NEWLINK, syscall.NLM_F_ACK)

	msg := nl.NewIfInfomsg(syscall.AF_UNSPEC)
	msg.Change = syscall.IFF_UP
	msg.Flags = syscall.IFF_UP
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LinkSetUp disables link device.
// Equivalent to: `ip link set $link down`
func LinkSetDown(link Link) error {
	base := link.Attrs()
	ensureIndex(base)
	req := nl.NewNetlinkRequest(syscall.RTM_NEWLINK, syscall.NLM_F_ACK)

	msg := nl.NewIfInfomsg(syscall.AF_UNSPEC)
	msg.Change = syscall.IFF_UP
	msg.Flags = 0 & ^syscall.IFF_UP
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LinkSetMTU sets the mtu of the link device.
// Equivalent to: `ip link set $link mtu $mtu`
func LinkSetMTU(link Link, mtu int) error {
	base := link.Attrs()
	ensureIndex(base)
	req := nl.NewNetlinkRequest(syscall.RTM_SETLINK, syscall.NLM_F_ACK)

	msg := nl.NewIfInfomsg(syscall.AF_UNSPEC)
	msg.Type = syscall.RTM_SETLINK
	msg.Flags = syscall.NLM_F_REQUEST
	msg.Index = int32(base.Index)
	msg.Change = nl.DEFAULT_CHANGE
	req.AddData(msg)

	var (
		b      = make([]byte, 4)
		native = nl.NativeEndian()
	)
	native.PutUint32(b, uint32(mtu))

	data := nl.NewRtAttr(syscall.IFLA_MTU, b)
	req.AddData(data)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LinkSetMaster sets the master of the link device.
// Equivalent to: `ip link set $link master $master`
func LinkSetMaster(link Link, master *Bridge) error {
	index := 0
	if master != nil {
		masterBase := master.Attrs()
		ensureIndex(masterBase)
		index = masterBase.Index
	}
	return LinkSetMasterByIndex(link, index)
}

// LinkSetMasterByIndex sets the master of the link device.
// Equivalent to: `ip link set $link master $master`
func LinkSetMasterByIndex(link Link, masterIndex int) error {
	base := link.Attrs()
	ensureIndex(base)
	req := nl.NewNetlinkRequest(syscall.RTM_SETLINK, syscall.NLM_F_ACK)

	msg := nl.NewIfInfomsg(syscall.AF_UNSPEC)
	msg.Type = syscall.RTM_SETLINK
	msg.Flags = syscall.NLM_F_REQUEST
	msg.Index = int32(base.Index)
	msg.Change = nl.DEFAULT_CHANGE
	req.AddData(msg)

	var (
		b      = make([]byte, 4)
		native = nl.NativeEndian()
	)

	native.PutUint32(b, uint32(masterIndex))

	data := nl.NewRtAttr(syscall.IFLA_MASTER, b)
	req.AddData(data)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LinkSetNsPid puts the device into a new network namespace. The
// pid must be a pid of a running process.
// Equivalent to: `ip link set $link netns $pid`
func LinkSetNsPid(link Link, nspid int) error {
	base := link.Attrs()
	ensureIndex(base)
	req := nl.NewNetlinkRequest(syscall.RTM_SETLINK, syscall.NLM_F_ACK)

	msg := nl.NewIfInfomsg(syscall.AF_UNSPEC)
	msg.Type = syscall.RTM_SETLINK
	msg.Flags = syscall.NLM_F_REQUEST
	msg.Index = int32(base.Index)
	msg.Change = nl.DEFAULT_CHANGE
	req.AddData(msg)

	var (
		b      = make([]byte, 4)
		native = nl.NativeEndian()
	)
	native.PutUint32(b, uint32(nspid))

	data := nl.NewRtAttr(syscall.IFLA_NET_NS_PID, b)
	req.AddData(data)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LinkSetNsPid puts the device into a new network namespace. The
// fd must be an open file descriptor to a network namespace.
// Similar to: `ip link set $link netns $ns`
func LinkSetNsFd(link Link, fd int) error {
	base := link.Attrs()
	ensureIndex(base)
	req := nl.NewNetlinkRequest(syscall.RTM_SETLINK, syscall.NLM_F_ACK)

	msg := nl.NewIfInfomsg(syscall.AF_UNSPEC)
	msg.Type = syscall.RTM_SETLINK
	msg.Flags = syscall.NLM_F_REQUEST
	msg.Index = int32(base.Index)
	msg.Change = nl.DEFAULT_CHANGE
	req.AddData(msg)

	var (
		b      = make([]byte, 4)
		native = nl.NativeEndian()
	)
	native.PutUint32(b, uint32(fd))

	data := nl.NewRtAttr(nl.IFLA_NET_NS_FD, b)
	req.AddData(data)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LinkAdd adds a new link device. The type and features of the device
// are taken fromt the parameters in the link object.
// Equivalent to: `ip link add $link`
func LinkAdd(link Link) error {
	// TODO: set mtu and hardware address
	// TODO: support extra data for macvlan
	base := link.Attrs()

	if base.Name == "" {
		return fmt.Errorf("LinkAttrs.Name cannot be empty!")
	}

	req := nl.NewNetlinkRequest(syscall.RTM_NEWLINK, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)

	msg := nl.NewIfInfomsg(syscall.AF_UNSPEC)
	req.AddData(msg)

	native := nl.NativeEndian()

	if base.ParentIndex != 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(base.ParentIndex))
		data := nl.NewRtAttr(syscall.IFLA_LINK, b)
		req.AddData(data)
	}

	nameData := nl.NewRtAttr(syscall.IFLA_IFNAME, nl.ZeroTerminated(base.Name))
	req.AddData(nameData)

	linkInfo := nl.NewRtAttr(syscall.IFLA_LINKINFO, nil)
	nl.NewRtAttrChild(linkInfo, nl.IFLA_INFO_KIND, nl.NonZeroTerminated(link.Type()))

	if vlan, ok := link.(*Vlan); ok {
		b := make([]byte, 2)
		native.PutUint16(b, uint16(vlan.VlanId))
		data := nl.NewRtAttrChild(linkInfo, nl.IFLA_INFO_DATA, nil)
		nl.NewRtAttrChild(data, nl.IFLA_VLAN_ID, b)
	} else if veth, ok := link.(*Veth); ok {
		data := nl.NewRtAttrChild(linkInfo, nl.IFLA_INFO_DATA, nil)
		peer := nl.NewRtAttrChild(data, nl.VETH_INFO_PEER, nil)
		nl.NewIfInfomsgChild(peer, syscall.AF_UNSPEC)
		nl.NewRtAttrChild(peer, syscall.IFLA_IFNAME, nl.ZeroTerminated(veth.PeerName))
	}

	req.AddData(linkInfo)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	if err != nil {
		return err
	}

	ensureIndex(base)

	// can't set master during create, so set it afterwards
	if base.MasterIndex != 0 {
		// TODO: verify MasterIndex is actually a bridge?
		return LinkSetMasterByIndex(link, base.MasterIndex)
	}
	return nil
}

// LinkAdd adds a new link device. Either Index or Name must be set in
// the link object for it to be deleted. The other values are ignored.
// Equivalent to: `ip link del $link`
func LinkDel(link Link) error {
	base := link.Attrs()

	ensureIndex(base)

	req := nl.NewNetlinkRequest(syscall.RTM_DELLINK, syscall.NLM_F_ACK)

	msg := nl.NewIfInfomsg(syscall.AF_UNSPEC)
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// LikByName finds a link by name and returns a pointer to the object.
func LinkByName(name string) (Link, error) {
	links, err := LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		base := link.Attrs()
		if base.Name == name {
			return link, nil
		}
	}
	return nil, fmt.Errorf("Link %s not found", name)
}

// LikByName finds a link by index and returns a pointer to the object.
func LinkByIndex(index int) (Link, error) {
	links, err := LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		base := link.Attrs()
		if base.Index == index {
			return link, nil
		}
	}
	return nil, fmt.Errorf("Link with index %d not found", index)
}

// LinkList gets a list of link devices.
// Equivalent to: `ip link show`
func LinkList() ([]Link, error) {
	// NOTE(vish): This duplicates functionality in net/iface_linux.go, but we need
	//             to get the message ourselves to parse link type.
	req := nl.NewNetlinkRequest(syscall.RTM_GETLINK, syscall.NLM_F_DUMP)

	msg := nl.NewIfInfomsg(syscall.AF_UNSPEC)
	req.AddData(msg)

	msgs, err := req.Execute(syscall.NETLINK_ROUTE, syscall.RTM_NEWLINK)
	if err != nil {
		return nil, err
	}

	native := nl.NativeEndian()
	res := make([]Link, 0)

	for _, m := range msgs {
		msg := nl.DeserializeIfInfomsg(m)

		attrs, err := nl.ParseRouteAttr(m[msg.Len():])
		if err != nil {
			return nil, err
		}

		base := LinkAttrs{Index: int(msg.Index), Flags: linkFlags(msg.Flags)}
		var link Link
		linkType := ""
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.IFLA_LINKINFO:
				infos, err := nl.ParseRouteAttr(attr.Value)
				if err != nil {
					return nil, err
				}
				for _, info := range infos {
					switch info.Attr.Type {
					case nl.IFLA_INFO_KIND:
						linkType = string(info.Value[:len(info.Value)-1])
						switch linkType {
						case "dummy":
							link = &Dummy{}
						case "bridge":
							link = &Bridge{}
						case "vlan":
							link = &Vlan{}
						case "veth":
							link = &Veth{}
						default:
							link = &Generic{LinkType: linkType}
						}
					case nl.IFLA_INFO_DATA:
						data, err := nl.ParseRouteAttr(info.Value)
						if err != nil {
							return nil, err
						}
						switch linkType {
						case "vlan":
							parseVlanData(link, data, native)
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
					base.HardwareAddr = attr.Value[:]
				}
			case syscall.IFLA_IFNAME:
				base.Name = string(attr.Value[:len(attr.Value)-1])
			case syscall.IFLA_MTU:
				base.MTU = int(native.Uint32(attr.Value[0:4]))
			case syscall.IFLA_LINK:
				base.ParentIndex = int(native.Uint32(attr.Value[0:4]))
			case syscall.IFLA_MASTER:
				base.MasterIndex = int(native.Uint32(attr.Value[0:4]))
			}
		}
		// Links that don't have IFLA_INFO_KIND are hardware devices
		if link == nil {
			link = &Device{}
		}
		*link.Attrs() = base
		res = append(res, link)
	}

	return res, nil
}

func parseVlanData(link Link, data []syscall.NetlinkRouteAttr, native binary.ByteOrder) {
	vlan, _ := link.(*Vlan)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.IFLA_VLAN_ID:
			vlan.VlanId = int(native.Uint16(datum.Value[0:2]))
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
