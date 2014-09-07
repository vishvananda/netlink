package netlink

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

type IfAddrmsg struct {
	syscall.IfAddrmsg
}

func newIfAddrmsg(family int) *IfAddrmsg {
	return &IfAddrmsg{
		IfAddrmsg: syscall.IfAddrmsg{
			Family: uint8(family),
		},
	}
}

// struct ifaddrmsg {
//   __u8    ifa_family;
//   __u8    ifa_prefixlen;  /* The prefix length    */
//   __u8    ifa_flags;  /* Flags      */
//   __u8    ifa_scope;  /* Address scope    */
//   __u32   ifa_index;  /* Link index     */
// };

// type IfAddrmsg struct {
// 	Family    uint8
// 	Prefixlen uint8
// 	Flags     uint8
// 	Scope     uint8
// 	Index     uint32
// }
// SizeofIfAddrmsg     = 0x8

func DeserializeIfAddrmsg(b []byte) *IfAddrmsg {
	return (*IfAddrmsg)(unsafe.Pointer(&b[0:syscall.SizeofIfAddrmsg][0]))
}

func (msg *IfAddrmsg) Serialize() []byte {
	return (*(*[syscall.SizeofIfAddrmsg]byte)(unsafe.Pointer(msg)))[:]
}

func (msg *IfAddrmsg) Len() int {
	return syscall.SizeofIfAddrmsg
}

// AddrAdd will add an IP address to a link device.
// Equivalent to: `ip addr del $addr dev $link`
func AddrAdd(link *Link, addr *Addr) error {

	req := newNetlinkRequest(syscall.RTM_NEWADDR, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)
	return addrHandle(link, addr, req)
}

// AddrDel will delete an IP address from a link device.
// Equivalent to: `ip addr del $addr dev $link`
func AddrDel(link *Link, addr *Addr) error {
	req := newNetlinkRequest(syscall.RTM_DELADDR, syscall.NLM_F_ACK)
	return addrHandle(link, addr, req)
}

func addrHandle(link *Link, addr *Addr, req *NetlinkRequest) error {
	if addr.Label != "" && !strings.HasPrefix(addr.Label, link.Name) {
		return fmt.Errorf("label must begin with interface name")
	}
	ensureIndex(link)

	family := GetIPFamily(addr.IP)

	msg := newIfAddrmsg(family)
	msg.Index = uint32(link.Index)
	prefixlen, _ := addr.Mask.Size()
	msg.Prefixlen = uint8(prefixlen)
	req.AddData(msg)

	var addrData []byte
	if family == FAMILY_V4 {
		addrData = addr.IP.To4()
	} else {
		addrData = addr.IP.To16()
	}

	localData := newRtAttr(syscall.IFA_LOCAL, addrData)
	req.AddData(localData)

	addressData := newRtAttr(syscall.IFA_ADDRESS, addrData)
	req.AddData(addressData)

	if addr.Label != "" {
		labelData := newRtAttr(syscall.IFA_LABEL, zeroTerminated(addr.Label))
		req.AddData(labelData)
	}

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	return err
}

// AddrList gets a list of IP addresses in the system.
// Equivalent to: `ip addr show`.
// The list can be filtered by link and ip family.
func AddrList(link *Link, family int) ([]Addr, error) {
	req := newNetlinkRequest(syscall.RTM_GETADDR, syscall.NLM_F_DUMP)
	msg := newIfInfomsg(family)
	req.AddData(msg)

	msgs, err := req.Execute(syscall.NETLINK_ROUTE, syscall.RTM_NEWADDR)
	if err != nil {
		return nil, err
	}
	
	ensureIndex(link)

	res := make([]Addr, 0)
	for _, m := range msgs {
		msg := DeserializeIfAddrmsg(m)

		if link != nil && msg.Index != uint32(link.Index) {
			// Ignore messages from other interfaces
			continue
		}

		attrs, err := parseRouteAttr(m[msg.Len():])
		if err != nil {
			return nil, err
		}

		var addr Addr
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.IFA_ADDRESS:
				addr.IPNet = &net.IPNet{
					IP:   attr.Value,
					Mask: net.CIDRMask(int(msg.Prefixlen), 8*len(attr.Value)),
				}
			case syscall.IFA_LABEL:
				addr.Label = string(attr.Value[:len(attr.Value)-1])
			}
		}
		res = append(res, addr)
	}

	return res, nil
}
