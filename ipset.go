package netlink

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// static errors might be returned by IPSET methods
var (
	ErrNameRequired = fmt.Errorf("ipset: name required")
	ErrNameTooLong  = fmt.Errorf("ipset: name too long")
)

// IPSetCreateInfo is a IPSetCreate parameters container
type IPSetCreateInfo struct {
	Name     string
	Type     IpsetTypeEnum
	Family   IpsetFamilyEnum
	Proto    IpsetProtoEnum
	Counters bool
	Comment  bool
	SkbInfo  bool
	ForceAdd bool
	Timeout  time.Duration
	HashSize uint32
	MaxElem  uint32
	NetMask  net.IPMask
	MarkMask uint32
}

// IPSetCreate create a new ipset just like `ipset create` does
func IPSetCreate(info IPSetCreateInfo) error {
	return pkgHandle.IPSetCreate(info)
}

// IPSetCreate create a new ipset just like `ipset create` does
// Note: range patrameter is not supported (yet?), so all the types requires it are not creatable.
func (h *Handle) IPSetCreate(info IPSetCreateInfo) error {
	if len(info.Name) == 0 {
		return ErrNameRequired
	}

	if len(info.Name) > IPSET_MAXNAMELEN-1 {
		return ErrNameTooLong
	}

	req := nl.NewNetlinkRequest(IPSET_CMD_CREATE|(NFNL_SUBSYS_IPSET<<8), unixNLM_F_ACK)
	req.AddData(
		&nl.Nfgenmsg{
			NfgenFamily: uint8(unix.AF_INET),
			Version:     nl.NFNETLINK_V0,
			ResId:       0,
		},
	)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_PROTOCOL, nl.Uint8Attr(IPSET_PROTOCOL)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(info.Name)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_TYPENAME, nl.ZeroTerminated(info.Type.toString())))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_REVISION, nl.Uint8Attr(IPSET_ATTR_REVISION_VALUE)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_FAMILY, nl.Uint8Attr(info.Family.toUint8())))

	data := nl.NewRtAttr(IPSET_ATTR_DATA|NLA_F_NESTED, nil)

	flags := ternaryUint32(info.Counters, IPSET_FLAG_WITH_COUNTERS, 0)
	flags |= ternaryUint32(info.Comment, IPSET_FLAG_WITH_COMMENT, 0)
	flags |= ternaryUint32(info.SkbInfo, IPSET_FLAG_WITH_SKBINFO, 0)
	flags |= ternaryUint32(info.ForceAdd, IPSET_FLAG_WITH_FORCEADD, 0)

	if flags != 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_CADT_FLAGS|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(flags))
	}

	if info.Timeout > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_TIMEOUT|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(uint32(info.Timeout.Seconds())))
	}

	if info.HashSize > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_HASHSIZE|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(info.HashSize))
	}

	if info.MaxElem > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_MAXELEM|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(info.MaxElem))
	}

	//if ipRange != nil {
	//	nl.NewRtAttrChild(data, IPSET_ATTR_IP_FROM, ipRange.From.To4())
	//	nl.NewRtAttrChild(data, IPSET_ATTR_IP_TO, ipRange.To.To4())
	//}
	//
	//if portRange != nil {
	//	nl.NewRtAttrChild(data, IPSET_ATTR_PORT_FROM|syscallNLA_F_NET_BYTEORDER, po.From.To4())
	//	nl.NewRtAttrChild(data, IPSET_ATTR_PORT_TO|syscallNLA_F_NET_BYTEORDER, ipRange.To.To4())
	//}

	if info.NetMask != nil {
		ones, _ := info.NetMask.Size()
		nl.NewRtAttrChild(data, IPSET_ATTR_NETMASK, nl.Uint8Attr(uint8(ones)))
	}

	if info.MarkMask != 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_NETMASK|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(info.MarkMask))
	}

	if data.Len() > 0 {
		req.AddData(data)
	}

	_, err := req.Execute(unixNETLINK_NETFILTER, 0)

	return err
}

// IPSetDestroy removes an ipset just like `ipset destroy` does
func IPSetDestroy(setName string) error {
	return pkgHandle.IPSetDestroy(setName)
}

// IPSetDestroy removes an ipset just like `ipset destroy` does
func (h *Handle) IPSetDestroy(setName string) error {
	if len(setName) == 0 {
		return ErrNameRequired
	}

	if len(setName) > IPSET_MAXNAMELEN-1 {
		return ErrNameTooLong
	}

	req := nl.NewNetlinkRequest(IPSET_CMD_DESTROY|(NFNL_SUBSYS_IPSET<<8), unixNLM_F_ACK)
	req.AddData(
		&nl.Nfgenmsg{
			NfgenFamily: uint8(unix.AF_INET),
			Version:     nl.NFNETLINK_V0,
			ResId:       0,
		},
	)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_PROTOCOL, nl.Uint8Attr(IPSET_PROTOCOL)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setName)))

	_, err := req.Execute(unixNETLINK_NETFILTER, 0)

	return err
}

// IPSetRename renames an ipset just like `ipset destroy` does
func IPSetRename(srcName string, dstName string) error {
	return pkgHandle.IPSetRename(srcName, dstName)
}

// IPSetRename renames an ipset just like `ipset rename` does
func (h *Handle) IPSetRename(srcName string, dstName string) error {
	if len(srcName) == 0 || len(dstName) == 0 {
		return ErrNameRequired
	}

	if len(srcName) > IPSET_MAXNAMELEN-1 || len(dstName) > IPSET_MAXNAMELEN-1 {
		return ErrNameTooLong
	}

	req := nl.NewNetlinkRequest(IPSET_CMD_RENAME|(NFNL_SUBSYS_IPSET<<8), unixNLM_F_ACK)
	req.AddData(
		&nl.Nfgenmsg{
			NfgenFamily: uint8(unix.AF_INET),
			Version:     nl.NFNETLINK_V0,
			ResId:       0,
		},
	)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_PROTOCOL, nl.Uint8Attr(IPSET_PROTOCOL)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(srcName)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME2, nl.ZeroTerminated(dstName)))

	_, err := req.Execute(unixNETLINK_NETFILTER, 0)

	return err
}

// IPSetSwap swaps two ipsets just like `ipset swap` does
func IPSetSwap(srcName string, dstName string) error {
	return pkgHandle.IPSetSwap(srcName, dstName)
}

// IPSetSwap swaps two ipsets just like `ipset swap` does
func (h *Handle) IPSetSwap(srcName string, dstName string) error {
	if len(srcName) == 0 || len(dstName) == 0 {
		return ErrNameRequired
	}

	if len(srcName) > IPSET_MAXNAMELEN-1 || len(dstName) > IPSET_MAXNAMELEN-1 {
		return ErrNameTooLong
	}

	req := nl.NewNetlinkRequest(IPSET_CMD_SWAP|(NFNL_SUBSYS_IPSET<<8), unixNLM_F_ACK)
	req.AddData(
		&nl.Nfgenmsg{
			NfgenFamily: uint8(unix.AF_INET),
			Version:     nl.NFNETLINK_V0,
			ResId:       0,
		},
	)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_PROTOCOL, nl.Uint8Attr(IPSET_PROTOCOL)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(srcName)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME2, nl.ZeroTerminated(dstName)))

	_, err := req.Execute(unixNETLINK_NETFILTER, 0)

	return err
}

// IPSetFlush flushes all entries from the specified set
func IPSetFlush(setName string) error {
	return pkgHandle.IPSetFlush(setName)
}

// IPSetFlush flushes all entries from the specified set
func (h *Handle) IPSetFlush(setName string) error {
	if len(setName) == 0 {
		return ErrNameRequired
	}

	if len(setName) > IPSET_MAXNAMELEN-1 {
		return ErrNameTooLong
	}

	req := nl.NewNetlinkRequest(IPSET_CMD_FLUSH|(NFNL_SUBSYS_IPSET<<8), unixNLM_F_ACK)
	req.AddData(
		&nl.Nfgenmsg{
			NfgenFamily: uint8(unix.AF_INET),
			Version:     nl.NFNETLINK_V0,
			ResId:       0,
		},
	)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_PROTOCOL, nl.Uint8Attr(IPSET_PROTOCOL)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setName)))

	_, err := req.Execute(unixNETLINK_NETFILTER, 0)

	return err
}

// IPSetList returns an info for the specified setName or all sets in case seName is empty
func IPSetList(setName string) ([]IPSetInfo, error) {
	return pkgHandle.IPSetList(setName)
}

// IPSetListBrief returns a brief (no content) info for the specified setName or all sets in case seName is empty
func IPSetListBrief(setName string) ([]IPSetInfo, error) {
	return pkgHandle.IPSetListBrief(setName)
}

// IPSetList returns an info for the specified setName or all sets in case seName is empty
func (h *Handle) IPSetList(setName string) ([]IPSetInfo, error) {
	return h.ipsetList(setName, true)
}

// IPSetListBrief returns a brief (no content) info for the specified setName or all sets in case seName is empty
func (h *Handle) IPSetListBrief(setName string) ([]IPSetInfo, error) {
	return h.ipsetList(setName, false)
}

// IPSetList returns an info for the specified setName or all sets in case seName is empty
func (h *Handle) ipsetList(setName string, full bool) ([]IPSetInfo, error) {
	req := nl.NewNetlinkRequest(IPSET_CMD_LIST|(NFNL_SUBSYS_IPSET<<8), unixNLM_F_ACK)
	req.AddData(
		&nl.Nfgenmsg{
			NfgenFamily: uint8(unix.AF_INET),
			Version:     nl.NFNETLINK_V0,
			ResId:       0,
		},
	)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_PROTOCOL, nl.Uint8Attr(IPSET_PROTOCOL)))

	if setName != "" {
		if len(setName) > IPSET_MAXNAMELEN-1 {
			return nil, ErrNameTooLong
		}

		req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setName)))
	}

	if !full {
		req.AddData(
			nl.NewRtAttr(
				IPSET_ATTR_FLAGS|syscallNLA_F_NET_BYTEORDER,
				nl.Uint32AttrNetEndian(IPSET_LIST_TERSE),
			),
		)
	}

	msgs, err := req.Execute(unixNETLINK_NETFILTER, 0)
	if err != nil {
		return nil, err
	}

	resp := make([]IPSetInfo, 0, 256)

	for _, m := range msgs {
		info, err := parseIPSetInfo(m)
		if err != nil {
			return nil, err
		}

		resp = append(resp, info)
	}

	return resp, nil
}

// IPSetAdd adds a specified entry to the specified set
func IPSetAdd(setName string, entry IPSetInfoADTData) error {
	return pkgHandle.IPSetAdd(setName, entry)
}

// IPSetAdd adds a specified entry to the specified set
func (h *Handle) IPSetAdd(setName string, entry IPSetInfoADTData) error {
	if len(setName) == 0 {
		return ErrNameRequired
	}

	if len(setName) > IPSET_MAXNAMELEN-1 {
		return ErrNameTooLong
	}

	req := nl.NewNetlinkRequest(IPSET_CMD_ADD|(NFNL_SUBSYS_IPSET<<8), unixNLM_F_ACK)
	req.AddData(
		&nl.Nfgenmsg{
			NfgenFamily: uint8(unix.AF_INET),
			Version:     nl.NFNETLINK_V0,
			ResId:       0,
		},
	)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_PROTOCOL, nl.Uint8Attr(IPSET_PROTOCOL)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setName)))

	data := nl.NewRtAttr(IPSET_ATTR_DATA|NLA_F_NESTED, nil)

	addr := nl.NewRtAttr(IPSET_ATTR_IP|NLA_F_NESTED, nil)
	if ip4 := entry.IP.Addr.To4(); ip4 != nil {
		nl.NewRtAttrChild(addr, IPSET_ATTR_IP|syscallNLA_F_NET_BYTEORDER, ip4)
	} else {
		nl.NewRtAttrChild(addr, IPSET_ATTR_IP|syscallNLA_F_NET_BYTEORDER, entry.IP.Addr.To16())
	}

	data.AddChild(addr)

	flags := ternaryUint32(entry.Nomatch, IPSET_FLAG_NOMATCH, 0)

	if entry.Mask != nil {
		ones, _ := entry.Mask.Size()
		nl.NewRtAttrChild(data, IPSET_ATTR_CIDR, nl.Uint8Attr(uint8(ones)))
	}

	if entry.Proto != 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_PROTO, nl.Uint8Attr(uint8(entry.Proto)))
	}

	if entry.Port != 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_PORT|syscallNLA_F_NET_BYTEORDER, nl.Uint16AttrNetEndian(uint16(entry.Port)))
	}

	if entry.PortTo != 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_PORT_TO|syscallNLA_F_NET_BYTEORDER, nl.Uint16AttrNetEndian(uint16(entry.PortTo)))
	}

	if entry.Packets > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_PACKETS|syscallNLA_F_NET_BYTEORDER, nl.Uint64AttrNetEndian(uint64(entry.Packets)))
	}

	if entry.Bytes > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_BYTES|syscallNLA_F_NET_BYTEORDER, nl.Uint64AttrNetEndian(uint64(entry.Bytes)))
	}

	if entry.Timeout > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_TIMEOUT|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(uint32(entry.Timeout.Seconds())))
	}

	if entry.Comment != "" {
		nl.NewRtAttrChild(data, IPSET_ATTR_COMMENT, nl.ZeroTerminated(entry.Comment))
	}

	if entry.SkbMark > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_SKBMARK|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(entry.SkbMark))
	}

	if entry.SkbPrio > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_SKBPRIO|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(entry.SkbPrio))
	}

	if entry.SkbQueue > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_SKBQUEUE|syscallNLA_F_NET_BYTEORDER, nl.Uint16AttrNetEndian(entry.SkbQueue))
	}

	if entry.Line > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_LINENO|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(uint32(entry.Line)))
	}

	if flags != 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_FLAGS|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(flags))
	}

	req.AddData(data)

	_, err := req.Execute(unixNETLINK_NETFILTER, 0)

	return err
}

// IPSetDel removes a specified entry to the specified set
// Note: IPSetDel would not report entry-does-not-exist error in any case
func IPSetDel(setName string, entry IPSetInfoADTData) error {
	return pkgHandle.IPSetDel(setName, entry)
}

// IPSetDel removes a specified entry to the specified set
// Note: IPSetDel would not report entry-does-not-exist error in any case
func (h *Handle) IPSetDel(setName string, entry IPSetInfoADTData) error {
	if len(setName) == 0 {
		return ErrNameRequired
	}

	if len(setName) > IPSET_MAXNAMELEN-1 {
		return ErrNameTooLong
	}

	req := nl.NewNetlinkRequest(IPSET_CMD_DEL|(NFNL_SUBSYS_IPSET<<8), unixNLM_F_ACK)
	req.AddData(
		&nl.Nfgenmsg{
			NfgenFamily: uint8(unix.AF_INET),
			Version:     nl.NFNETLINK_V0,
			ResId:       0,
		},
	)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_PROTOCOL, nl.Uint8Attr(IPSET_PROTOCOL)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setName)))

	data := nl.NewRtAttr(IPSET_ATTR_DATA|NLA_F_NESTED, nil)

	addr := nl.NewRtAttr(IPSET_ATTR_IP|NLA_F_NESTED, nil)
	if entry.IP.Addr.To4 != nil {
		nl.NewRtAttrChild(addr, IPSET_ATTR_IP|syscallNLA_F_NET_BYTEORDER, entry.IP.Addr.To4())
	} else {
		nl.NewRtAttrChild(addr, IPSET_ATTR_IP|syscallNLA_F_NET_BYTEORDER, entry.IP.Addr.To16())
	}

	data.AddChild(addr)

	req.AddData(data)

	_, err := req.Execute(unixNETLINK_NETFILTER, 0)

	return err
}

/////////////////////////////////////////////////////////////////////
func ternaryUint32(cond bool, ifTrue uint32, ifFalse uint32) uint32 {
	if cond {
		return ifTrue
	}

	return ifFalse
}
