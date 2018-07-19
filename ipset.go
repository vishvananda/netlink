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

// IPSetCreate create a new ipset just like `ipset create` does
func IPSetCreate(
	setName string,
	setType ipsetTypeEnum,
	timeout time.Duration,
	counters bool,
	comment bool,
	skbinfo bool,
	hashsize uint32,
	maxelem uint32,
	family ipsetFamilyEnum,
	forceadd bool,
	netmask net.IPMask,
	markmask uint32,
	// ipRange *IPSetIPRange,
	// portRange *IPSetPortRange,
) error {
	return pkgHandle.IPSetCreate(
		setName,
		setType,
		timeout,
		counters,
		comment,
		skbinfo,
		hashsize,
		maxelem,
		family,
		forceadd,
		netmask,
		markmask,
		// ipRange,
		// portRange,
	)
}

// IPSetCreate create a new ipset just like `ipset create` does
// Note: range patrameter is not supported (yet?), so all the types requires it are not creatable.
func (h *Handle) IPSetCreate(
	setName string,
	setType ipsetTypeEnum,
	timeout time.Duration,
	counters bool,
	comment bool,
	skbinfo bool,
	hashsize uint32,
	maxelem uint32,
	family ipsetFamilyEnum,
	forceadd bool,
	netmask net.IPMask,
	markmask uint32,
	// ipRange *IPSetIPRange,
	// portRange *IPSetPortRange,
) error {
	if len(setName) == 0 {
		return ErrNameRequired
	}

	if len(setName) > IPSET_MAXNAMELEN-1 {
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
	req.AddData(nl.NewRtAttr(IPSET_ATTR_SETNAME, nl.ZeroTerminated(setName)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_TYPENAME, nl.ZeroTerminated(setType.toString())))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_REVISION, nl.Uint8Attr(IPSET_ATTR_REVISION_VALUE)))
	req.AddData(nl.NewRtAttr(IPSET_ATTR_FAMILY, nl.Uint8Attr(family.toUint8())))

	data := nl.NewRtAttr(IPSET_ATTR_DATA|NLA_F_NESTED, nil)

	flags := ternaryUint32(counters, IPSET_FLAG_WITH_COUNTERS, 0)
	flags |= ternaryUint32(comment, IPSET_FLAG_WITH_COMMENT, 0)
	flags |= ternaryUint32(skbinfo, IPSET_FLAG_WITH_SKBINFO, 0)
	flags |= ternaryUint32(forceadd, IPSET_FLAG_WITH_FORCEADD, 0)

	if flags != 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_CADT_FLAGS|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(flags))
	}

	if timeout > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_TIMEOUT|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(uint32(timeout.Seconds())))
	}

	if hashsize > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_HASHSIZE|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(hashsize))
	}

	if maxelem > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_MAXELEM|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(maxelem))
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

	if netmask != nil {
		ones, _ := netmask.Size()
		nl.NewRtAttrChild(data, IPSET_ATTR_NETMASK, nl.Uint8Attr(uint8(ones)))
	}

	if markmask != 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_NETMASK|syscallNLA_F_NET_BYTEORDER, nl.Uint32AttrNetEndian(markmask))
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

// IPSetList returns an info for the specified setName or all sets in case seName is empty
func (h *Handle) IPSetList(setName string) ([]IPSetInfo, error) {
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

// IPSetList returns an info for the specified setName or all sets in case seName is empty
func IPSetAdd(setName string, entry IPSetInfoADTData) error {
	return pkgHandle.IPSetAdd(setName, entry)
}

// IPSetList returns an info for the specified setName or all sets in case seName is empty
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
	if entry.IP.Addr.To4 != nil {
		nl.NewRtAttrChild(addr, IPSET_ATTR_IP|syscallNLA_F_NET_BYTEORDER, entry.IP.Addr.To4())
	} else {
		nl.NewRtAttrChild(addr, IPSET_ATTR_IP|syscallNLA_F_NET_BYTEORDER, entry.IP.Addr.To16())
	}

	data.AddChild(addr)

	if entry.Mask != nil {
		ones, _ := entry.Mask.Size()
		nl.NewRtAttrChild(data, IPSET_ATTR_CIDR, nl.Uint8Attr(uint8(ones)))
	}

	flags := ternaryUint32(entry.Nomatch, IPSET_FLAG_NOMATCH, 0)
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

/////////////////////////////////////////////////////////////////////
func ternaryUint32(cond bool, ifTrue uint32, ifFalse uint32) uint32 {
	if cond {
		return ifTrue
	}

	return ifFalse
}
