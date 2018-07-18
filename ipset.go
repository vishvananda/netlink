package netlink

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink/nl"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// ipset [ OPTIONS ] COMMAND [ COMMAND-OPTIONS ]
// COMMANDS := { create | add | del | test | destroy | list | save | restore | flush | rename | swap | help | version | - }
//
// OPTIONS := { -exist | -output { plain | save | xml } | -quiet | -resolve | -sorted | -name | -terse | -file filename }
//
// ipset create SETNAME TYPENAME [ CREATE-OPTIONS ]
//
// ipset add SETNAME ADD-ENTRY [ ADD-OPTIONS ]
//
// ipset del SETNAME DEL-ENTRY [ DEL-OPTIONS ]
//
// ipset test SETNAME TEST-ENTRY [ TEST-OPTIONS ]
//
// ipset destroy [ SETNAME ]
//
// ipset list [ SETNAME ]
//
// ipset save [ SETNAME ]
//
// ipset restore
//
// ipset flush [ SETNAME ]
//
// ipset rename SETNAME-FROM SETNAME-TO
//
// ipset swap SETNAME-FROM SETNAME-TO
//
// ipset help [ TYPENAME ]
//
// ipset version
//
// ipset -

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

// IPSetDestroy removes an ipset just like `ipset create` does
func IPSetDestroy(setName string) error {
	return pkgHandle.IPSetDestroy(setName)
}

// IPSetDestroy removes an ipset just like `ipset create` does
func (h *Handle) IPSetDestroy(setName string) error {
	if len(setName) == 0 {
		return fmt.Errorf("ipset: name required")
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

// IPSetFlush flushes all entries from the specified set
func IPSetFlush(setName string) error {
	return pkgHandle.IPSetFlush(setName)
}

// IPSetFlush flushes all entries from the specified set
func (h *Handle) IPSetFlush(setName string) error {
	if len(setName) == 0 {
		return fmt.Errorf("ipset: name required")
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

// IPSetList flushes all entries from the specified set
func IPSetList(setName string) ([]IPSetInfo, error) {
	return pkgHandle.IPSetList(setName)
}

// IPSetList flushes all entries from the specified set
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

	// resp:	attr:	IPSET_ATTR_SETNAME
	// IPSET_ATTR_TYPENAME
	// IPSET_ATTR_REVISION
	// IPSET_ATTR_FAMILY
	// IPSET_ATTR_DATA
	// 	create-specific-data
	// IPSET_ATTR_ADT
	// 	IPSET_ATTR_DATA
	// 		adt-specific-data
	// 	...

	resp := make([]IPSetInfo, 0, 256)

	for _, m := range msgs {
		info, err := parseIPSetInfo(m)
		if err != nil {
			return nil, err
		}

		zap.L().Debug("here", zap.Reflect("info", info))

		resp = append(resp, info)
	}

	return resp, nil
}

func ternaryUint32(cond bool, ifTrue uint32, ifFalse uint32) uint32 {
	if cond {
		return ifTrue
	}

	return ifFalse
}
