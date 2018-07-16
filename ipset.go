package netlink

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
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

// IPSetCreate create a new ipset just like `ipset create` does
func IPSetCreate(
	setName string,
	setType ipsetTypeEnum,
	family ipsetFamilyEnum,
	timeout time.Duration,
	hashsize uint32,
	maxelem uint32,
) error {
	return pkgHandle.IPSetCreate(setName, setType, family, timeout, hashsize, maxelem)
}

// IPSetCreate create a new ipset just like `ipset create` does
func (h *Handle) IPSetCreate(
	setName string,
	setType ipsetTypeEnum,
	family ipsetFamilyEnum,
	timeout time.Duration,
	hashsize uint32,
	maxelem uint32,
) error {
	if len(setName) == 0 {
		return fmt.Errorf("ipset: name required")
	}

	if len(setName) > IPSET_MAXNAMELEN-1 {
		return fmt.Errorf("ipset: name too long")
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

	if timeout > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_TIMEOUT|syscallNLA_F_NET_BYTEORDER, Uint32AttrNetworkOrder(uint32(timeout.Seconds())))
	}

	if hashsize > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_HASHSIZE|syscallNLA_F_NET_BYTEORDER, Uint32AttrNetworkOrder(hashsize))
	}

	if maxelem > 0 {
		nl.NewRtAttrChild(data, IPSET_ATTR_MAXELEM|syscallNLA_F_NET_BYTEORDER, Uint32AttrNetworkOrder(maxelem))
	}

	req.AddData(data)

	zap.L().Debug("here", zap.String("req", spew.Sprintf("%#v", data)))

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
		return fmt.Errorf("ipset: name too long")
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
		return fmt.Errorf("ipset: name too long")
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
func IPSetList(setName string) error {
	return pkgHandle.IPSetList()
}

// IPSetList flushes all entries from the specified set
func (h *Handle) IPSetList() error {
	req := nl.NewNetlinkRequest(IPSET_CMD_LIST|(NFNL_SUBSYS_IPSET<<8), unixNLM_F_ACK)
	req.AddData(
		&nl.Nfgenmsg{
			NfgenFamily: uint8(unix.AF_INET),
			Version:     nl.NFNETLINK_V0,
			ResId:       0,
		},
	)
	req.AddData(nl.NewRtAttr(IPSET_ATTR_PROTOCOL, nl.Uint8Attr(IPSET_PROTOCOL)))

	_, err := req.Execute(unixNETLINK_NETFILTER, 0)

	return err
}

func Uint32AttrNetworkOrder(v uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, v)
	return bytes
}
