package netlink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink/nl"
)

type IPSetIPRange struct {
	From net.IP
	To   net.IP
}

type IPSetPortRange struct {
	Proto ipsetProtoEnum
	From  int
	To    int
}

type IPSetInfoData struct {
	Bytes string
}

type IPSetInfoADT struct {
	Bytes string
}

type IPSetInfo struct {
	Header   NfGenHdr
	Name     string
	Type     string
	Revision uint8
	Family   uint8
	Data     IPSetInfoData
	ADT      IPSetInfoADT
	Proto    uint8
	Flags    uint32
}

// General address family dependent message header
type NfGenHdr struct {
	Family  uint8  // AF_XXX
	Version uint8  // nfnetlink version
	ResID   uint16 // resource id
}

func parseIPSetInfo(data []byte) (IPSetInfo, error) {
	i := IPSetInfo{}
	r := bytes.NewReader(data)

	if err := binary.Read(r, binary.BigEndian, &i.Header); err != nil {
		return i, err
	}

	for r.Len() >= syscallNLA_HDRLEN {
		id, val, err := parseIPSetInfoAttr(r)
		if err != nil {
			return i, err
		}
		i.setAttr(id, val)
	}

	return i, nil
}

func parseIPSetInfoAttr(r *bytes.Reader) (uint16, []byte, error) {
	if r.Len() < syscallNLA_HDRLEN {
		return 0, nil, errors.New("Truncated attribute")
	}

	var (
		aLen  uint16
		aType uint16
	)

	binary.Read(r, native, &aLen)
	binary.Read(r, native, &aType)

	if aLen < syscallNLA_HDRLEN || int(aLen-syscallNLA_HDRLEN) > r.Len() {
		return 0, nil, errors.New("Truncated attribute")
	}

	aLen -= syscallNLA_HDRLEN
	if aLen == 0 {
		return aType, nil, nil
	}

	aData := make([]byte, aLen)
	r.Read(aData)

	for padlen := nlaAlignOf(int(aLen)) - int(aLen); padlen > 0; padlen-- {
		r.ReadByte()
	}

	return aType, aData, nil
}

func nlaAlignOf(attrlen int) int {
	return (attrlen + syscallNLA_ALIGNTO - 1) & ^(syscallNLA_ALIGNTO - 1)
}

func (i *IPSetInfo) setAttr(id uint16, data []byte) {
	nested := id&NLA_F_NESTED > 0
	id = id & ^uint16(NLA_F_NESTED)

	switch id {
	case IPSET_ATTR_PROTOCOL:
		i.Proto, _ = readUint8(data)

	case IPSET_ATTR_SETNAME:
		i.Name, _ = readZeroTerminated(data)

	case IPSET_ATTR_TYPENAME:
		i.Type, _ = readZeroTerminated(data)

	case IPSET_ATTR_REVISION:
		i.Revision, _ = readUint8(data)

	case IPSET_ATTR_FAMILY:
		i.Family, _ = readUint8(data)

	case IPSET_ATTR_FLAGS:
		i.Flags, _ = readUint32(data)
		//i.Counters = i.Flags&IPSET_FLAG_WITH_COUNTERS > 0
		//i.Comment = i.Flags&IPSET_FLAG_WITH_COMMENT > 0
		//i.Skbinfo = i.Flags&IPSET_FLAG_WITH_SKBINFO > 0
		//i.Forceadd = i.Flags&IPSET_FLAG_WITH_FORCEADD > 0

	case IPSET_ATTR_DATA:
		if !nested {
			panic("not nested data")
		}
		i.Data, _ = readIPSetData(data)

	case IPSET_ATTR_ADT:
		if !nested {
			panic("not nested ADT")
		}
		i.ADT, _ = readIPSetADT(data)

	default:
		panic(fmt.Sprintf("unknown field%d: %q", id, data))
	}
}

func readUint8(data []byte) (uint8, []byte) {
	return data[0], data[1:]
}

func readUint16(data []byte) (uint16, []byte) {
	return nl.NativeEndian().Uint16(data[:2]), data[2:]
}

func readUint32(data []byte) (uint32, []byte) {
	return nl.NativeEndian().Uint32(data[:4]), data[4:]
}

func readZeroTerminated(data []byte) (string, []byte) {
	zeroPos := bytes.Index(data, []byte{0})
	return string(data[:zeroPos]), data[zeroPos+1:]
}

func readIPSetData(data []byte) (IPSetInfoData, []byte) {
	return IPSetInfoData{Bytes: string(data)}, data
}

func readIPSetADT(data []byte) (IPSetInfoADT, []byte) {
	return IPSetInfoADT{Bytes: string(data)}, data
}
