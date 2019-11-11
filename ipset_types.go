package netlink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink/nl"
)

//type IPSetIPRange struct {
//	From net.IP
//	To   net.IP
//}
//
//type IPSetPortRange struct {
//	Proto IpsetProtoEnum
//	From  int
//	To    int
//}

// IPSetInfo is a IPSET one set info representation
type IPSetInfo struct {
	Header   nl.Nfgenmsg
	Name     string
	Type     IpsetTypeEnum
	Revision uint8
	Family   IpsetFamilyEnum
	Proto    IpsetProtoEnum
	Flags    uint32
	Data     IPSetInfoData
	ADT      IPSetInfoADT
}

// IPSetInfoData is a IPSET set data representation
type IPSetInfoData struct {
	Counters   bool
	Comment    bool
	Skbinfo    bool
	Forceadd   bool
	Timeout    time.Duration
	HashSize   int
	MaxElem    int
	NetMask    net.IPMask
	MarkMask   uint32
	Elements   int
	References int
	MemSize    int
}

// IPSetInfoADT is a IPSET set ADT representation
type IPSetInfoADT struct {
	Data []IPSetInfoADTData
}

// IPSetInfoADTData is a IPSET set ADT one entry data representation
type IPSetInfoADTData struct {
	IP       IPSetInfoADTDataIP
	Mask     net.IPMask
	Line     int
	Packets  int
	Bytes    int
	Timeout  time.Duration
	Nomatch  bool
	Comment  string
	SkbMark  uint32
	SkbPrio  uint32
	SkbQueue uint16
	Port     int
	PortTo   int
	Proto    IpsetProtoEnum

	tmpMask byte
}

// IPSetInfoADTDataIP is a IPSET set ADT one entry IP address data representation
type IPSetInfoADTDataIP struct {
	Addr net.IP
}

func (d *IPSetInfoData) setAttr(id uint16, data []byte) {
	switch id {
	case IPSET_ATTR_CADT_FLAGS | syscallNLA_F_NET_BYTEORDER:
		flags := binary.BigEndian.Uint32(data[:4])
		d.Counters = flags&IPSET_FLAG_WITH_COUNTERS > 0
		d.Comment = flags&IPSET_FLAG_WITH_COMMENT > 0
		d.Skbinfo = flags&IPSET_FLAG_WITH_SKBINFO > 0
		d.Forceadd = flags&IPSET_FLAG_WITH_FORCEADD > 0

	case IPSET_ATTR_TIMEOUT | syscallNLA_F_NET_BYTEORDER:
		d.Timeout = time.Second * time.Duration(binary.BigEndian.Uint32(data[:4]))

	case IPSET_ATTR_HASHSIZE | syscallNLA_F_NET_BYTEORDER:
		d.HashSize = int(binary.BigEndian.Uint32(data[:4]))

	case IPSET_ATTR_MAXELEM | syscallNLA_F_NET_BYTEORDER:
		d.MaxElem = int(binary.BigEndian.Uint32(data[:4]))

	case IPSET_ATTR_NETMASK:
		d.NetMask = net.CIDRMask(int(data[0]), 32)

	case IPSET_ATTR_MARKMASK | syscallNLA_F_NET_BYTEORDER:
		d.MarkMask = binary.BigEndian.Uint32(data[:4])

	case IPSET_ATTR_ELEMENTS | syscallNLA_F_NET_BYTEORDER:
		d.Elements = int(binary.BigEndian.Uint32(data[:4]))

	case IPSET_ATTR_REFERENCES | syscallNLA_F_NET_BYTEORDER:
		d.References = int(binary.BigEndian.Uint32(data[:4]))

	case IPSET_ATTR_MEMSIZE | syscallNLA_F_NET_BYTEORDER:
		d.MemSize = int(binary.BigEndian.Uint32(data[:4]))

	default:
		panic(
			fmt.Errorf(
				"unknown field %d (%d), %d bytes: %q",
				id,
				id&^syscallNLA_F_NET_BYTEORDER,
				len(data),
				data,
			),
		)
	}
}

func (a *IPSetInfoADT) setAttr(id uint16, data []byte) {
	switch id {
	case IPSET_ATTR_DATA | NLA_F_NESTED:
		d, err := parseIPSetInfoADTData(data)
		if err != nil {
			panic(err)
		}
		a.Data = append(a.Data, d)

	default:
		panic(
			fmt.Errorf(
				"unknown field %d (%d), %d bytes: %q",
				id,
				id&^NLA_F_NESTED,
				len(data),
				data,
			),
		)
	}
}

func (d *IPSetInfoADTData) setAttr(id uint16, data []byte) {
	switch id {
	case IPSET_ATTR_IP | NLA_F_NESTED:
		var err error
		d.IP, err = parseIPSetInfoADTDataIP(data)
		if err != nil {
			panic(err)
		}

	case IPSET_ATTR_CIDR:
		// d.Mask = net.CIDRMask(int(data[0]), 32)
		d.tmpMask = data[0]

	case IPSET_ATTR_BYTES | syscallNLA_F_NET_BYTEORDER:
		d.Bytes = int(binary.BigEndian.Uint64(data[:8]))

	case IPSET_ATTR_PACKETS | syscallNLA_F_NET_BYTEORDER:
		d.Packets = int(binary.BigEndian.Uint64(data[:8]))

	case IPSET_ATTR_TIMEOUT | syscallNLA_F_NET_BYTEORDER:
		d.Timeout = time.Second * time.Duration(binary.BigEndian.Uint32(data[:4]))

	case IPSET_ATTR_COMMENT:
		d.Comment = nl.ParseZeroTerminated(data)

	case IPSET_ATTR_SKBMARK | syscallNLA_F_NET_BYTEORDER:
		d.SkbMark = binary.BigEndian.Uint32(data[:4])

	case IPSET_ATTR_SKBPRIO | syscallNLA_F_NET_BYTEORDER:
		d.SkbPrio = binary.BigEndian.Uint32(data[:4])

	case IPSET_ATTR_SKBQUEUE | syscallNLA_F_NET_BYTEORDER:
		d.SkbQueue = binary.BigEndian.Uint16(data[:2])

	case IPSET_ATTR_PORT | syscallNLA_F_NET_BYTEORDER:
		d.Port = int(binary.BigEndian.Uint16(data[:2]))

	case IPSET_ATTR_PORT_TO | syscallNLA_F_NET_BYTEORDER:
		d.PortTo = int(binary.BigEndian.Uint16(data[:2]))

	case IPSET_ATTR_PROTO:
		d.Proto = IpsetProtoEnumFromByte(data[0])

	default:
		panic(
			fmt.Errorf(
				"unknown field %d (%d or %d), %d bytes: %q",
				id,
				id&^NLA_F_NESTED,
				id&^syscallNLA_F_NET_BYTEORDER,
				len(data),
				data,
			),
		)
	}
}

func (d *IPSetInfoADTDataIP) setAttr(id uint16, data []byte) {
	switch id {
	case IPSET_ATTR_IP:
		d.Addr = net.IPv4(data[0], data[1], data[2], data[3])

	default:
		panic(
			fmt.Errorf(
				"unknown field %d (%d), %d bytes: %q",
				id,
				id&^NLA_F_NESTED,
				len(data),
				data,
			),
		)
	}
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
	switch id {
	case IPSET_ATTR_PROTOCOL:
		i.Proto = IpsetProtoEnumFromByte(data[0])

	case IPSET_ATTR_SETNAME:
		i.Name = nl.ParseZeroTerminated(data)

	case IPSET_ATTR_TYPENAME:
		i.Type = IpsetTypeEnumFromString(nl.ParseZeroTerminated(data))

	case IPSET_ATTR_REVISION:
		i.Revision = data[0]

	case IPSET_ATTR_FAMILY:
		i.Family = IpsetFamilyEnumFromByte(data[0])

	case IPSET_ATTR_FLAGS:
		i.Flags = nl.NativeEndian().Uint32(data[:4])

	case IPSET_ATTR_DATA | NLA_F_NESTED:
		var err error
		i.Data, err = parseIPSetInfoData(data)
		if err != nil {
			panic(err)
		}

	case IPSET_ATTR_ADT | NLA_F_NESTED:
		var err error
		i.ADT, err = parseIPSetInfoADT(data)
		if err != nil {
			panic(err)
		}

	default:
		panic(fmt.Sprintf("unknown field %d (%d), %d bytes: %q", id&^NLA_F_NESTED, id, len(data), data))
	}
}

func parseIPSetInfoData(data []byte) (IPSetInfoData, error) {
	d := IPSetInfoData{}
	r := bytes.NewReader(data)

	for r.Len() >= syscallNLA_HDRLEN {
		id, val, err := parseIPSetInfoAttr(r)
		if err != nil {
			return d, err
		}
		d.setAttr(id, val)
	}

	return d, nil
}

func parseIPSetInfoADT(data []byte) (IPSetInfoADT, error) {
	a := IPSetInfoADT{
		Data: make([]IPSetInfoADTData, 0, 256),
	}
	r := bytes.NewReader(data)

	for r.Len() >= syscallNLA_HDRLEN {
		id, val, err := parseIPSetInfoAttr(r)
		if err != nil {
			return a, err
		}
		a.setAttr(id, val)
	}

	return a, nil
}

func parseIPSetInfoADTData(data []byte) (IPSetInfoADTData, error) {
	ad := IPSetInfoADTData{}
	r := bytes.NewReader(data)

	for r.Len() >= syscallNLA_HDRLEN {
		id, val, err := parseIPSetInfoAttr(r)
		if err != nil {
			return ad, err
		}
		ad.setAttr(id, val)
	}

	if ad.IP.Addr.To4() != nil {
		ad.Mask = net.CIDRMask(int(ad.tmpMask), 32)
	} else {
		ad.Mask = net.CIDRMask(int(ad.tmpMask), 128)
	}

	return ad, nil
}

func parseIPSetInfoADTDataIP(data []byte) (IPSetInfoADTDataIP, error) {
	ip := IPSetInfoADTDataIP{}
	r := bytes.NewReader(data)

	for r.Len() >= syscallNLA_HDRLEN {
		id, val, err := parseIPSetInfoAttr(r)
		if err != nil {
			return ip, err
		}
		ip.setAttr(id, val)
	}

	return ip, nil
}
