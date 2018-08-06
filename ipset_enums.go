package netlink

import "fmt"

type ipsetTypeEnum string

func (t ipsetTypeEnum) toString() string {
	return string(t)
}

// possible IPSet types
const (
	IPSetHashIP         ipsetTypeEnum = "hash:ip"
	IPSetBitmapIP       ipsetTypeEnum = "bitmap:ip"
	IPSetBitmapIPMac    ipsetTypeEnum = "bitmap:ip,mac"
	IPSetBitmapPort     ipsetTypeEnum = "bitmap:port"
	IPSetHashMac        ipsetTypeEnum = "hash:mac"
	IPSetHashNet        ipsetTypeEnum = "hash:net"
	IPSetHashNetNet     ipsetTypeEnum = "hash:net,net"
	IPSetHashIPPort     ipsetTypeEnum = "hash:ip,port"
	IPSetHashNetPort    ipsetTypeEnum = "hash:net,port"
	IPSetHashIPPortIP   ipsetTypeEnum = "hash:ip,port,ip"
	IPSetHashIPPortNet  ipsetTypeEnum = "hash:ip,port,net"
	IPSetHashIPMark     ipsetTypeEnum = "hash:ip,mark"
	IPSetHashNetPortNet ipsetTypeEnum = "hash:net,port,net"
	IPSetHashNetIface   ipsetTypeEnum = "hash:net,iface"
	IPSetListSet        ipsetTypeEnum = "list:set"
)

func ipsetTypeEnumFromString(str string) ipsetTypeEnum {
	switch str {
	case "hash:ip":
		return IPSetHashIP
	case "bitmap:ip":
		return IPSetBitmapIP
	case "bitmap:ip,mac":
		return IPSetBitmapIPMac
	case "bitmap:port":
		return IPSetBitmapPort
	case "hash:mac":
		return IPSetHashMac
	case "hash:net":
		return IPSetHashNet
	case "hash:net,net":
		return IPSetHashNetNet
	case "hash:ip,port":
		return IPSetHashIPPort
	case "hash:net,port":
		return IPSetHashNetPort
	case "hash:ip,port,ip":
		return IPSetHashIPPortIP
	case "hash:ip,port,net":
		return IPSetHashIPPortNet
	case "hash:ip,mark":
		return IPSetHashIPMark
	case "hash:net,port,net":
		return IPSetHashNetPortNet
	case "hash:net,iface":
		return IPSetHashNetIface
	case "list:set":
		return IPSetListSet
	default:
		panic(fmt.Errorf("Invalid IPSet type %q", str))
	}
}

type ipsetFamilyEnum uint8

func (f ipsetFamilyEnum) toUint8() uint8 {
	return uint8(f)
}

// http://git.netfilter.org/ipset/tree/include/libipset/nfproto.h
const (
	NFPROTO_IPV4 ipsetFamilyEnum = 2
	NFPROTO_IPV6 ipsetFamilyEnum = 10
)

func ipsetFamilyEnumFromByte(b uint8) ipsetFamilyEnum {
	switch b {
	case 2:
		return NFPROTO_IPV4
	case 10:
		return NFPROTO_IPV6
	default:
		panic(fmt.Errorf("Invalid IPSet family %d", b))
	}
}

type ipsetProtoEnum uint8

// possible IPSet protocols
const (
	IPSetPortRangeAny ipsetProtoEnum = 0
	IPSetPortRangeTCP ipsetProtoEnum = TCP_PROTO
	IPSetPortRangeUDP ipsetProtoEnum = UDP_PROTO
)

func ipsetProtoEnumFromByte(b uint8) ipsetProtoEnum {
	switch b {
	case 0:
		return IPSetPortRangeAny
	case TCP_PROTO:
		return IPSetPortRangeTCP
	case UDP_PROTO:
		return IPSetPortRangeUDP
	default:
		panic(fmt.Errorf("Invalid IPSet family %d", b))
	}
}
