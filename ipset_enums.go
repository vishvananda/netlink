package netlink

type ipsetTypeEnum string

func (t ipsetTypeEnum) toString() string {
	return string(t)
}

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

type ipsetFamilyEnum uint8

func (f ipsetFamilyEnum) toUint8() uint8 {
	return uint8(f)
}

// http://git.netfilter.org/ipset/tree/include/libipset/nfproto.h
const (
	NFPROTO_IPV4 ipsetFamilyEnum = 2
	NFPROTO_IPV6 ipsetFamilyEnum = 10
)
