package nl

const (
	DEFAULT_CHANGE = 0xFFFFFFFF
)

const (
	IFLA_INFO_UNSPEC = iota
	IFLA_INFO_KIND   = iota
	IFLA_INFO_DATA   = iota
	IFLA_INFO_XSTATS = iota
	IFLA_INFO_MAX    = IFLA_INFO_XSTATS
)

const (
	IFLA_VLAN_UNSPEC      = iota
	IFLA_VLAN_ID          = iota
	IFLA_VLAN_FLAGS       = iota
	IFLA_VLAN_EGRESS_QOS  = iota
	IFLA_VLAN_INGRESS_QOS = iota
	IFLA_VLAN_PROTOCOL    = iota
	IFLA_VLAN_MAX         = IFLA_VLAN_PROTOCOL
)

const (
	VETH_INFO_UNSPEC = iota
	VETH_INFO_PEER   = iota
	VETH_INFO_MAX    = VETH_INFO_PEER
)

const (
	// not defined in syscall
	IFLA_NET_NS_FD = 28
)
