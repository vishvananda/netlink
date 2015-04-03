package nl

const (
	DEFAULT_CHANGE = 0xFFFFFFFF
)

const (
	ETH_ALEN = 6
)

const (
	IFLA_INFO_UNSPEC = iota
	IFLA_INFO_KIND
	IFLA_INFO_DATA
	IFLA_INFO_XSTATS
	IFLA_INFO_MAX = IFLA_INFO_XSTATS
)

const (
	IFLA_VLAN_UNSPEC = iota
	IFLA_VLAN_ID
	IFLA_VLAN_FLAGS
	IFLA_VLAN_EGRESS_QOS
	IFLA_VLAN_INGRESS_QOS
	IFLA_VLAN_PROTOCOL
	IFLA_VLAN_MAX = IFLA_VLAN_PROTOCOL
)

const (
	VETH_INFO_UNSPEC = iota
	VETH_INFO_PEER
	VETH_INFO_MAX = VETH_INFO_PEER
)

const (
	IFLA_VXLAN_UNSPEC = iota
	IFLA_VXLAN_ID
	IFLA_VXLAN_GROUP
	IFLA_VXLAN_LINK
	IFLA_VXLAN_LOCAL
	IFLA_VXLAN_TTL
	IFLA_VXLAN_TOS
	IFLA_VXLAN_LEARNING
	IFLA_VXLAN_AGEING
	IFLA_VXLAN_LIMIT
	IFLA_VXLAN_PORT_RANGE
	IFLA_VXLAN_PROXY
	IFLA_VXLAN_RSC
	IFLA_VXLAN_L2MISS
	IFLA_VXLAN_L3MISS
	IFLA_VXLAN_PORT
	IFLA_VXLAN_GROUP6
	IFLA_VXLAN_LOCAL6
	IFLA_VXLAN_MAX = IFLA_VXLAN_LOCAL6
)

const (
	BRIDGE_MODE_UNSPEC = iota
	BRIDGE_MODE_HAIRPIN
)

const (
	IFLA_BRPORT_UNSPEC = iota
	IFLA_BRPORT_STATE
	IFLA_BRPORT_PRIORITY
	IFLA_BRPORT_COST
	IFLA_BRPORT_MODE
	IFLA_BRPORT_GUARD
	IFLA_BRPORT_PROTECT
	IFLA_BRPORT_FAST_LEAVE
	IFLA_BRPORT_LEARNING
	IFLA_BRPORT_UNICAST_FLOOD
	IFLA_BRPORT_MAX = IFLA_BRPORT_UNICAST_FLOOD
)

const (
	IFLA_IPVLAN_UNSPEC = iota
	IFLA_IPVLAN_MODE
	IFLA_IPVLAN_MAX = IFLA_IPVLAN_MODE
)

const (
	// not defined in syscall
	IFLA_NET_NS_FD = 28
)

const (
	IFLA_MACVLAN_UNSPEC = iota
	IFLA_MACVLAN_MODE
	IFLA_MACVLAN_FLAGS
	IFLA_MACVLAN_MAX = IFLA_MACVLAN_FLAGS
)

const (
	MACVLAN_MODE_PRIVATE  = 1
	MACVLAN_MODE_VEPA     = 2
	MACVLAN_MODE_BRIDGE   = 4
	MACVLAN_MODE_PASSTHRU = 8
	MACVLAN_MODE_SOURCE   = 16
)

const (
	IFLA_BOND_UNSPEC = iota
	IFLA_BOND_MODE
	IFLA_BOND_ACTIVE_SLAVE
	IFLA_BOND_MIIMON
	IFLA_BOND_UPDELAY
	IFLA_BOND_DOWNDELAY
	IFLA_BOND_USE_CARRIER
	IFLA_BOND_ARP_INTERVAL
	IFLA_BOND_ARP_IP_TARGET
	IFLA_BOND_ARP_VALIDATE
	IFLA_BOND_ARP_ALL_TARGETS
	IFLA_BOND_PRIMARY
	IFLA_BOND_PRIMARY_RESELECT
	IFLA_BOND_FAIL_OVER_MAC
	IFLA_BOND_XMIT_HASH_POLICY
	IFLA_BOND_RESEND_IGMP
	IFLA_BOND_NUM_PEER_NOTIF
	IFLA_BOND_ALL_SLAVES_ACTIVE
	IFLA_BOND_MIN_LINKS
	IFLA_BOND_LP_INTERVAL
	IFLA_BOND_PACKETS_PER_SLAVE
	IFLA_BOND_AD_LACP_RATE
	IFLA_BOND_AD_SELECT
	IFLA_BOND_AD_INFO
)

const (
	IFLA_BOND_AD_INFO_UNSPEC = iota
	IFLA_BOND_AD_INFO_AGGREGATOR
	IFLA_BOND_AD_INFO_NUM_PORTS
	IFLA_BOND_AD_INFO_ACTOR_KEY
	IFLA_BOND_AD_INFO_PARTNER_KEY
	IFLA_BOND_AD_INFO_PARTNER_MAC
)

const (
	IFLA_BOND_SLAVE_UNSPEC = iota
	IFLA_BOND_SLAVE_STATE
	IFLA_BOND_SLAVE_MII_STATUS
	IFLA_BOND_SLAVE_LINK_FAILURE_COUNT
	IFLA_BOND_SLAVE_PERM_HWADDR
	IFLA_BOND_SLAVE_QUEUE_ID
	IFLA_BOND_SLAVE_AD_AGGREGATOR_ID
)
