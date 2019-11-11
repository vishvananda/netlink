package netlink

// NFNL_SUBSYS_IPSET netfilter netlink message types
// https://github.com/torvalds/linux/blob/9e66317d3c92ddaab330c125dfe9d06eee268aff/include/uapi/linux/netfilter/nfnetlink.h#L56
const NFNL_SUBSYS_IPSET = 6

// IPSET_PROTOCOL The protocol version
// http://git.netfilter.org/ipset/tree/include/libipset/linux_ip_set.h
const IPSET_PROTOCOL = 6

// IPSET_MAXNAMELEN The max length of strings including NUL: set and type identifiers
const IPSET_MAXNAMELEN = 32

/* The maximum permissible comment length we will accept over netlink */
const IPSET_MAX_COMMENT_SIZE = 255

// ipset of my arch linux vbox, makes revision 4
const IPSET_ATTR_REVISION_VALUE = 4

// Message types and commands
const (
	IPSET_CMD_NONE     = iota
	IPSET_CMD_PROTOCOL /* 1: Return protocol version */
	IPSET_CMD_CREATE   /* 2: Create a new (empty) set */
	IPSET_CMD_DESTROY  /* 3: Destroy a (empty) set */
	IPSET_CMD_FLUSH    /* 4: Remove all elements from a set */
	IPSET_CMD_RENAME   /* 5: Rename a set */
	IPSET_CMD_SWAP     /* 6: Swap two sets */
	IPSET_CMD_LIST     /* 7: List sets */
	IPSET_CMD_SAVE     /* 8: Save sets */
	IPSET_CMD_ADD      /* 9: Add an element to a set */
	IPSET_CMD_DEL      /* 10: Delete an element from a set */
	IPSET_CMD_TEST     /* 11: Test an element in a set */
	IPSET_CMD_HEADER   /* 12: Get set header data only */
	IPSET_CMD_TYPE     /* 13: Get set type */
)

/* Attributes at command level */
const (
	IPSET_ATTR_UNSPEC   = iota
	IPSET_ATTR_PROTOCOL /* 1: Protocol version */
	IPSET_ATTR_SETNAME  /* 2: Name of the set */
	IPSET_ATTR_TYPENAME /* 3: Typename */
)

/* Attributes at command level */
const (
	IPSET_ATTR_SETNAME2     = IPSET_ATTR_TYPENAME + iota /* Setname at rename/swap */
	IPSET_ATTR_REVISION                                  /* 4: Settype revision */
	IPSET_ATTR_FAMILY                                    /* 5: Settype family */
	IPSET_ATTR_FLAGS                                     /* 6: Flags at command level */
	IPSET_ATTR_DATA                                      /* 7: Nested attributes */
	IPSET_ATTR_ADT                                       /* 8: Multiple data containers */
	IPSET_ATTR_LINENO                                    /* 9: Restore lineno */
	IPSET_ATTR_PROTOCOL_MIN                              /* 10: Minimal supported version number */
)

/* Attributes at command level */
const (
	IPSET_ATTR_REVISION_MIN = IPSET_ATTR_PROTOCOL_MIN + iota /* type rev min */
	__IPSET_ATTR_CMD_MAX
)

// ATTR flags
const (
	NLA_F_NESTED = (1 << 15)
)

/* CADT specific attributes */
const (
	IPSET_ATTR_IP = IPSET_ATTR_UNSPEC + 1
)

/* CADT specific attributes */
const (
	IPSET_ATTR_IP_FROM = IPSET_ATTR_IP + iota
	IPSET_ATTR_IP_TO   /* 2 */
	IPSET_ATTR_CIDR    /* 3 */
	IPSET_ATTR_PORT    /* 4 */
)

/* CADT specific attributes */
const (
	IPSET_ATTR_PORT_FROM  = IPSET_ATTR_PORT + iota
	IPSET_ATTR_PORT_TO    /* 5 */
	IPSET_ATTR_TIMEOUT    /* 6 */
	IPSET_ATTR_PROTO      /* 7 */
	IPSET_ATTR_CADT_FLAGS /* 8 */
)

/* CADT specific attributes */
const (
	IPSET_ATTR_CADT_LINENO = IPSET_ATTR_LINENO + iota /* 9 */
	IPSET_ATTR_MARK                                   /* 10 */
	IPSET_ATTR_MARKMASK                               /* 11 */
)

/* CADT specific attributes */
const (
	/* Reserve empty slots */
	IPSET_ATTR_CADT_MAX = 16 + iota
	/* Create-only specific attributes */
	IPSET_ATTR_GC
	IPSET_ATTR_HASHSIZE
	IPSET_ATTR_MAXELEM
	IPSET_ATTR_NETMASK
	IPSET_ATTR_PROBES
	IPSET_ATTR_RESIZE
	IPSET_ATTR_SIZE
	/* Kernel-only */
	IPSET_ATTR_ELEMENTS
	IPSET_ATTR_REFERENCES
	IPSET_ATTR_MEMSIZE
)

/* Flags at CADT attribute level, upper half of cmdattrs */
const (
	IPSET_FLAG_BIT_BEFORE        = 0
	IPSET_FLAG_BEFORE            = (1 << IPSET_FLAG_BIT_BEFORE)
	IPSET_FLAG_BIT_PHYSDEV       = 1
	IPSET_FLAG_PHYSDEV           = (1 << IPSET_FLAG_BIT_PHYSDEV)
	IPSET_FLAG_BIT_NOMATCH       = 2
	IPSET_FLAG_NOMATCH           = (1 << IPSET_FLAG_BIT_NOMATCH)
	IPSET_FLAG_BIT_WITH_COUNTERS = 3
	IPSET_FLAG_WITH_COUNTERS     = (1 << IPSET_FLAG_BIT_WITH_COUNTERS)
	IPSET_FLAG_BIT_WITH_COMMENT  = 4
	IPSET_FLAG_WITH_COMMENT      = (1 << IPSET_FLAG_BIT_WITH_COMMENT)
	IPSET_FLAG_BIT_WITH_FORCEADD = 5
	IPSET_FLAG_WITH_FORCEADD     = (1 << IPSET_FLAG_BIT_WITH_FORCEADD)
	IPSET_FLAG_BIT_WITH_SKBINFO  = 6
	IPSET_FLAG_WITH_SKBINFO      = (1 << IPSET_FLAG_BIT_WITH_SKBINFO)
	IPSET_FLAG_CADT_MAX          = 15
)

/* ADT specific attributes */
const (
	IPSET_ATTR_ETHER = IPSET_ATTR_CADT_MAX + 1 + iota
	IPSET_ATTR_NAME
	IPSET_ATTR_NAMEREF
	IPSET_ATTR_IP2
	IPSET_ATTR_CIDR2
	IPSET_ATTR_IP2_TO
	IPSET_ATTR_IFACE
	IPSET_ATTR_BYTES
	IPSET_ATTR_PACKETS
	IPSET_ATTR_COMMENT
	IPSET_ATTR_SKBMARK
	IPSET_ATTR_SKBPRIO
	IPSET_ATTR_SKBQUEUE
	IPSET_ATTR_PAD
	__IPSET_ATTR_ADT_MAX
)

/* Environment option flags */
const (
	IPSET_ENV_BIT_SORTED       = 0
	IPSET_ENV_SORTED           = (1 << IPSET_ENV_BIT_SORTED)
	IPSET_ENV_BIT_QUIET        = 1
	IPSET_ENV_QUIET            = (1 << IPSET_ENV_BIT_QUIET)
	IPSET_ENV_BIT_RESOLVE      = 2
	IPSET_ENV_RESOLVE          = (1 << IPSET_ENV_BIT_RESOLVE)
	IPSET_ENV_BIT_EXIST        = 3
	IPSET_ENV_EXIST            = (1 << IPSET_ENV_BIT_EXIST)
	IPSET_ENV_BIT_LIST_SETNAME = 4
	IPSET_ENV_LIST_SETNAME     = (1 << IPSET_ENV_BIT_LIST_SETNAME)
	IPSET_ENV_BIT_LIST_HEADER  = 5
	IPSET_ENV_LIST_HEADER      = (1 << IPSET_ENV_BIT_LIST_HEADER)
)

/* values were reverse engineered */
const (
	IPSET_LIST_TERSE = 0x04
)
