package netlink

// NFNL_SUBSYS_IPSET netfilter netlink message types
// https://github.com/torvalds/linux/blob/9e66317d3c92ddaab330c125dfe9d06eee268aff/include/uapi/linux/netfilter/nfnetlink.h#L56
const NFNL_SUBSYS_IPSET = 6

// IPSET_PROTOCOL The protocol version
// http://git.netfilter.org/ipset/tree/include/libipset/linux_ip_set.h
const IPSET_PROTOCOL = 6

// IPSET_MAXNAMELEN The max length of strings including NUL: set and type identifiers
const IPSET_MAXNAMELEN = 32

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
const (
	IPSET_ATTR_REVISION_MIN = IPSET_ATTR_PROTOCOL_MIN + iota /* type rev min */
	__IPSET_ATTR_CMD_MAX
)

// ATTR flags
const (
	NLA_F_NESTED = (1 << 15)
)

/* Keywords */
const (
	IPSET_ARG_NONE = iota
	/* Family and aliases */
	IPSET_ARG_FAMILY /* family */
	IPSET_ARG_INET   /* -4 */
	IPSET_ARG_INET6  /* -6 */
	/* Hash types */
	IPSET_ARG_HASHSIZE /* hashsize */
	IPSET_ARG_MAXELEM  /* maxelem */
	/* Ignored options: backward compatibilty */
	IPSET_ARG_PROBES          /* probes */
	IPSET_ARG_RESIZE          /* resize */
	IPSET_ARG_GC              /* gc */
	IPSET_ARG_IGNORED_FROM    /* from */
	IPSET_ARG_IGNORED_TO      /* to */
	IPSET_ARG_IGNORED_NETWORK /* network */
	/* List type */
	IPSET_ARG_SIZE /* size */
	/* IP-type elements */
	IPSET_ARG_IPRANGE /* range */
	IPSET_ARG_NETMASK /* netmask */
	/* Port-type elements */
	IPSET_ARG_PORTRANGE /* range */
	/* Setname type elements */
	IPSET_ARG_BEFORE /* before */
	IPSET_ARG_AFTER  /* after */
	/* Backward compatibility */
	IPSET_ARG_FROM_IP   /* from */
	IPSET_ARG_TO_IP     /* to */
	IPSET_ARG_NETWORK   /* network */
	IPSET_ARG_FROM_PORT /* from */
	IPSET_ARG_TO_PORT   /* to */
	/* Extra flags, options */
	IPSET_ARG_FORCEADD /* forceadd */
	IPSET_ARG_MARKMASK /* markmask */
	IPSET_ARG_NOMATCH  /* nomatch */
	/* Extensions */
	IPSET_ARG_TIMEOUT     /* timeout */
	IPSET_ARG_COUNTERS    /* counters */
	IPSET_ARG_PACKETS     /* packets */
	IPSET_ARG_BYTES       /* bytes */
	IPSET_ARG_COMMENT     /* comment */
	IPSET_ARG_ADT_COMMENT /* comment */
	IPSET_ARG_SKBINFO     /* skbinfo */
	IPSET_ARG_SKBMARK     /* skbmark */
	IPSET_ARG_SKBPRIO     /* skbprio */
	IPSET_ARG_SKBQUEUE    /* skbqueue */
	IPSET_ARG_MAX
)

/* CADT specific attributes */
const (
	IPSET_ATTR_IP = IPSET_ATTR_UNSPEC + 1
)
const (
	IPSET_ATTR_IP_FROM = IPSET_ATTR_IP + iota
	IPSET_ATTR_IP_TO   /* 2 */
	IPSET_ATTR_CIDR    /* 3 */
	IPSET_ATTR_PORT    /* 4 */
)
const (
	IPSET_ATTR_PORT_FROM  = IPSET_ATTR_PORT + iota
	IPSET_ATTR_PORT_TO    /* 5 */
	IPSET_ATTR_TIMEOUT    /* 6 */
	IPSET_ATTR_PROTO      /* 7 */
	IPSET_ATTR_CADT_FLAGS /* 8 */
)
const (
	IPSET_ATTR_CADT_LINENO = IPSET_ATTR_LINENO + iota /* 9 */
	IPSET_ATTR_MARK                                   /* 10 */
	IPSET_ATTR_MARKMASK                               /* 11 */
)
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
