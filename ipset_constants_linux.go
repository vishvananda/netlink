package netlink

import (
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	unixNLM_F_ACK              = unix.NLM_F_ACK
	unixNETLINK_NETFILTER      = unix.NETLINK_NETFILTER
	syscallNLA_F_NET_BYTEORDER = syscall.NLA_F_NET_BYTEORDER
)
