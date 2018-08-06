package netlink

import "golang.org/x/sys/unix"

type unixNlMsghdr = unix.NlMsghdr

const unixSizeofNlMsghdr = unix.SizeofNlMsghdr
