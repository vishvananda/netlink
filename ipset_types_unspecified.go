// +build !linux

package netlink

type unixNlMsghdr struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

const unixSizeofNlMsghdr = 16
