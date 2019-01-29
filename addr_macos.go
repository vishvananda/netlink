// Stubfile to let netlink package compile on macos
// This file is only to make compilation succeed.
// Functionality is NOT supported on macos.

// +build darwin

// Only the definations needed for compilation on MacOs are added here.
// When adding the definitions, copy the corresponding ones from
//	addr_linux.go
package netlink

import (
	"net"

	"github.com/vishvananda/netns"
)

type AddrUpdate struct {
	LinkAddress net.IPNet
	LinkIndex   int
	Flags       int
	Scope       int
	PreferedLft int
	ValidLft    int
	NewAddr     bool // true=added false=deleted
}

type AddrSubscribeOptions struct {
	Namespace         *netns.NsHandle
	ErrorCallback     func(error)
	ListExisting      bool
	ReceiveBufferSize int
}

func AddrSubscribeWithOptions(ch chan<- AddrUpdate, done <-chan struct{}, options AddrSubscribeOptions) error {
	return nil
}
