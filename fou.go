package netlink

import (
	"net"
)

type Fou struct {
	Family    int
	Protocol  int
	EncapType int
	Port      int
	PeerPort  int
	LocalAddr net.IP
	PeerAddr  net.IP
	IfIndex   int
}
