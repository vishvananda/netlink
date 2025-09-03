package netlink

import "net/netip"

type Fou struct {
	Family    int
	Port      int
	Protocol  int
	EncapType int
	Local     netip.Addr
	Peer      netip.Addr
	PeerPort  int
	IfIndex   int
}
