package netlink

import (
	"net"
)

// XfrmStateAlgo represents the algorithm to use for the ipsec encryption.
type XfrmStateAlgo struct {
	Name        string
	Key         []byte
	TruncateLen int // Auth only
}

// XfrmState represents the state of an ipsec policy. It optionally
// contains an XfrmStateAlgo for encryption and one for authentication.
type XfrmState struct {
	Dst   net.IP
	Src   net.IP
	Proto Proto
	Mode  Mode
	Spi   int
	Reqid int
	ReplayWindow int
	Auth  *XfrmStateAlgo
	Crypt *XfrmStateAlgo
}
