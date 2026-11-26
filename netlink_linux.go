package netlink

import "github.com/vishvananda/netlink/nl"

// Family type definitions
const (
	FAMILY_ALL  = nl.FAMILY_ALL
	FAMILY_V4   = nl.FAMILY_V4
	FAMILY_V6   = nl.FAMILY_V6
	FAMILY_MPLS = nl.FAMILY_MPLS
)

// ErrDumpInterrupted is an alias for [nl.ErrDumpInterrupted].
var ErrDumpInterrupted = nl.ErrDumpInterrupted

// closeOnDone closes s once done is closed or the returned stop function is
// called, whichever happens first. Subscribe functions call stop when their
// receive goroutine exits, so the socket does not outlive it. A nil done never
// fires, so only stop closes the socket then.
func closeOnDone(s *nl.NetlinkSocket, done <-chan struct{}) (stop func()) {
	exited := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-exited:
		}
		s.Close()
	}()
	return func() { close(exited) }
}
