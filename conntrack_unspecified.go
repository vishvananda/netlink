// +build !linux

package netlink

import "net"

// ConntrackTableType Conntrack table for the netlink operation
type ConntrackTableType uint8

const (
	ConntrackTable = 1
)

// InetFamily Family type
type InetFamily uint8

// ConntrackFlow placeholder
type ConntrackFlow struct{}

// ConntrackFilter placeholder
type ConntrackFilter struct{}

type ConntrackFilterType uint8

const (
	ConntrackOrigSrcIP   = iota                // -orig-src ip    Source address from original direction
	ConntrackOrigDstIP                         // -orig-dst ip    Destination address from original direction
	ConntrackReplySrcIP                        // --reply-src ip  Reply Source IP
	ConntrackReplyDstIP                        // --reply-dst ip  Reply Destination IP
	ConntrackReplyAnyIP                        // Match source or destination reply IP
	ConntrackOrigSrcPort                       // --orig-port-src port    Source port in original direction
	ConntrackOrigDstPort                       // --orig-port-dst port    Destination port in original direction
	ConntrackNatSrcIP    = ConntrackReplySrcIP // deprecated use instead ConntrackReplySrcIP
	ConntrackNatDstIP    = ConntrackReplyDstIP // deprecated use instead ConntrackReplyDstIP
	ConntrackNatAnyIP    = ConntrackReplyAnyIP // deprecated use instead ConntrackReplyAnyIP
)

func (f *ConntrackFilter) AddIP(tp ConntrackFilterType, ip net.IP) error {
	return ErrNotImplemented
}
func (f *ConntrackFilter) AddPort(tp ConntrackFilterType, port uint16) error {

	return ErrNotImplemented
}
func (f *ConntrackFilter) AddProtocol(proto uint8) error {
	return ErrNotImplemented
}

// ConntrackTableList returns the flow list of a table of a specific family
// conntrack -L [table] [options]          List conntrack or expectation table
func ConntrackTableList(table ConntrackTableType, family InetFamily) ([]*ConntrackFlow, error) {
	return nil, ErrNotImplemented
}

// ConntrackTableFlush flushes all the flows of a specified table
// conntrack -F [table]            Flush table
// The flush operation applies to all the family types
func ConntrackTableFlush(table ConntrackTableType) error {
	return ErrNotImplemented
}

// ConntrackDeleteFilter deletes entries on the specified table on the base of the filter
// conntrack -D [table] parameters         Delete conntrack or expectation
func ConntrackDeleteFilter(table ConntrackTableType, family InetFamily, filter *ConntrackFilter) (uint, error) {
	return 0, ErrNotImplemented
}

// ConntrackTableList returns the flow list of a table of a specific family using the netlink handle passed
// conntrack -L [table] [options]          List conntrack or expectation table
func (h *Handle) ConntrackTableList(table ConntrackTableType, family InetFamily) ([]*ConntrackFlow, error) {
	return nil, ErrNotImplemented
}

// ConntrackTableFlush flushes all the flows of a specified table using the netlink handle passed
// conntrack -F [table]            Flush table
// The flush operation applies to all the family types
func (h *Handle) ConntrackTableFlush(table ConntrackTableType) error {
	return ErrNotImplemented
}

// ConntrackDeleteFilter deletes entries on the specified table on the base of the filter using the netlink handle passed
// conntrack -D [table] parameters         Delete conntrack or expectation
func (h *Handle) ConntrackDeleteFilter(table ConntrackTableType, family InetFamily, filter *ConntrackFilter) (uint, error) {
	return 0, ErrNotImplemented
}
