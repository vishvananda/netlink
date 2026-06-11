package netlink

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// NetDevQueueType identifies the direction of a netdev queue.
type NetDevQueueType uint32

const (
	NetDevQueueTypeRx NetDevQueueType = nl.NETDEV_QUEUE_TYPE_RX
	NetDevQueueTypeTx NetDevQueueType = nl.NETDEV_QUEUE_TYPE_TX
)

// NetDevQueueID identifies a single queue on a netdevice by its id and type.
type NetDevQueueID struct {
	ID   uint32
	Type NetDevQueueType
}

// NetDevQueueLease describes the binding of a virtual netdev queue to a real
// queue on a physical netdevice. A leased queue acts as a proxy: memory
// provider (io_uring zero-copy, devmem) and AF_XDP operations issued against
// the virtual queue are forwarded to the physical queue named here.
type NetDevQueueLease struct {
	// IfIndex is the physical netdevice the queue is leased from.
	IfIndex uint32
	// Queue is the real queue on the physical device.
	Queue NetDevQueueID
	// NetNSID is the network namespace id of the physical device, relative
	// to the caller's namespace. NetNSIDSet reports whether it was provided.
	NetNSID    int32
	NetNSIDSet bool
}

// NetDevQueue is a queue on a netdevice as reported by queue-get.
type NetDevQueue struct {
	IfIndex uint32
	ID      uint32
	Type    NetDevQueueType
	NapiID  uint32
	// Lease is non-nil when the queue is bound to a queue on another
	// netdevice via queue leasing.
	Lease *NetDevQueueLease
}

// netdevRequest builds and executes a request against the "netdev" generic
// netlink family, returning the attribute lists of each response message.
func (h *Handle) netdevRequest(command uint8, flags int, attrs []*nl.RtAttr) ([][]syscall.NetlinkRouteAttr, error) {
	f, err := h.GenlFamilyGet(nl.NETDEV_FAMILY_NAME)
	if err != nil {
		return nil, err
	}
	req := h.newNetlinkRequest(int(f.ID), flags)
	req.AddData(&nl.Genlmsg{
		Command: command,
		Version: nl.NETDEV_FAMILY_VERSION,
	})
	for _, a := range attrs {
		req.AddData(a)
	}

	msgs, executeErr := req.Execute(unix.NETLINK_GENERIC, 0)
	if executeErr != nil && !errors.Is(executeErr, ErrDumpInterrupted) {
		return nil, executeErr
	}
	out := make([][]syscall.NetlinkRouteAttr, 0, len(msgs))
	for _, m := range msgs {
		parsed, err := nl.ParseRouteAttr(m[nl.SizeofGenlmsg:])
		if err != nil {
			return nil, err
		}
		out = append(out, parsed)
	}
	return out, executeErr
}

// parseNetDevQueueID decodes a queue-id nested attribute (NETDEV_A_QUEUE_ID
// and NETDEV_A_QUEUE_TYPE) into a NetDevQueueID.
func parseNetDevQueueID(value []byte) (NetDevQueueID, error) {
	var q NetDevQueueID
	attrs, err := nl.ParseRouteAttr(value)
	if err != nil {
		return q, err
	}
	for _, a := range attrs {
		switch a.Attr.Type & nl.NLA_TYPE_MASK {
		case nl.NETDEV_A_QUEUE_ID:
			q.ID = native.Uint32(a.Value)
		case nl.NETDEV_A_QUEUE_TYPE:
			q.Type = NetDevQueueType(native.Uint32(a.Value))
		}
	}
	return q, nil
}

// parseNetDevQueueLease decodes a lease nested attribute (the physical
// ifindex, the nested queue-id, and an optional netns-id) into a
// NetDevQueueLease.
func parseNetDevQueueLease(value []byte) (*NetDevQueueLease, error) {
	attrs, err := nl.ParseRouteAttr(value)
	if err != nil {
		return nil, err
	}
	lease := &NetDevQueueLease{}
	for _, a := range attrs {
		switch a.Attr.Type & nl.NLA_TYPE_MASK {
		case nl.NETDEV_A_LEASE_IFINDEX:
			lease.IfIndex = native.Uint32(a.Value)
		case nl.NETDEV_A_LEASE_QUEUE:
			q, err := parseNetDevQueueID(a.Value)
			if err != nil {
				return nil, err
			}
			lease.Queue = q
		case nl.NETDEV_A_LEASE_NETNS_ID:
			lease.NetNSID = int32(native.Uint32(a.Value))
			lease.NetNSIDSet = true
		}
	}
	return lease, nil
}

// parseNetDevQueue decodes the attributes of a queue-get response into a
// NetDevQueue, including its nested lease attribute when present.
func parseNetDevQueue(attrs []syscall.NetlinkRouteAttr) (*NetDevQueue, error) {
	q := &NetDevQueue{}
	for _, a := range attrs {
		switch a.Attr.Type & nl.NLA_TYPE_MASK {
		case nl.NETDEV_A_QUEUE_IFINDEX:
			q.IfIndex = native.Uint32(a.Value)
		case nl.NETDEV_A_QUEUE_ID:
			q.ID = native.Uint32(a.Value)
		case nl.NETDEV_A_QUEUE_TYPE:
			q.Type = NetDevQueueType(native.Uint32(a.Value))
		case nl.NETDEV_A_QUEUE_NAPI_ID:
			q.NapiID = native.Uint32(a.Value)
		case nl.NETDEV_A_QUEUE_LEASE:
			lease, err := parseNetDevQueueLease(a.Value)
			if err != nil {
				return nil, err
			}
			q.Lease = lease
		}
	}
	return q, nil
}

// NetDevQueueGet returns information about a single queue on the netdevice
// identified by ifIndex, including its lease binding if it has one.
// Equivalent to: `ynl --do queue-get --json '{"ifindex":.., "id":.., "type":..}'`
func NetDevQueueGet(ifIndex int, id uint32, qType NetDevQueueType) (*NetDevQueue, error) {
	return pkgHandle.NetDevQueueGet(ifIndex, id, qType)
}

// NetDevQueueGet returns information about a single queue. See [NetDevQueueGet].
func (h *Handle) NetDevQueueGet(ifIndex int, id uint32, qType NetDevQueueType) (*NetDevQueue, error) {
	attrs := []*nl.RtAttr{
		nl.NewRtAttr(nl.NETDEV_A_QUEUE_IFINDEX, nl.Uint32Attr(uint32(ifIndex))),
		nl.NewRtAttr(nl.NETDEV_A_QUEUE_ID, nl.Uint32Attr(id)),
		nl.NewRtAttr(nl.NETDEV_A_QUEUE_TYPE, nl.Uint32Attr(uint32(qType))),
	}
	msgs, err := h.netdevRequest(nl.NETDEV_CMD_QUEUE_GET, unix.NLM_F_ACK, attrs)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("netlink: no response for queue-get")
	}
	return parseNetDevQueue(msgs[0])
}

// NetDevQueueCreateRequest describes a queue-create operation that creates a
// new rx queue on a virtual netdevice and leases it to a real queue on a
// physical netdevice.
type NetDevQueueCreateRequest struct {
	// IfIndex is the virtual netdevice on which to create the new queue.
	IfIndex int
	// Type is the queue type. Only rx queues may be leased today.
	Type NetDevQueueType
	// Lease names the physical device and real queue to lease.
	Lease NetDevQueueLease
}

// NetDevQueueCreate creates a new queue on a virtual netdevice and leases it to
// a real queue on a physical netdevice, returning the new queue's id. Requires
// CAP_NET_ADMIN.
// Equivalent to: `ynl --do queue-create --json
// '{"ifindex":.., "type":"rx", "lease":{"ifindex":.., "queue":{"id":.., "type":"rx"}}}'`
func NetDevQueueCreate(req NetDevQueueCreateRequest) (uint32, error) {
	return pkgHandle.NetDevQueueCreate(req)
}

// NetDevQueueCreate creates and leases a queue. See [NetDevQueueCreate].
func (h *Handle) NetDevQueueCreate(req NetDevQueueCreateRequest) (uint32, error) {
	// Build the nested lease attribute. Container attributes must carry the
	// NLA_F_NESTED flag: the kernel's nla_parse_nested rejects them otherwise
	// ("NLA_F_NESTED is missing").
	lease := nl.NewRtAttr(unix.NLA_F_NESTED|nl.NETDEV_A_QUEUE_LEASE, nil)
	lease.AddRtAttr(nl.NETDEV_A_LEASE_IFINDEX, nl.Uint32Attr(req.Lease.IfIndex))
	if req.Lease.NetNSIDSet {
		lease.AddRtAttr(nl.NETDEV_A_LEASE_NETNS_ID, nl.Uint32Attr(uint32(req.Lease.NetNSID)))
	}
	queue := lease.AddRtAttr(unix.NLA_F_NESTED|nl.NETDEV_A_LEASE_QUEUE, nil)
	queue.AddRtAttr(nl.NETDEV_A_QUEUE_ID, nl.Uint32Attr(req.Lease.Queue.ID))
	queue.AddRtAttr(nl.NETDEV_A_QUEUE_TYPE, nl.Uint32Attr(uint32(req.Lease.Queue.Type)))

	attrs := []*nl.RtAttr{
		nl.NewRtAttr(nl.NETDEV_A_QUEUE_IFINDEX, nl.Uint32Attr(uint32(req.IfIndex))),
		nl.NewRtAttr(nl.NETDEV_A_QUEUE_TYPE, nl.Uint32Attr(uint32(req.Type))),
		lease,
	}

	msgs, err := h.netdevRequest(nl.NETDEV_CMD_QUEUE_CREATE, unix.NLM_F_ACK, attrs)
	if err != nil {
		return 0, err
	}
	if len(msgs) == 0 {
		return 0, fmt.Errorf("netlink: no response for queue-create")
	}
	for _, a := range msgs[0] {
		if a.Attr.Type&nl.NLA_TYPE_MASK == nl.NETDEV_A_QUEUE_ID {
			return native.Uint32(a.Value), nil
		}
	}
	return 0, fmt.Errorf("netlink: queue-create reply missing queue id")
}
