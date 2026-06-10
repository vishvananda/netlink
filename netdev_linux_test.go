package netlink

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
)

// setupNetDevTest skips the test unless the running kernel exposes the netdev
// genl family and the required commands.
func setupNetDevTest(t *testing.T, reqCommands ...int) {
	t.Helper()
	skipUnlessRoot(t)
	gFam, err := GenlFamilyGet(nl.NETDEV_FAMILY_NAME)
	if err != nil {
		t.Skip("netdev genl family not available")
	}
	for _, c := range reqCommands {
		found := false
		for _, op := range gFam.Ops {
			if op.ID == uint32(c) {
				found = true
				break
			}
		}
		if !found {
			t.Skipf("host doesn't support netdev command %d", c)
		}
	}
}

// netDevTestNetkitName returns a unique netkit device name for a test run, so
// that a stale interface left over from a previously interrupted run cannot
// collide with the one a test creates (which would otherwise cause a false
// skip at LinkAdd). The random suffix keeps the name well under IFNAMSIZ-1
// (15) bytes.
func netDevTestNetkitName(t *testing.T) string {
	t.Helper()
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("failed to generate random suffix: %v", err)
	}
	return fmt.Sprintf("nlt%02x%02x%02x", b[0], b[1], b[2])
}

// setupNetdevsim creates a netdevsim device with the requested number of rx/tx
// queues and returns its netdev plus a cleanup function. netdevsim implements
// the kernel's queue management ops, so it can act as a physical lease source
// without real hardware. The test is skipped if netdevsim is unavailable.
func setupNetdevsim(t *testing.T, queueCount int) (Link, func()) {
	t.Helper()
	skipUnlessKModuleLoaded(t, "netdevsim")

	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		t.Fatalf("failed to generate netdevsim id: %v", err)
	}
	id := int(idb[0])<<8 | int(idb[1])
	busDev := fmt.Sprintf("netdevsim%d", id)

	// Format: "<id> <port_count> <queue_count>".
	spec := fmt.Sprintf("%d 1 %d", id, queueCount)
	if err := os.WriteFile("/sys/bus/netdevsim/new_device", []byte(spec), 0o200); err != nil {
		t.Skipf("could not create netdevsim device: %v", err)
	}
	cleanup := func() {
		_ = os.WriteFile("/sys/bus/netdevsim/del_device", []byte(fmt.Sprintf("%d", id)), 0o200)
	}

	// The netdev is created asynchronously and udev renames it to the
	// predictable "eni<id>np1" form. Resolve it via netlink (LinkByName),
	// which does not depend on the /sys/class/net view. Fall back to scanning
	// the bus device's net/ directory in case naming differs.
	wantName := fmt.Sprintf("eni%dnp1", id)
	netDir := filepath.Join("/sys/bus/netdevsim/devices", busDev, "net")
	var link Link
	deadline := time.Now().Add(3 * time.Second)
	for {
		if l, err := LinkByName(wantName); err == nil {
			link = l
			break
		}
		if entries, err := os.ReadDir(netDir); err == nil && len(entries) > 0 {
			if l, lerr := LinkByName(entries[0].Name()); lerr == nil {
				link = l
				break
			}
		}
		if time.Now().After(deadline) {
			cleanup()
			t.Skipf("netdevsim netdev %q did not appear", wantName)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// queue-get only reports a queue once the device is up and its NAPI is
	// attached, so bring the device up before returning it.
	if err := LinkSetUp(link); err != nil {
		cleanup()
		t.Fatalf("failed to bring netdevsim %q up: %v", wantName, err)
	}
	return link, cleanup
}

// TestNetDevQueueLeaseRoundTrip verifies the full encode and decode path: it
// creates an rx queue on a netkit peer device and leases it to a real queue on
// a netdevsim device, then reads the netdevsim queue back and asserts the
// decoded lease points to the netkit peer with the exact expected values.
func TestNetDevQueueLeaseRoundTrip(t *testing.T) {
	setupNetDevTest(t, nl.NETDEV_CMD_QUEUE_CREATE, nl.NETDEV_CMD_QUEUE_GET)

	// netdevsim acts as the physical lease source; queue 1 is the real rx
	// queue we lease (queueCount=2 gives rx queues 0 and 1).
	const physQueueID = 1
	sim, simCleanup := setupNetdevsim(t, 2)
	defer simCleanup()
	physIdx := sim.Attrs().Index

	// netkit pair: only the non-primary (peer) device may lease, and it needs
	// rx queue headroom (real_num_rx_queues < num_rx_queues), so give the peer
	// the extra rx queues.
	peerName := netDevTestNetkitName(t)
	nk := &Netkit{
		LinkAttrs:  LinkAttrs{Name: netDevTestNetkitName(t)},
		Mode:       NETKIT_MODE_L3,
		Policy:     NETKIT_POLICY_FORWARD,
		PeerPolicy: NETKIT_POLICY_FORWARD,
	}
	nk.SetPeerAttrs(&LinkAttrs{Name: peerName, NumRxQueues: 4})
	if err := LinkAdd(nk); err != nil {
		t.Skipf("could not create netkit pair (kernel may lack support): %v", err)
	}
	defer LinkDel(nk)

	peer, err := LinkByName(peerName)
	if err != nil {
		t.Fatalf("failed to get netkit peer %s: %v", peerName, err)
	}
	peerIdx := peer.Attrs().Index

	// queue-create: make a new rx queue on the netkit peer and lease it to the
	// netdevsim rx queue.
	newID, err := NetDevQueueCreate(NetDevQueueCreateRequest{
		IfIndex: peerIdx,
		Type:    NetDevQueueTypeRx,
		Lease: NetDevQueueLease{
			IfIndex: uint32(physIdx),
			Queue:   NetDevQueueID{ID: physQueueID, Type: NetDevQueueTypeRx},
		},
	})
	if err != nil {
		t.Fatalf("queue-create failed: %v", err)
	}

	// queue-get the physical (netdevsim) queue: the kernel reports the lease
	// pointing back to the virtual netkit peer. This exercises the lease
	// decoder, and the values must match exactly.
	q, err := NetDevQueueGet(physIdx, physQueueID, NetDevQueueTypeRx)
	if err != nil {
		t.Fatalf("queue-get on physical queue failed: %v", err)
	}
	if q.Lease == nil {
		t.Fatalf("queue-get on leased physical queue returned no lease info")
	}
	if q.Lease.IfIndex != uint32(peerIdx) {
		t.Errorf("lease ifindex = %d, want netkit peer %d", q.Lease.IfIndex, peerIdx)
	}
	if q.Lease.Queue.ID != newID {
		t.Errorf("lease queue id = %d, want created queue %d", q.Lease.Queue.ID, newID)
	}
	if q.Lease.Queue.Type != NetDevQueueTypeRx {
		t.Errorf("lease queue type = %d, want rx", q.Lease.Queue.Type)
	}
}

// TestNetDevQueueCreateNetNSID verifies that the optional NETDEV_A_LEASE_NETNS_ID
// attribute is encoded and reaches the kernel. The kernel resolves netns-id
// (get_net_ns_by_id) only after fully parsing the nested lease structure and
// before it looks up the lease device, so a netns-id that resolves to no
// namespace fails with ENONET. A malformed message would be rejected earlier
// with EINVAL and could never reach ENONET, so this is a cut-and-dry, single
// errno assertion proving the nested encode (including netns-id) is correct.
// It needs no second namespace or special hardware.
func TestNetDevQueueCreateNetNSID(t *testing.T) {
	setupNetDevTest(t, nl.NETDEV_CMD_QUEUE_CREATE)

	name := netDevTestNetkitName(t)
	link := &Netkit{
		LinkAttrs:  LinkAttrs{Name: name, NumRxQueues: 4},
		Mode:       NETKIT_MODE_L3,
		Policy:     NETKIT_POLICY_FORWARD,
		PeerPolicy: NETKIT_POLICY_FORWARD,
	}
	if err := LinkAdd(link); err != nil {
		t.Skipf("could not create netkit device (kernel may lack support): %v", err)
	}
	defer LinkDel(link)

	nk, err := LinkByName(name)
	if err != nil {
		t.Fatalf("failed to get %s: %v", name, err)
	}

	// A non-negative netns-id that is very unlikely to map to any namespace
	// relative to the caller. The kernel reads the attribute only when the id
	// is >= 0, so this must not be negative.
	const bogusNetNSID = 0x6f6f6f

	_, err = NetDevQueueCreate(NetDevQueueCreateRequest{
		IfIndex: nk.Attrs().Index,
		Type:    NetDevQueueTypeRx,
		Lease: NetDevQueueLease{
			IfIndex:    1, // lo; irrelevant, netns resolution fails first
			Queue:      NetDevQueueID{ID: 0, Type: NetDevQueueTypeRx},
			NetNSID:    bogusNetNSID,
			NetNSIDSet: true,
		},
	})
	if err == nil {
		t.Fatal("queue-create with a bogus netns-id unexpectedly succeeded")
	}
	if !errors.Is(err, syscall.ENONET) {
		t.Fatalf("expected ENONET (proving netns-id was parsed before device lookup), got: %v", err)
	}
	t.Logf("netns-id encoded and parsed by kernel; got expected ENONET: %v", err)
}
