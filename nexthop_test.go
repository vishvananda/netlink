//go:build linux
// +build linux

package netlink

import (
	"net"
	"slices"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func TestNexthopAddListDelReplace(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	// get loopback interface
	loop, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = LinkSetUp(loop); err != nil {
		t.Fatal(err)
	}

	// create dummy interface
	if err = LinkAdd(&Dummy{LinkAttrs: LinkAttrs{Name: "dummy0"}}); err != nil {
		t.Fatal(err)
	}

	// get dummy interface
	link0, err := LinkByName("dummy0")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = LinkSetUp(link0); err != nil {
		t.Fatal(err)
	}

	// Assign ip address to dummy interface
	if err = AddrAdd(link0, &Addr{IPNet: &net.IPNet{
		IP:   net.ParseIP("10.0.0.2"),
		Mask: net.CIDRMask(24, 32),
	}}); err != nil {
		t.Fatal(err)
	}

	nh0 := &Nexthop{
		// Manually assign ID
		ID:        1,
		Blackhole: true,
	}

	nh1 := &Nexthop{
		// Auto assign ID
		ID:       0,
		OIF:      uint32(link0.Attrs().Index),
		Gateway:  net.ParseIP("fe80::1234:5678:9abc:def0"),
		Protocol: unix.RTPROT_BGP,
	}

	// Test NexthopAdd
	if err = NexthopAdd(nh0); err != nil {
		t.Fatal(err)
	}

	if err = NexthopAdd(nh1); err != nil {
		t.Fatal(err)
	}

	// Test NexthopList
	nhs, err := NexthopList()
	if err != nil {
		t.Fatal(err)
	}
	if len(nhs) != 2 {
		t.Fatalf("Expected 2 nexthop, got %d", len(nhs))
	}

	// Check that the ID assignment (both manual and automatic) worked
	if nhs[0].ID == nhs[1].ID {
		t.Fatalf("Duplicate nexthop IDs found: %d", nhs[0].ID)
	}
	idx := slices.IndexFunc(nhs, func(nh Nexthop) bool { return nh.ID == nh0.ID })
	if idx == -1 {
		t.Fatal("Manually assigned nexthop ID not found")
	}
	if nhs[1-idx].ID == 0 {
		t.Fatal("Nexthop ID was not auto assigned")
	}

	resNH0 := nhs[idx]
	resNH1 := nhs[1-idx]

	// Check we can read what we wrote
	if resNH0.Blackhole != nh0.Blackhole {
		t.Fatalf("Nexthop Blackhole mismatch: expected %v, got %v", nh0.Blackhole, resNH0.Blackhole)
	}
	if resNH1.OIF != nh1.OIF {
		t.Fatalf("Nexthop OIF mismatch: expected %d, got %d", nh1.OIF, resNH1.OIF)
	}
	if !resNH1.Gateway.Equal(nh1.Gateway) {
		t.Fatalf("Nexthop Gateway mismatch: expected %s, got %s", nh1.Gateway, resNH1.Gateway)
	}
	if resNH1.Protocol != nh1.Protocol {
		t.Fatalf("Nexthop Protocol mismatch: expected %s, got %s", nh1.Protocol, resNH1.Protocol)
	}

	// Test NexthopDel
	if err = NexthopDel(nh0); err != nil {
		t.Fatal(err)
	}
	nhs, err = NexthopList()
	if err != nil {
		t.Fatal(err)
	}
	if len(nhs) != 1 {
		t.Fatalf("Expected 1 nexthop, got %d", len(nhs))
	}

	// Test NexthopReplace
	nh2 := &Nexthop{
		// Replace nh1
		ID:       resNH1.ID,
		Protocol: unix.RTPROT_STATIC,
		OIF:      uint32(link0.Attrs().Index),
		Gateway:  net.ParseIP("10.0.0.1"),
	}
	if err = NexthopReplace(nh2); err != nil {
		t.Fatal(err)
	}
	nhs, err = NexthopList()
	if err != nil {
		t.Fatal(err)
	}
	if len(nhs) != 1 {
		t.Fatalf("Expected 1 nexthop, got %d", len(nhs))
	}

	// Check we can read what we wrote
	resNH2 := nhs[0]
	if resNH2.Protocol != nh2.Protocol {
		t.Fatalf("Nexthop Protocol mismatch: expected %s, got %s", nh2.Protocol, resNH2.Protocol)
	}
	if resNH2.OIF != nh2.OIF {
		t.Fatalf("Nexthop OIF mismatch: expected %d, got %d", nh2.OIF, resNH2.OIF)
	}
	if !resNH2.Gateway.Equal(nh2.Gateway) {
		t.Fatalf("Nexthop Gateway mismatch: expected %s, got %s", nh2.Gateway, resNH2.Gateway)
	}
}

func TestNexthopEncap(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	// get loopback interface
	loop, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = LinkSetUp(loop); err != nil {
		t.Fatal(err)
	}

	nh := &Nexthop{
		ID:  1,
		OIF: uint32(loop.Attrs().Index),
		Encap: &SEG6Encap{
			Mode: nl.SEG6_IPTUN_MODE_ENCAP,
			Segments: []net.IP{
				net.ParseIP("2001:db8:1234::"),
			},
		},
	}

	if err = NexthopAdd(nh); err != nil {
		t.Fatal(err)
	}

	nhs, err := NexthopList()
	if err != nil {
		t.Fatal(err)
	}
	if len(nhs) != 1 {
		t.Fatalf("Expected 1 nexthop, got %d", len(nhs))
	}

	// Check we can read what we wrote
	resNH := nhs[0]
	if resNH.Encap == nil {
		t.Fatal("Nexthop Encap is nil")
	}
	seg6Encap, ok := resNH.Encap.(*SEG6Encap)
	if !ok {
		t.Fatalf("Nexthop Encap is not SEG6Encap, got %T", resNH.Encap)
	}
	if seg6Encap.Mode != nl.SEG6_IPTUN_MODE_ENCAP {
		t.Fatalf("Nexthop Encap Mode mismatch: expected %d, got %d", nl.SEG6_IPTUN_MODE_ENCAP, seg6Encap.Mode)
	}
	if len(seg6Encap.Segments) != 1 {
		t.Fatalf("Expected 1 segment, got %d", len(seg6Encap.Segments))
	}
	if !seg6Encap.Segments[0].Equal(net.ParseIP("2001:db8:1234::")) {
		t.Fatalf("Nexthop Encap Segment mismatch: expected %s, got %s", "2001:db8:1234::", seg6Encap.Segments[0])
	}
}
