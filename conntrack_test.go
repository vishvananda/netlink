//go:build linux
// +build linux

package netlink

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func CheckErrorFail(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("Fatal Error: %s", err)
	}
}
func CheckError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Error: %s", err)
	}
}

func udpFlowCreateProg(t *testing.T, flows, srcPort int, dstIP string, dstPort int) {
	for i := 0; i < flows; i++ {
		ServerAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dstIP, dstPort))
		CheckError(t, err)

		LocalAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", srcPort+i))
		CheckError(t, err)

		Conn, err := net.DialUDP("udp", LocalAddr, ServerAddr)
		CheckError(t, err)

		Conn.Write([]byte("Hello World"))
		Conn.Close()
	}
}

func nsCreateAndEnter(t *testing.T) (*netns.NsHandle, *netns.NsHandle, *Handle) {
	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()

	ns, err := netns.New()
	CheckErrorFail(t, err)

	h, err := NewHandleAt(ns)
	CheckErrorFail(t, err)

	// Enter the new namespace
	netns.Set(ns)

	// Bing up loopback
	link, _ := h.LinkByName("lo")
	h.LinkSetUp(link)

	return &origns, &ns, h
}

func applyFilter(flowList []ConntrackFlow, ipv4Filter *ConntrackFilter, ipv6Filter *ConntrackFilter) (ipv4Match, ipv6Match uint) {
	for _, flow := range flowList {
		if ipv4Filter.MatchConntrackFlow(&flow) == true {
			ipv4Match++
		}
		if ipv6Filter.MatchConntrackFlow(&flow) == true {
			ipv6Match++
		}
	}
	return ipv4Match, ipv6Match
}

// TestConntrackSocket test the opening of a NETFILTER family socket
func TestConntrackSocket(t *testing.T) {
	skipUnlessRoot(t)
	setUpNetlinkTestWithKModule(t, "nf_conntrack")
	setUpNetlinkTestWithKModule(t, "nf_conntrack_netlink")

	h, err := NewHandle(unix.NETLINK_NETFILTER)
	CheckErrorFail(t, err)

	if h.SupportsNetlinkFamily(unix.NETLINK_NETFILTER) != true {
		t.Fatal("ERROR not supporting the NETFILTER family")
	}
}

// TestConntrackTableList test the conntrack table list
// Creates some flows and checks that they are correctly fetched from the conntrack table
func TestConntrackTableList(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skipf("Fails in CI: Flow creation fails")
	}
	skipUnlessRoot(t)
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		setUpNetlinkTestWithKModule(t, "nf_conntrack_ipv4")
		setUpNetlinkTestWithKModule(t, "nf_conntrack_ipv6")
	}
	setUpNetlinkTestWithKModule(t, "nf_conntrack")
	setUpNetlinkTestWithKModule(t, "nf_conntrack_netlink")

	// Creates a new namespace and bring up the loopback interface
	origns, ns, h := nsCreateAndEnter(t)
	defer netns.Set(*origns)
	defer origns.Close()
	defer ns.Close()
	defer runtime.UnlockOSThread()

	setUpF(t, "/proc/sys/net/netfilter/nf_conntrack_acct", "1")
	setUpF(t, "/proc/sys/net/netfilter/nf_conntrack_timestamp", "1")
	setUpF(t, "/proc/sys/net/netfilter/nf_conntrack_udp_timeout", "45")

	// Flush the table to start fresh
	err = h.ConntrackTableFlush(ConntrackTable)
	CheckErrorFail(t, err)

	// Create 5 udp
	startTime := time.Now()
	udpFlowCreateProg(t, 5, 2000, "127.0.0.10", 3000)

	// Fetch the conntrack table
	flows, err := h.ConntrackTableList(ConntrackTable, unix.AF_INET)
	CheckErrorFail(t, err)

	// Check that it is able to find the 5 flows created
	var found int
	for _, flow := range flows {
		if flow.Forward.Protocol == 17 &&
			flow.Forward.DstIP.Equal(net.ParseIP("127.0.0.10")) &&
			flow.Forward.DstPort == 3000 &&
			(flow.Forward.SrcPort >= 2000 && flow.Forward.SrcPort <= 2005) {
			found++
			flowStart := time.Unix(0, int64(flow.TimeStart))
			if flowStart.Before(startTime) || flowStart.Sub(startTime) > time.Second {
				t.Error("Invalid conntrack entry start timestamp")
			}
			if flow.TimeStop != 0 {
				t.Error("Invalid conntrack entry stop timestamp")
			}
			// Expect at most one second to have already passed from the configured UDP timeout of 45secs.
			if flow.TimeOut < 44 || flow.TimeOut > 45 {
				t.Error("Invalid conntrack entry timeout")
			}
		}

		if flow.Forward.Bytes == 0 && flow.Forward.Packets == 0 && flow.Reverse.Bytes == 0 && flow.Reverse.Packets == 0 {
			t.Error("No traffic statistics are collected")
		}
	}
	if found != 5 {
		t.Fatalf("Found only %d flows over 5", found)
	}

	// Give a try also to the IPv6 version
	_, err = h.ConntrackTableList(ConntrackTable, unix.AF_INET6)
	CheckErrorFail(t, err)

	// Switch back to the original namespace
	netns.Set(*origns)
}

// TestConntrackTableFlush test the conntrack table flushing
// Creates some flows and then call the table flush
func TestConntrackTableFlush(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skipf("Fails in CI: Flow creation fails")
	}
	skipUnlessRoot(t)
	setUpNetlinkTestWithKModule(t, "nf_conntrack")
	setUpNetlinkTestWithKModule(t, "nf_conntrack_netlink")
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		setUpNetlinkTestWithKModule(t, "nf_conntrack_ipv4")
	}
	setUpNetlinkTestWithKModule(t, "nf_conntrack")
	// Creates a new namespace and bring up the loopback interface
	origns, ns, h := nsCreateAndEnter(t)
	defer netns.Set(*origns)
	defer origns.Close()
	defer ns.Close()
	defer runtime.UnlockOSThread()

	// Create 5 udp flows using netcat
	udpFlowCreateProg(t, 5, 3000, "127.0.0.10", 4000)

	// Fetch the conntrack table
	flows, err := h.ConntrackTableList(ConntrackTable, unix.AF_INET)
	CheckErrorFail(t, err)

	// Check that it is able to find the 5 flows created
	var found int
	for _, flow := range flows {
		if flow.Forward.Protocol == 17 &&
			flow.Forward.DstIP.Equal(net.ParseIP("127.0.0.10")) &&
			flow.Forward.DstPort == 4000 &&
			(flow.Forward.SrcPort >= 3000 && flow.Forward.SrcPort <= 3005) {
			found++
		}
	}
	if found != 5 {
		t.Fatalf("Found only %d flows over 5", found)
	}

	// Flush the table
	err = h.ConntrackTableFlush(ConntrackTable)
	CheckErrorFail(t, err)

	// Fetch again the flows to validate the flush
	flows, err = h.ConntrackTableList(ConntrackTable, unix.AF_INET)
	CheckErrorFail(t, err)

	// Check if it is still able to find the 5 flows created
	found = 0
	for _, flow := range flows {
		if flow.Forward.Protocol == 17 &&
			flow.Forward.DstIP.Equal(net.ParseIP("127.0.0.10")) &&
			flow.Forward.DstPort == 4000 &&
			(flow.Forward.SrcPort >= 3000 && flow.Forward.SrcPort <= 3005) {
			found++
		}
	}
	if found > 0 {
		t.Fatalf("Found %d flows, they should had been flushed", found)
	}

	// Switch back to the original namespace
	netns.Set(*origns)
}

// TestConntrackTableDelete tests the deletion with filter
// Creates 2 group of flows then deletes only one group and validates the result
func TestConntrackTableDelete(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Skipf("Fails in CI: Flow creation fails")
	}
	skipUnlessRoot(t)
	setUpNetlinkTestWithKModule(t, "nf_conntrack")
	setUpNetlinkTestWithKModule(t, "nf_conntrack_netlink")
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		setUpNetlinkTestWithKModule(t, "nf_conntrack_ipv4")
	}

	// Creates a new namespace and bring up the loopback interface
	origns, ns, h := nsCreateAndEnter(t)
	defer netns.Set(*origns)
	defer origns.Close()
	defer ns.Close()
	defer runtime.UnlockOSThread()

	// Create 10 udp flows
	udpFlowCreateProg(t, 5, 5000, "127.0.0.10", 6000)
	udpFlowCreateProg(t, 5, 7000, "127.0.0.20", 8000)

	// Fetch the conntrack table
	flows, err := h.ConntrackTableList(ConntrackTable, unix.AF_INET)
	CheckErrorFail(t, err)

	// Check that it is able to find the 5 flows created for each group
	var groupA int
	var groupB int
	for _, flow := range flows {
		if flow.Forward.Protocol == 17 &&
			flow.Forward.DstIP.Equal(net.ParseIP("127.0.0.10")) &&
			flow.Forward.DstPort == 6000 &&
			(flow.Forward.SrcPort >= 5000 && flow.Forward.SrcPort <= 5005) {
			groupA++
		}
		if flow.Forward.Protocol == 17 &&
			flow.Forward.DstIP.Equal(net.ParseIP("127.0.0.20")) &&
			flow.Forward.DstPort == 8000 &&
			(flow.Forward.SrcPort >= 7000 && flow.Forward.SrcPort <= 7005) {
			groupB++
		}
	}
	if groupA != 5 || groupB != 5 {
		t.Fatalf("Flow creation issue groupA:%d, groupB:%d", groupA, groupB)
	}

	// Create a filter to erase groupB flows
	filter := &ConntrackFilter{}
	filter.AddIP(ConntrackOrigDstIP, net.ParseIP("127.0.0.20"))
	filter.AddProtocol(17)
	filter.AddPort(ConntrackOrigDstPort, 8000)

	// Flush entries of groupB
	var deleted uint
	if deleted, err = h.ConntrackDeleteFilter(ConntrackTable, unix.AF_INET, filter); err != nil {
		t.Fatalf("Error during the erase: %s", err)
	}
	if deleted != 5 {
		t.Fatalf("Error deleted a wrong number of flows:%d instead of 5", deleted)
	}

	// Check again the table to verify that are gone
	flows, err = h.ConntrackTableList(ConntrackTable, unix.AF_INET)
	CheckErrorFail(t, err)

	// Check if it is able to find the 5 flows of groupA but none of groupB
	groupA = 0
	groupB = 0
	for _, flow := range flows {
		if flow.Forward.Protocol == 17 &&
			flow.Forward.DstIP.Equal(net.ParseIP("127.0.0.10")) &&
			flow.Forward.DstPort == 6000 &&
			(flow.Forward.SrcPort >= 5000 && flow.Forward.SrcPort <= 5005) {
			groupA++
		}
		if flow.Forward.Protocol == 17 &&
			flow.Forward.DstIP.Equal(net.ParseIP("127.0.0.20")) &&
			flow.Forward.DstPort == 8000 &&
			(flow.Forward.SrcPort >= 7000 && flow.Forward.SrcPort <= 7005) {
			groupB++
		}
	}
	if groupA != 5 || groupB > 0 {
		t.Fatalf("Error during the erase groupA:%d, groupB:%d", groupA, groupB)
	}

	// Switch back to the original namespace
	netns.Set(*origns)
}

func TestConntrackFilter(t *testing.T) {
	var flowList []ConntrackFlow
	flowList = append(flowList, ConntrackFlow{
		FamilyType: unix.AF_INET,
		Forward: ipTuple{
			SrcIP:    net.ParseIP("10.0.0.1"),
			DstIP:    net.ParseIP("20.0.0.1"),
			SrcPort:  1000,
			DstPort:  2000,
			Protocol: 17,
		},
		Reverse: ipTuple{
			SrcIP:    net.ParseIP("20.0.0.1"),
			DstIP:    net.ParseIP("192.168.1.1"),
			SrcPort:  2000,
			DstPort:  1000,
			Protocol: 17,
		},
	},
		ConntrackFlow{
			FamilyType: unix.AF_INET,
			Forward: ipTuple{
				SrcIP:    net.ParseIP("10.0.0.2"),
				DstIP:    net.ParseIP("20.0.0.2"),
				SrcPort:  5000,
				DstPort:  6000,
				Protocol: 6,
			},
			Reverse: ipTuple{
				SrcIP:    net.ParseIP("20.0.0.2"),
				DstIP:    net.ParseIP("192.168.1.1"),
				SrcPort:  6000,
				DstPort:  5000,
				Protocol: 6,
			},
		},
		ConntrackFlow{
			FamilyType: unix.AF_INET6,
			Forward: ipTuple{
				SrcIP:    net.ParseIP("eeee:eeee:eeee:eeee:eeee:eeee:eeee:eeee"),
				DstIP:    net.ParseIP("dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd"),
				SrcPort:  1000,
				DstPort:  2000,
				Protocol: 132,
			},
			Reverse: ipTuple{
				SrcIP:    net.ParseIP("dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd"),
				DstIP:    net.ParseIP("eeee:eeee:eeee:eeee:eeee:eeee:eeee:eeee"),
				SrcPort:  2000,
				DstPort:  1000,
				Protocol: 132,
			},
		})

	// Empty filter
	v4Match, v6Match := applyFilter(flowList, &ConntrackFilter{}, &ConntrackFilter{})
	if v4Match > 0 || v6Match > 0 {
		t.Fatalf("Error, empty filter cannot match, v4:%d, v6:%d", v4Match, v6Match)
	}

	// Filter errors

	// Adding same attribute should fail
	filter := &ConntrackFilter{}
	err := filter.AddIP(ConntrackOrigSrcIP, net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if err := filter.AddIP(ConntrackOrigSrcIP, net.ParseIP("10.0.0.1")); err == nil {
		t.Fatalf("Error, it should fail adding same attribute to the filter")
	}
	err = filter.AddProtocol(6)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if err := filter.AddProtocol(17); err == nil {
		t.Fatalf("Error, it should fail adding same attribute to the filter")
	}
	filter.AddPort(ConntrackOrigSrcPort, 80)
	if err := filter.AddPort(ConntrackOrigSrcPort, 80); err == nil {
		t.Fatalf("Error, it should fail adding same attribute to the filter")
	}

	// Can not add a Port filter without Layer 4 protocol
	filter = &ConntrackFilter{}
	if err := filter.AddPort(ConntrackOrigSrcPort, 80); err == nil {
		t.Fatalf("Error, it should fail adding a port filter without a protocol")
	}

	// Can not add a Port filter if the Layer 4 protocol does not support it
	filter = &ConntrackFilter{}
	err = filter.AddProtocol(47)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if err := filter.AddPort(ConntrackOrigSrcPort, 80); err == nil {
		t.Fatalf("Error, it should fail adding a port filter with a wrong protocol")
	}

	// Proto filter
	filterV4 := &ConntrackFilter{}
	err = filterV4.AddProtocol(6)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 := &ConntrackFilter{}
	err = filterV6.AddProtocol(132)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 1 || v6Match != 1 {
		t.Fatalf("Error, there should be only 1 match for TCP:%d, UDP:%d", v4Match, v6Match)
	}

	// SrcIP filter
	filterV4 = &ConntrackFilter{}
	err = filterV4.AddIP(ConntrackOrigSrcIP, net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	err = filterV6.AddIP(ConntrackOrigSrcIP, net.ParseIP("eeee:eeee:eeee:eeee:eeee:eeee:eeee:eeee"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 1 || v6Match != 1 {
		t.Fatalf("Error, there should be only 1 match, v4:%d, v6:%d", v4Match, v6Match)
	}

	// DstIp filter
	filterV4 = &ConntrackFilter{}
	err = filterV4.AddIP(ConntrackOrigDstIP, net.ParseIP("20.0.0.1"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	err = filterV6.AddIP(ConntrackOrigDstIP, net.ParseIP("dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 1 || v6Match != 1 {
		t.Fatalf("Error, there should be only 1 match, v4:%d, v6:%d", v4Match, v6Match)
	}

	// SrcIP for NAT
	filterV4 = &ConntrackFilter{}
	err = filterV4.AddIP(ConntrackReplySrcIP, net.ParseIP("20.0.0.1"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	err = filterV6.AddIP(ConntrackReplySrcIP, net.ParseIP("dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 1 || v6Match != 1 {
		t.Fatalf("Error, there should be only 1 match, v4:%d, v6:%d", v4Match, v6Match)
	}

	// DstIP for NAT
	filterV4 = &ConntrackFilter{}
	err = filterV4.AddIP(ConntrackReplyDstIP, net.ParseIP("192.168.1.1"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	err = filterV6.AddIP(ConntrackReplyDstIP, net.ParseIP("dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 2 || v6Match != 0 {
		t.Fatalf("Error, there should be an exact match, v4:%d, v6:%d", v4Match, v6Match)
	}

	// AnyIp for Nat
	filterV4 = &ConntrackFilter{}
	err = filterV4.AddIP(ConntrackReplyAnyIP, net.ParseIP("192.168.1.1"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	err = filterV6.AddIP(ConntrackReplyAnyIP, net.ParseIP("eeee:eeee:eeee:eeee:eeee:eeee:eeee:eeee"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 2 || v6Match != 1 {
		t.Fatalf("Error, there should be an exact match, v4:%d, v6:%d", v4Match, v6Match)
	}

	// SrcIPNet filter
	filterV4 = &ConntrackFilter{}
	ipNet, err := ParseIPNet("10.0.0.0/12")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV4.AddIPNet(ConntrackOrigSrcIP, ipNet)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	ipNet, err = ParseIPNet("eeee:eeee:eeee:eeee::/64")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV6.AddIPNet(ConntrackOrigSrcIP, ipNet)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 2 || v6Match != 1 {
		t.Fatalf("Error, there should be only 1 match, v4:%d, v6:%d", v4Match, v6Match)
	}

	// DstIpNet filter
	filterV4 = &ConntrackFilter{}
	ipNet, err = ParseIPNet("20.0.0.0/12")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV4.AddIPNet(ConntrackOrigDstIP, ipNet)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	ipNet, err = ParseIPNet("dddd:dddd:dddd:dddd::/64")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV6.AddIPNet(ConntrackOrigDstIP, ipNet)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 2 || v6Match != 1 {
		t.Fatalf("Error, there should be only 1 match, v4:%d, v6:%d", v4Match, v6Match)
	}

	// SrcIPNet for NAT
	filterV4 = &ConntrackFilter{}
	ipNet, err = ParseIPNet("20.0.0.0/12")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV4.AddIPNet(ConntrackReplySrcIP, ipNet)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	ipNet, err = ParseIPNet("dddd:dddd:dddd:dddd::/64")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV6.AddIPNet(ConntrackReplySrcIP, ipNet)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 2 || v6Match != 1 {
		t.Fatalf("Error, there should be only 1 match, v4:%d, v6:%d", v4Match, v6Match)
	}

	// DstIPNet for NAT
	filterV4 = &ConntrackFilter{}
	ipNet, err = ParseIPNet("192.168.0.0/12")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV4.AddIPNet(ConntrackReplyDstIP, ipNet)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	ipNet, err = ParseIPNet("dddd:dddd:dddd:dddd::/64")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV6.AddIPNet(ConntrackReplyDstIP, ipNet)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 2 || v6Match != 0 {
		t.Fatalf("Error, there should be an exact match, v4:%d, v6:%d", v4Match, v6Match)
	}

	// AnyIpNet for Nat
	filterV4 = &ConntrackFilter{}
	ipNet, err = ParseIPNet("192.168.0.0/12")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV4.AddIPNet(ConntrackReplyAnyIP, ipNet)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	ipNet, err = ParseIPNet("eeee:eeee:eeee:eeee::/64")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV6.AddIPNet(ConntrackReplyAnyIP, ipNet)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 2 || v6Match != 1 {
		t.Fatalf("Error, there should be an exact match, v4:%d, v6:%d", v4Match, v6Match)
	}
	// SrcPort filter
	filterV4 = &ConntrackFilter{}
	err = filterV4.AddProtocol(6)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV4.AddPort(ConntrackOrigSrcPort, 5000)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	err = filterV6.AddProtocol(132)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV6.AddPort(ConntrackOrigSrcPort, 1000)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 1 || v6Match != 1 {
		t.Fatalf("Error, there should be only 1 match, v4:%d, v6:%d", v4Match, v6Match)
	}

	// DstPort filter
	filterV4 = &ConntrackFilter{}
	err = filterV4.AddProtocol(6)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV4.AddPort(ConntrackOrigDstPort, 6000)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	err = filterV6.AddProtocol(132)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	err = filterV6.AddPort(ConntrackOrigDstPort, 2000)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 1 || v6Match != 1 {
		t.Fatalf("Error, there should be only 1 match, v4:%d, v6:%d", v4Match, v6Match)
	}
}

func TestParseRawData(t *testing.T) {
	if nl.NativeEndian() == binary.BigEndian {
		t.Skip("testdata expect little-endian test executor")
	}
	os.Setenv("TZ", "") // print timestamps in UTC
	tests := []struct {
		testname         string
		rawData          []byte
		expConntrackFlow string
	}{
		{
			testname: "UDP conntrack",
			rawData: []byte{
				/* Nfgenmsg header */
				2, 0, 0, 0,
				/* >> nested CTA_TUPLE_ORIG */
				52, 0, 1, 128,
				/* >>>> nested CTA_TUPLE_IP */
				20, 0, 1, 128,
				/* >>>>>> CTA_IP_V4_SRC */
				8, 0, 1, 0,
				192, 168, 0, 10,
				/* >>>>>> CTA_IP_V4_DST */
				8, 0, 2, 0,
				192, 168, 0, 3,
				/* >>>>>> nested proto info */
				28, 0, 2, 128,
				/* >>>>>>>> CTA_PROTO_NUM */
				5, 0, 1, 0,
				17, 0, 0, 0,
				/* >>>>>>>> CTA_PROTO_SRC_PORT */
				6, 0, 2, 0,
				189, 1, 0, 0,
				/* >>>>>>>> CTA_PROTO_DST_PORT */
				6, 0, 3, 0,
				0, 53, 0, 0,
				/* >> CTA_TUPLE_REPLY */
				52, 0, 2, 128,
				/* >>>> nested CTA_TUPLE_IP */
				20, 0, 1, 128,
				/* >>>>>> CTA_IP_V4_SRC */
				8, 0, 1, 0,
				192, 168, 0, 3,
				/* >>>>>> CTA_IP_V4_DST */
				8, 0, 2, 0,
				192, 168, 0, 10,
				/* >>>>>> nested proto info */
				28, 0, 2, 128,
				/* >>>>>>>> CTA_PROTO_NUM */
				5, 0, 1, 0,
				17, 0, 0, 0,
				/* >>>>>>>> CTA_PROTO_SRC_PORT */
				6, 0, 2, 0,
				0, 53, 0, 0,
				/* >>>>>>>> CTA_PROTO_DST_PORT */
				6, 0, 3, 0,
				189, 1, 0, 0,
				/* >> CTA_STATUS */
				8, 0, 3, 0,
				0, 0, 1, 138,
				/* >> CTA_MARK */
				8, 0, 8, 0,
				0, 0, 0, 5,
				/* >> CTA_ID */
				8, 0, 12, 0,
				81, 172, 253, 151,
				/* >> CTA_USE */
				8, 0, 11, 0,
				0, 0, 0, 1,
				/* >> CTA_TIMEOUT */
				8, 0, 7, 0,
				0, 0, 0, 32,
				/* >> nested CTA_COUNTERS_ORIG */
				28, 0, 9, 128,
				/* >>>> CTA_COUNTERS_PACKETS */
				12, 0, 1, 0,
				0, 0, 0, 0, 0, 0, 0, 1,
				/* >>>> CTA_COUNTERS_BYTES */
				12, 0, 2, 0,
				0, 0, 0, 0, 0, 0, 0, 55,
				/* >> nested CTA_COUNTERS_REPLY */
				28, 0, 10, 128,
				/* >>>> CTA_COUNTERS_PACKETS */
				12, 0, 1, 0,
				0, 0, 0, 0, 0, 0, 0, 1,
				/* >>>> CTA_COUNTERS_BYTES */
				12, 0, 2, 0,
				0, 0, 0, 0, 0, 0, 0, 71,
				/* >> nested CTA_TIMESTAMP */
				16, 0, 20, 128,
				/* >>>> CTA_TIMESTAMP_START */
				12, 0, 1, 0,
				22, 134, 80, 142, 230, 127, 74, 166},
			expConntrackFlow: "udp\t17 src=192.168.0.10 dst=192.168.0.3 sport=48385 dport=53 packets=1 bytes=55\t" +
				"src=192.168.0.3 dst=192.168.0.10 sport=53 dport=48385 packets=1 bytes=71 mark=0x5 " +
				"start=2021-06-07 13:41:30.39632247 +0000 UTC stop=1970-01-01 00:00:00 +0000 UTC timeout=32(sec)",
		},
		{
			testname: "TCP conntrack",
			rawData: []byte{
				/* Nfgenmsg header */
				2, 0, 0, 0,
				/* >> nested CTA_TUPLE_ORIG */
				52, 0, 1, 128,
				/* >>>> nested CTA_TUPLE_IP */
				20, 0, 1, 128,
				/* >>>>>> CTA_IP_V4_SRC */
				8, 0, 1, 0,
				192, 168, 0, 10,
				/* >>>>>> CTA_IP_V4_DST */
				8, 0, 2, 0,
				192, 168, 77, 73,
				/* >>>>>> nested proto info */
				28, 0, 2, 128,
				/* >>>>>>>> CTA_PROTO_NUM */
				5, 0, 1, 0,
				6, 0, 0, 0,
				/* >>>>>>>> CTA_PROTO_SRC_PORT */
				6, 0, 2, 0,
				166, 129, 0, 0,
				/* >>>>>>>> CTA_PROTO_DST_PORT */
				6, 0, 3, 0,
				13, 5, 0, 0,
				/* >> CTA_TUPLE_REPLY */
				52, 0, 2, 128,
				/* >>>> nested CTA_TUPLE_IP */
				20, 0, 1, 128,
				/* >>>>>> CTA_IP_V4_SRC */
				8, 0, 1, 0,
				192, 168, 77, 73,
				/* >>>>>> CTA_IP_V4_DST */
				8, 0, 2, 0,
				192, 168, 0, 10,
				/* >>>>>> nested proto info */
				28, 0, 2, 128,
				/* >>>>>>>> CTA_PROTO_NUM */
				5, 0, 1, 0,
				6, 0, 0, 0,
				/* >>>>>>>> CTA_PROTO_SRC_PORT */
				6, 0, 2, 0,
				13, 5, 0, 0,
				/* >>>>>>>> CTA_PROTO_DST_PORT */
				6, 0, 3, 0,
				166, 129, 0, 0,
				/* >> CTA_STATUS */
				8, 0, 3, 0,
				0, 0, 1, 142,
				/* >> CTA_MARK */
				8, 0, 8, 0,
				0, 0, 0, 5,
				/* >> CTA_ID */
				8, 0, 12, 0,
				177, 65, 179, 133,
				/* >> CTA_USE */
				8, 0, 11, 0,
				0, 0, 0, 1,
				/* >> CTA_TIMEOUT */
				8, 0, 7, 0,
				0, 0, 0, 152,
				/* >> CTA_PROTOINFO */
				48, 0, 4, 128,
				44, 0, 1, 128,
				5, 0, 1, 0, 8, 0, 0, 0,
				5, 0, 2, 0, 0, 0, 0, 0,
				5, 0, 3, 0, 0, 0, 0, 0,
				6, 0, 4, 0, 39, 0, 0, 0,
				6, 0, 5, 0, 32, 0, 0, 0,
				/* >> nested CTA_COUNTERS_ORIG */
				28, 0, 9, 128,
				/* >>>> CTA_COUNTERS_PACKETS */
				12, 0, 1, 0,
				0, 0, 0, 0, 0, 0, 0, 11,
				/* >>>> CTA_COUNTERS_BYTES */
				12, 0, 2, 0,
				0, 0, 0, 0, 0, 0, 7, 122,
				/* >> nested CTA_COUNTERS_REPLY */
				28, 0, 10, 128,
				/* >>>> CTA_COUNTERS_PACKETS */
				12, 0, 1, 0,
				0, 0, 0, 0, 0, 0, 0, 10,
				/* >>>> CTA_COUNTERS_BYTES */
				12, 0, 2, 0,
				0, 0, 0, 0, 0, 0, 7, 66,
				/* >> nested CTA_TIMESTAMP */
				16, 0, 20, 128,
				/* >>>> CTA_TIMESTAMP_START */
				12, 0, 1, 0,
				22, 134, 80, 175, 134, 10, 182, 221},
			expConntrackFlow: "tcp\t6 src=192.168.0.10 dst=192.168.77.73 sport=42625 dport=3333 packets=11 bytes=1914\t" +
				"src=192.168.77.73 dst=192.168.0.10 sport=3333 dport=42625 packets=10 bytes=1858 mark=0x5 " +
				"start=2021-06-07 13:43:50.511990493 +0000 UTC stop=1970-01-01 00:00:00 +0000 UTC timeout=152(sec)",
		},
	}

	for _, test := range tests {
		t.Run(test.testname, func(t *testing.T) {
			conntrackFlow := parseRawData(test.rawData)
			if conntrackFlow.String() != test.expConntrackFlow {
				t.Errorf("expected conntrack flow:\n\t%q\ngot conntrack flow:\n\t%q",
					test.expConntrackFlow, conntrackFlow)
			}
		})
	}
}
