//go:build linux
// +build linux

package netlink

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
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
	for i := range flows {
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

// Install minimal hooks so packets traverse conntrack in this netns.
// Prefer iptables if available; otherwise use nftables.
// Returns a cleanup function that removes the installed hooks.
func ensureCtHooksInThisNS(t *testing.T) func() {
	t.Helper()

	// Prefer iptables if present
	if _, err := exec.LookPath("iptables"); err == nil {
		ipt := func(fatalOnErr bool, args ...string) error {
			cmd := exec.Command("iptables", args...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				if fatalOnErr {
					t.Fatalf("iptables %v failed: %v\n%s", args, err, out)
				}
				// For -C, non-zero exit is expected when rule doesn't exist.
				// For -D, we don't want to fail the test on cleanup.
				t.Logf("iptables %v -> non-fatal error (ok): %v\n%s", args, err, out)
			}
			return err
		}

		// Minimal hooks so packets traverse conntrack in this netns.
		// Check (-C); if absent, insert (-I). Idempotent on reruns.
		var addedInput, addedOutput bool
		if ipt(false, "-C", "INPUT", "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED", "-j", "ACCEPT") != nil {
			ipt(true, "-I", "INPUT", "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED", "-j", "ACCEPT")
			// Add a rule to set conntrack label to allocate the label space
			// https://lore.kernel.org/netfilter-devel/aPdkVOTuUElaFKZZ@strlen.de/
			ipt(true, "-I", "INPUT", "-m", "connlabel", "--set", "--label", "1")
			addedInput = true
		}
		if ipt(false, "-C", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT") != nil {
			ipt(true, "-I", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT")
			// Add a rule to set conntrack label to allocate the label space
			// https://lore.kernel.org/netfilter-devel/aPdkVOTuUElaFKZZ@strlen.de/
			ipt(true, "-I", "OUTPUT", "-m", "connlabel", "--set", "--label", "1")
			addedOutput = true
		}
		return func() {
			if addedInput {
				ipt(false, "-D", "INPUT", "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED", "-j", "ACCEPT")
			}
			if addedOutput {
				ipt(false, "-D", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT")
			}
		}
	}

	// Fallback to nft if iptables isn’t available
	if _, err := exec.LookPath("nft"); err == nil {
		// Best-effort, ignore “already exists” errors to be idempotent
		_ = exec.Command("nft", "add", "table", "inet", "ct_test").Run()
		_ = exec.Command("nft", "add", "chain", "inet", "ct_test", "input",
			"{", "type", "filter", "hook", "input", "priority", "0", ";",
			"ct", "state", "{", "new,established", "}", "accept", "}").Run()
		_ = exec.Command("nft", "add", "chain", "inet", "ct_test", "output",
			"{", "type", "filter", "hook", "output", "priority", "0", ";",
			"ct", "state", "established", "accept", "}").Run()
		// Add a rule to set conntrack label to allocate the label space
		// https://lore.kernel.org/netfilter-devel/aPdkVOTuUElaFKZZ@strlen.de/
		_ = exec.Command("nft", "add", "rule", "inet", "ct_test", "output",
			"ct", "label", "set", "1").Run()
		_ = exec.Command("nft", "add", "rule", "inet", "ct_test", "input",
			"ct", "label", "set", "1").Run()
		return func() {
			_ = exec.Command("nft", "delete", "table", "inet", "ct_test").Run()
		}
	}

	t.Skip("neither iptables nor nft found to install conntrack hooks")
	return func() {}
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

	setUpF(t, "/proc/sys/net/netfilter/nf_conntrack_acct", "1")
	setUpF(t, "/proc/sys/net/netfilter/nf_conntrack_timestamp", "1")
	setUpF(t, "/proc/sys/net/netfilter/nf_conntrack_udp_timeout", "45")

	t.Cleanup(ensureCtHooksInThisNS(t))

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
	t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack"))
	t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack_netlink"))

	h, err := NewHandle(unix.NETLINK_NETFILTER)
	CheckErrorFail(t, err)

	if h.SupportsNetlinkFamily(unix.NETLINK_NETFILTER) != true {
		t.Fatal("ERROR not supporting the NETFILTER family")
	}
}

// TestConntrackTableList test the conntrack table list
// Creates some flows and checks that they are correctly fetched from the conntrack table
func TestConntrackTableList(t *testing.T) {
	skipUnlessRoot(t)
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack_ipv4"))
		t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack_ipv6"))
	}
	t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack"))
	t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack_netlink"))

	// Creates a new namespace and bring up the loopback interface
	origns, ns, h := nsCreateAndEnter(t)
	defer netns.Set(*origns)
	defer origns.Close()
	defer ns.Close()
	defer runtime.UnlockOSThread()

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
	skipUnlessRoot(t)
	t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack"))
	t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack_netlink"))
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack_ipv4"))
	}
	t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack"))
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
	skipUnlessRoot(t)

	requiredModules := []string{"nf_conntrack", "nf_conntrack_netlink"}
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		requiredModules = append(requiredModules, "nf_conntrack_ipv4")
	}

	t.Cleanup(setUpNetlinkTestWithKModule(t, requiredModules...))

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
	if deleted, err = h.ConntrackDeleteFilters(ConntrackTable, unix.AF_INET, filter); err != nil {
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
		Forward: IPTuple{
			SrcIP:    net.ParseIP("10.0.0.1"),
			DstIP:    net.ParseIP("20.0.0.1"),
			SrcPort:  1000,
			DstPort:  2000,
			Protocol: 17,
		},
		Reverse: IPTuple{
			SrcIP:    net.ParseIP("20.0.0.1"),
			DstIP:    net.ParseIP("192.168.1.1"),
			SrcPort:  2000,
			DstPort:  1000,
			Protocol: 17,
		},
	},
		ConntrackFlow{
			FamilyType: unix.AF_INET,
			Forward: IPTuple{
				SrcIP:    net.ParseIP("10.0.0.2"),
				DstIP:    net.ParseIP("20.0.0.2"),
				SrcPort:  5000,
				DstPort:  6000,
				Protocol: 6,
			},
			Reverse: IPTuple{
				SrcIP:    net.ParseIP("20.0.0.2"),
				DstIP:    net.ParseIP("192.168.1.1"),
				SrcPort:  6000,
				DstPort:  5000,
				Protocol: 6,
			},
			Labels: []byte{0, 0, 0, 0, 3, 4, 61, 141, 207, 170, 2, 0, 0, 0, 0, 0},
			Zone:   200,
		},
		ConntrackFlow{
			FamilyType: unix.AF_INET6,
			Forward: IPTuple{
				SrcIP:    net.ParseIP("eeee:eeee:eeee:eeee:eeee:eeee:eeee:eeee"),
				DstIP:    net.ParseIP("dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd"),
				SrcPort:  1000,
				DstPort:  2000,
				Protocol: 132,
			},
			Reverse: IPTuple{
				SrcIP:    net.ParseIP("dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd"),
				DstIP:    net.ParseIP("eeee:eeee:eeee:eeee:eeee:eeee:eeee:eeee"),
				SrcPort:  2000,
				DstPort:  1000,
				Protocol: 132,
			},
			Zone: 200,
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

	// Labels filter
	filterV4 = &ConntrackFilter{}
	var labels [][]byte
	labels = append(labels, []byte{3, 4, 61, 141, 207, 170})
	labels = append(labels, []byte{0x2})
	err = filterV4.AddLabels(ConntrackMatchLabels, labels)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	filterV6 = &ConntrackFilter{}
	err = filterV6.AddLabels(ConntrackUnmatchLabels, labels)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 1 || v6Match != 0 {
		t.Fatalf("Error, there should be only 1 match, v4:%d, v6:%d", v4Match, v6Match)
	}

	filterV4 = &ConntrackFilter{}
	err = filterV4.AddZone(200)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	filterV6 = &ConntrackFilter{}
	v4Match, v6Match = applyFilter(flowList, filterV4, filterV6)
	if v4Match != 2 || v6Match != 0 {
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
				22, 134, 80, 142, 230, 127, 74, 166,
				/* >> CTA_LABELS */
				20, 0, 22, 0,
				0, 0, 0, 0, 5, 0, 18, 172, 66, 2, 1, 0, 0, 0, 0, 0},
			expConntrackFlow: "udp\t17 src=192.168.0.10 dst=192.168.0.3 sport=48385 dport=53 packets=1 bytes=55\t" +
				"src=192.168.0.3 dst=192.168.0.10 sport=53 dport=48385 packets=1 bytes=71 mark=0x5 labels=0x00000000050012ac4202010000000000 " +
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
				/* >> CTA_ZONE */
				8, 0, 18, 0,
				0, 100, 0, 0,
				/* >> nested CTA_TIMESTAMP */
				16, 0, 20, 128,
				/* >>>> CTA_TIMESTAMP_START */
				12, 0, 1, 0,
				22, 134, 80, 175, 134, 10, 182, 221},
			expConntrackFlow: "tcp\t6 src=192.168.0.10 dst=192.168.77.73 sport=42625 dport=3333 packets=11 bytes=1914\t" +
				"src=192.168.77.73 dst=192.168.0.10 sport=3333 dport=42625 packets=10 bytes=1858 mark=0x5 zone=100 " +
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

// TestConntrackUpdateV4 first tries to update a non-existant IPv4 conntrack and asserts that an error occurs.
// It then creates a conntrack entry using and adjacent API method (ConntrackCreate), and attempts to update the value of the created conntrack.
func TestConntrackUpdateV4(t *testing.T) {
	// Print timestamps in UTC
	os.Setenv("TZ", "")

	requiredModules := []string{"nf_conntrack", "nf_conntrack_netlink"}
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// Conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		requiredModules = append(requiredModules, "nf_conntrack_ipv4")
	}
	// Implicitly skips test if not root:
	nsStr, teardown := setUpNamedNetlinkTestWithKModule(t, requiredModules...)
	t.Cleanup(teardown)

	ns, err := netns.GetFromName(nsStr)
	if err != nil {
		t.Fatalf("couldn't get handle to generated namespace: %s", err)
	}

	h, err := NewHandleAt(ns, nl.FAMILY_V4)
	if err != nil {
		t.Fatalf("failed to create netlink handle: %s", err)
	}

	flow := ConntrackFlow{
		FamilyType: FAMILY_V4,
		Forward: IPTuple{
			SrcIP:    net.IP{234, 234, 234, 234},
			DstIP:    net.IP{123, 123, 123, 123},
			SrcPort:  48385,
			DstPort:  53,
			Protocol: unix.IPPROTO_TCP,
		},
		Reverse: IPTuple{
			SrcIP:    net.IP{123, 123, 123, 123},
			DstIP:    net.IP{234, 234, 234, 234},
			SrcPort:  53,
			DstPort:  48385,
			Protocol: unix.IPPROTO_TCP,
		},
		// No point checking equivalence of timeout, but value must
		// be reasonable to allow for a potentially slow subsequent read.
		TimeOut: 100,
		Mark:    12,
		ProtoInfo: &ProtoInfoTCP{
			State: nl.TCP_CONNTRACK_SYN_SENT2,
		},
	}

	err = h.ConntrackUpdate(ConntrackTable, nl.FAMILY_V4, &flow)
	if err == nil {
		t.Fatalf("expected an error to occur when trying to update a non-existant conntrack: %+v", flow)
	}

	err = h.ConntrackCreate(ConntrackTable, nl.FAMILY_V4, &flow)
	if err != nil {
		t.Fatalf("failed to insert conntrack: %s", err)
	}

	flows, err := h.ConntrackTableList(ConntrackTable, nl.FAMILY_V4)
	if err != nil {
		t.Fatalf("failed to list conntracks following successful insert: %s", err)
	}

	filter := ConntrackFilter{
		ipNetFilter: map[ConntrackFilterType]*net.IPNet{
			ConntrackOrigSrcIP:  NewIPNet(flow.Forward.SrcIP),
			ConntrackOrigDstIP:  NewIPNet(flow.Forward.DstIP),
			ConntrackReplySrcIP: NewIPNet(flow.Reverse.SrcIP),
			ConntrackReplyDstIP: NewIPNet(flow.Reverse.DstIP),
		},
		portFilter: map[ConntrackFilterType]uint16{
			ConntrackOrigSrcPort: flow.Forward.SrcPort,
			ConntrackOrigDstPort: flow.Forward.DstPort,
		},
		protoFilter: unix.IPPROTO_TCP,
	}

	var match *ConntrackFlow
	for _, f := range flows {
		if filter.MatchConntrackFlow(f) {
			match = f
			break
		}
	}

	if match == nil {
		t.Fatalf("Didn't find any matching conntrack entries for original flow: %+v\n Filter used: %+v", flow, filter)
	} else {
		t.Logf("Found entry in conntrack table matching original flow: %+v labels=%+v", match, match.Labels)
	}
	checkFlowsEqual(t, &flow, match)
	checkProtoInfosEqual(t, flow.ProtoInfo, match.ProtoInfo)

	// Change the conntrack and update the kernel entry.
	flow.Mark = 10
	flow.ProtoInfo = &ProtoInfoTCP{
		State: nl.TCP_CONNTRACK_ESTABLISHED,
	}
	err = h.ConntrackUpdate(ConntrackTable, nl.FAMILY_V4, &flow)
	if err != nil {
		t.Fatalf("failed to update conntrack with new mark: %s", err)
	}

	// Look for updated conntrack.
	flows, err = h.ConntrackTableList(ConntrackTable, nl.FAMILY_V4)
	if err != nil {
		t.Fatalf("failed to list conntracks following successful update: %s", err)
	}

	var updatedMatch *ConntrackFlow
	for _, f := range flows {
		if filter.MatchConntrackFlow(f) {
			updatedMatch = f
			break
		}
	}
	if updatedMatch == nil {
		t.Fatalf("Didn't find any matching conntrack entries for updated flow: %+v\n Filter used: %+v", flow, filter)
	} else {
		t.Logf("Found entry in conntrack table matching updated flow: %+v labels=%+v", updatedMatch, updatedMatch.Labels)
	}

	checkFlowsEqual(t, &flow, updatedMatch)
	checkProtoInfosEqual(t, flow.ProtoInfo, updatedMatch.ProtoInfo)
}

// TestConntrackUpdateV6 first tries to update a non-existant IPv6 conntrack and asserts that an error occurs.
// It then creates a conntrack entry using and adjacent API method (ConntrackCreate), and attempts to update the value of the created conntrack.
func TestConntrackUpdateV6(t *testing.T) {
	// Print timestamps in UTC
	os.Setenv("TZ", "")

	requiredModules := []string{"nf_conntrack", "nf_conntrack_netlink"}
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// Conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		requiredModules = append(requiredModules, "nf_conntrack_ipv4")
	}
	// Implicitly skips test if not root:
	nsStr, teardown := setUpNamedNetlinkTestWithKModule(t, requiredModules...)
	t.Cleanup(teardown)

	ns, err := netns.GetFromName(nsStr)
	if err != nil {
		t.Fatalf("couldn't get handle to generated namespace: %s", err)
	}

	h, err := NewHandleAt(ns, nl.FAMILY_V6)
	if err != nil {
		t.Fatalf("failed to create netlink handle: %s", err)
	}

	flow := ConntrackFlow{
		FamilyType: FAMILY_V6,
		Forward: IPTuple{
			SrcIP:    net.ParseIP("2001:db8::68"),
			DstIP:    net.ParseIP("2001:db9::32"),
			SrcPort:  48385,
			DstPort:  53,
			Protocol: unix.IPPROTO_TCP,
		},
		Reverse: IPTuple{
			SrcIP:    net.ParseIP("2001:db9::32"),
			DstIP:    net.ParseIP("2001:db8::68"),
			SrcPort:  53,
			DstPort:  48385,
			Protocol: unix.IPPROTO_TCP,
		},
		// No point checking equivalence of timeout, but value must
		// be reasonable to allow for a potentially slow subsequent read.
		TimeOut: 100,
		Mark:    12,
		ProtoInfo: &ProtoInfoTCP{
			State: nl.TCP_CONNTRACK_SYN_SENT2,
		},
	}

	err = h.ConntrackUpdate(ConntrackTable, nl.FAMILY_V6, &flow)
	if err == nil {
		t.Fatalf("expected an error to occur when trying to update a non-existant conntrack: %+v", flow)
	}

	err = h.ConntrackCreate(ConntrackTable, nl.FAMILY_V6, &flow)
	if err != nil {
		t.Fatalf("failed to insert conntrack: %s", err)
	}

	flows, err := h.ConntrackTableList(ConntrackTable, nl.FAMILY_V6)
	if err != nil {
		t.Fatalf("failed to list conntracks following successful insert: %s", err)
	}

	filter := ConntrackFilter{
		ipNetFilter: map[ConntrackFilterType]*net.IPNet{
			ConntrackOrigSrcIP:  NewIPNet(flow.Forward.SrcIP),
			ConntrackOrigDstIP:  NewIPNet(flow.Forward.DstIP),
			ConntrackReplySrcIP: NewIPNet(flow.Reverse.SrcIP),
			ConntrackReplyDstIP: NewIPNet(flow.Reverse.DstIP),
		},
		portFilter: map[ConntrackFilterType]uint16{
			ConntrackOrigSrcPort: flow.Forward.SrcPort,
			ConntrackOrigDstPort: flow.Forward.DstPort,
		},
		protoFilter: unix.IPPROTO_TCP,
	}

	var match *ConntrackFlow
	for _, f := range flows {
		if filter.MatchConntrackFlow(f) {
			match = f
			break
		}
	}

	if match == nil {
		t.Fatalf("didn't find any matching conntrack entries for original flow: %+v\n Filter used: %+v", flow, filter)
	} else {
		t.Logf("found entry in conntrack table matching original flow: %+v labels=%+v", match, match.Labels)
	}
	checkFlowsEqual(t, &flow, match)
	checkProtoInfosEqual(t, flow.ProtoInfo, match.ProtoInfo)

	// Change the conntrack and update the kernel entry.
	flow.Mark = 10
	flow.ProtoInfo = &ProtoInfoTCP{
		State: nl.TCP_CONNTRACK_ESTABLISHED,
	}
	err = h.ConntrackUpdate(ConntrackTable, nl.FAMILY_V6, &flow)
	if err != nil {
		t.Fatalf("failed to update conntrack with new mark: %s", err)
	}

	// Look for updated conntrack.
	flows, err = h.ConntrackTableList(ConntrackTable, nl.FAMILY_V6)
	if err != nil {
		t.Fatalf("failed to list conntracks following successful update: %s", err)
	}

	var updatedMatch *ConntrackFlow
	for _, f := range flows {
		if filter.MatchConntrackFlow(f) {
			updatedMatch = f
			break
		}
	}
	if updatedMatch == nil {
		t.Fatalf("didn't find any matching conntrack entries for updated flow: %+v\n Filter used: %+v", flow, filter)
	} else {
		t.Logf("found entry in conntrack table matching updated flow: %+v labels=%+v", updatedMatch, updatedMatch.Labels)
	}

	checkFlowsEqual(t, &flow, updatedMatch)
	checkProtoInfosEqual(t, flow.ProtoInfo, updatedMatch.ProtoInfo)
}

func TestConntrackCreateV4(t *testing.T) {
	// Print timestamps in UTC
	os.Setenv("TZ", "")

	requiredModules := []string{"nf_conntrack", "nf_conntrack_netlink"}
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// Conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		requiredModules = append(requiredModules, "nf_conntrack_ipv4")
	}
	// Implicitly skips test if not root:
	nsStr, teardown := setUpNamedNetlinkTestWithKModule(t, requiredModules...)
	t.Cleanup(teardown)

	ns, err := netns.GetFromName(nsStr)
	if err != nil {
		t.Fatalf("couldn't get handle to generated namespace: %s", err)
	}

	h, err := NewHandleAt(ns, nl.FAMILY_V4)
	if err != nil {
		t.Fatalf("failed to create netlink handle: %s", err)
	}

	flow := ConntrackFlow{
		FamilyType: FAMILY_V4,
		Forward: IPTuple{
			SrcIP:    net.IP{234, 234, 234, 234},
			DstIP:    net.IP{123, 123, 123, 123},
			SrcPort:  48385,
			DstPort:  53,
			Protocol: unix.IPPROTO_TCP,
		},
		Reverse: IPTuple{
			SrcIP:    net.IP{123, 123, 123, 123},
			DstIP:    net.IP{234, 234, 234, 234},
			SrcPort:  53,
			DstPort:  48385,
			Protocol: unix.IPPROTO_TCP,
		},
		// No point checking equivalence of timeout, but value must
		// be reasonable to allow for a potentially slow subsequent read.
		TimeOut: 100,
		Mark:    12,
		ProtoInfo: &ProtoInfoTCP{
			State: nl.TCP_CONNTRACK_ESTABLISHED,
		},
	}

	err = h.ConntrackCreate(ConntrackTable, nl.FAMILY_V4, &flow)
	if err != nil {
		t.Fatalf("failed to insert conntrack: %s", err)
	}

	flows, err := h.ConntrackTableList(ConntrackTable, nl.FAMILY_V4)
	if err != nil {
		t.Fatalf("failed to list conntracks following successful insert: %s", err)
	}

	filter := ConntrackFilter{
		ipNetFilter: map[ConntrackFilterType]*net.IPNet{
			ConntrackOrigSrcIP:  NewIPNet(flow.Forward.SrcIP),
			ConntrackOrigDstIP:  NewIPNet(flow.Forward.DstIP),
			ConntrackReplySrcIP: NewIPNet(flow.Reverse.SrcIP),
			ConntrackReplyDstIP: NewIPNet(flow.Reverse.DstIP),
		},
		portFilter: map[ConntrackFilterType]uint16{
			ConntrackOrigSrcPort: flow.Forward.SrcPort,
			ConntrackOrigDstPort: flow.Forward.DstPort,
		},
		protoFilter: unix.IPPROTO_TCP,
	}

	var match *ConntrackFlow
	for _, f := range flows {
		if filter.MatchConntrackFlow(f) {
			match = f
			break
		}
	}

	if match == nil {
		t.Fatalf("didn't find any matching conntrack entries for original flow: %+v\n Filter used: %+v", flow, filter)
	} else {
		t.Logf("Found entry in conntrack table matching original flow: %+v labels=%+v", match, match.Labels)
	}

	checkFlowsEqual(t, &flow, match)
	checkProtoInfosEqual(t, flow.ProtoInfo, match.ProtoInfo)
}

func TestConntrackCreateV6(t *testing.T) {
	// Print timestamps in UTC
	os.Setenv("TZ", "")

	requiredModules := []string{"nf_conntrack", "nf_conntrack_netlink"}
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// Conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		requiredModules = append(requiredModules, "nf_conntrack_ipv4")
	}
	// Implicitly skips test if not root:
	nsStr, teardown := setUpNamedNetlinkTestWithKModule(t, requiredModules...)
	t.Cleanup(teardown)

	ns, err := netns.GetFromName(nsStr)
	if err != nil {
		t.Fatalf("couldn't get handle to generated namespace: %s", err)
	}

	h, err := NewHandleAt(ns, nl.FAMILY_V6)
	if err != nil {
		t.Fatalf("failed to create netlink handle: %s", err)
	}

	flow := ConntrackFlow{
		FamilyType: FAMILY_V6,
		Forward: IPTuple{
			SrcIP:    net.ParseIP("2001:db8::68"),
			DstIP:    net.ParseIP("2001:db9::32"),
			SrcPort:  48385,
			DstPort:  53,
			Protocol: unix.IPPROTO_TCP,
		},
		Reverse: IPTuple{
			SrcIP:    net.ParseIP("2001:db9::32"),
			DstIP:    net.ParseIP("2001:db8::68"),
			SrcPort:  53,
			DstPort:  48385,
			Protocol: unix.IPPROTO_TCP,
		},
		// No point checking equivalence of timeout, but value must
		// be reasonable to allow for a potentially slow subsequent read.
		TimeOut: 100,
		Mark:    12,
		ProtoInfo: &ProtoInfoTCP{
			State: nl.TCP_CONNTRACK_ESTABLISHED,
		},
	}

	err = h.ConntrackCreate(ConntrackTable, nl.FAMILY_V6, &flow)
	if err != nil {
		t.Fatalf("failed to insert conntrack: %s", err)
	}

	flows, err := h.ConntrackTableList(ConntrackTable, nl.FAMILY_V6)
	if err != nil {
		t.Fatalf("failed to list conntracks following successful insert: %s", err)
	}

	filter := ConntrackFilter{
		ipNetFilter: map[ConntrackFilterType]*net.IPNet{
			ConntrackOrigSrcIP:  NewIPNet(flow.Forward.SrcIP),
			ConntrackOrigDstIP:  NewIPNet(flow.Forward.DstIP),
			ConntrackReplySrcIP: NewIPNet(flow.Reverse.SrcIP),
			ConntrackReplyDstIP: NewIPNet(flow.Reverse.DstIP),
		},
		portFilter: map[ConntrackFilterType]uint16{
			ConntrackOrigSrcPort: flow.Forward.SrcPort,
			ConntrackOrigDstPort: flow.Forward.DstPort,
		},
		protoFilter: unix.IPPROTO_TCP,
	}

	var match *ConntrackFlow
	for _, f := range flows {
		if filter.MatchConntrackFlow(f) {
			match = f
			break
		}
	}

	if match == nil {
		t.Fatalf("Didn't find any matching conntrack entries for original flow: %+v\n Filter used: %+v", flow, filter)
	} else {
		t.Logf("Found entry in conntrack table matching original flow: %+v labels=%+v", match, match.Labels)
	}

	// Other fields are implicitly correct due to the filter/match logic.
	if match.Mark != flow.Mark {
		t.Logf("Matched kernel entry did not have correct mark. Kernel: %d, Expected: %d", flow.Mark, match.Mark)
		t.Fail()
	}
	checkProtoInfosEqual(t, flow.ProtoInfo, match.ProtoInfo)
}

// TestConntrackDeleteV4 creates an IPv4 conntrack entry, verifies it exists,
// deletes it via Handle.ConntrackDelete, and verifies it was removed.
func TestConntrackDeleteV4(t *testing.T) {
	// Print timestamps in UTC
	os.Setenv("TZ", "")

	requiredModules := []string{"nf_conntrack", "nf_conntrack_netlink"}
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// Conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		requiredModules = append(requiredModules, "nf_conntrack_ipv4")
	}
	// Implicitly skips test if not root:
	nsStr, teardown := setUpNamedNetlinkTestWithKModule(t, requiredModules...)
	t.Cleanup(teardown)

	ns, err := netns.GetFromName(nsStr)
	if err != nil {
		t.Fatalf("couldn't get handle to generated namespace: %s", err)
	}

	h, err := NewHandleAt(ns, nl.FAMILY_V4)
	if err != nil {
		t.Fatalf("failed to create netlink handle: %s", err)
	}

	flow := ConntrackFlow{
		FamilyType: FAMILY_V4,
		Forward: IPTuple{
			SrcIP:    net.IP{234, 234, 234, 234},
			DstIP:    net.IP{123, 123, 123, 123},
			SrcPort:  48385,
			DstPort:  53,
			Protocol: unix.IPPROTO_TCP,
		},
		Reverse: IPTuple{
			SrcIP:    net.IP{123, 123, 123, 123},
			DstIP:    net.IP{234, 234, 234, 234},
			SrcPort:  53,
			DstPort:  48385,
			Protocol: unix.IPPROTO_TCP,
		},
		TimeOut: 100,
		Mark:    12,
		ProtoInfo: &ProtoInfoTCP{
			State: nl.TCP_CONNTRACK_ESTABLISHED,
		},
	}

	// Create the entry using the handle
	if err := h.ConntrackCreate(ConntrackTable, nl.FAMILY_V4, &flow); err != nil {
		t.Fatalf("failed to insert conntrack: %s", err)
	}

	// Verify it exists
	flows, err := h.ConntrackTableList(ConntrackTable, nl.FAMILY_V4)
	if err != nil {
		t.Fatalf("failed to list conntracks following successful insert: %s", err)
	}
	filter := ConntrackFilter{
		ipNetFilter: map[ConntrackFilterType]*net.IPNet{
			ConntrackOrigSrcIP:  NewIPNet(flow.Forward.SrcIP),
			ConntrackOrigDstIP:  NewIPNet(flow.Forward.DstIP),
			ConntrackReplySrcIP: NewIPNet(flow.Reverse.SrcIP),
			ConntrackReplyDstIP: NewIPNet(flow.Reverse.DstIP),
		},
		portFilter: map[ConntrackFilterType]uint16{
			ConntrackOrigSrcPort: flow.Forward.SrcPort,
			ConntrackOrigDstPort: flow.Forward.DstPort,
		},
		protoFilter: unix.IPPROTO_TCP,
	}
	var match *ConntrackFlow
	for _, f := range flows {
		if filter.MatchConntrackFlow(f) {
			match = f
			break
		}
	}
	if match == nil {
		t.Fatalf("didn't find any matching conntrack entries for original flow: %+v\n Filter used: %+v", flow, filter)
	}

	// Delete using the handler
	if err := h.ConntrackDelete(ConntrackTable, InetFamily(nl.FAMILY_V4), &flow); err != nil {
		t.Fatalf("failed to delete conntrack via handler: %s", err)
	}

	// Verify it's gone
	flows, err = h.ConntrackTableList(ConntrackTable, nl.FAMILY_V4)
	if err != nil {
		t.Fatalf("failed to list conntracks following delete: %s", err)
	}
	for _, f := range flows {
		if filter.MatchConntrackFlow(f) {
			t.Fatalf("found flow after delete: %+v", f)
		}
	}
}

// TestConntrackDeleteV6 creates an IPv6 conntrack entry, verifies it exists,
// deletes it via Handle.ConntrackDelete, and verifies it was removed.
func TestConntrackDeleteV6(t *testing.T) {
	// Print timestamps in UTC
	os.Setenv("TZ", "")

	requiredModules := []string{"nf_conntrack", "nf_conntrack_netlink"}
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// Conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		requiredModules = append(requiredModules, "nf_conntrack_ipv4")
	}
	// Implicitly skips test if not root:
	nsStr, teardown := setUpNamedNetlinkTestWithKModule(t, requiredModules...)
	t.Cleanup(teardown)

	ns, err := netns.GetFromName(nsStr)
	if err != nil {
		t.Fatalf("couldn't get handle to generated namespace: %s", err)
	}

	h, err := NewHandleAt(ns, nl.FAMILY_V6)
	if err != nil {
		t.Fatalf("failed to create netlink handle: %s", err)
	}

	flow := ConntrackFlow{
		FamilyType: FAMILY_V6,
		Forward: IPTuple{
			SrcIP:    net.ParseIP("2001:db8::68"),
			DstIP:    net.ParseIP("2001:db9::32"),
			SrcPort:  48385,
			DstPort:  53,
			Protocol: unix.IPPROTO_TCP,
		},
		Reverse: IPTuple{
			SrcIP:    net.ParseIP("2001:db9::32"),
			DstIP:    net.ParseIP("2001:db8::68"),
			SrcPort:  53,
			DstPort:  48385,
			Protocol: unix.IPPROTO_TCP,
		},
		TimeOut: 100,
		Mark:    12,
		ProtoInfo: &ProtoInfoTCP{
			State: nl.TCP_CONNTRACK_ESTABLISHED,
		},
	}

	// Create the entry using the handle
	if err := h.ConntrackCreate(ConntrackTable, nl.FAMILY_V6, &flow); err != nil {
		t.Fatalf("failed to insert conntrack: %s", err)
	}

	// Verify it exists
	flows, err := h.ConntrackTableList(ConntrackTable, nl.FAMILY_V6)
	if err != nil {
		t.Fatalf("failed to list conntracks following successful insert: %s", err)
	}
	filter := ConntrackFilter{
		ipNetFilter: map[ConntrackFilterType]*net.IPNet{
			ConntrackOrigSrcIP:  NewIPNet(flow.Forward.SrcIP),
			ConntrackOrigDstIP:  NewIPNet(flow.Forward.DstIP),
			ConntrackReplySrcIP: NewIPNet(flow.Reverse.SrcIP),
			ConntrackReplyDstIP: NewIPNet(flow.Reverse.DstIP),
		},
		portFilter: map[ConntrackFilterType]uint16{
			ConntrackOrigSrcPort: flow.Forward.SrcPort,
			ConntrackOrigDstPort: flow.Forward.DstPort,
		},
		protoFilter: unix.IPPROTO_TCP,
	}
	var match *ConntrackFlow
	for _, f := range flows {
		if filter.MatchConntrackFlow(f) {
			match = f
			break
		}
	}
	if match == nil {
		t.Fatalf("didn't find any matching conntrack entries for original flow: %+v\n Filter used: %+v", flow, filter)
	}

	// Delete using the handler
	if err := h.ConntrackDelete(ConntrackTable, InetFamily(nl.FAMILY_V6), &flow); err != nil {
		t.Fatalf("failed to delete conntrack via handler: %s", err)
	}

	// Verify it's gone
	flows, err = h.ConntrackTableList(ConntrackTable, nl.FAMILY_V6)
	if err != nil {
		t.Fatalf("failed to list conntracks following delete: %s", err)
	}
	for _, f := range flows {
		if filter.MatchConntrackFlow(f) {
			t.Fatalf("found flow after delete: %+v", f)
		}
	}
}

// TestConntrackLabels test the conntrack table labels
// Creates some flows and then checks the labels associated
func TestConntrackLabels(t *testing.T) {
	skipUnlessRoot(t)
	t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack"))
	t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack_netlink"))
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	// conntrack l3proto was unified since 4.19
	// https://github.com/torvalds/linux/commit/a0ae2562c6c4b2721d9fddba63b7286c13517d9f
	if k < 4 || k == 4 && m < 19 {
		t.Cleanup(setUpNetlinkTestWithKModule(t, "nf_conntrack_ipv4"))
	}
	// Creates a new namespace and bring up the loopback interface
	origns, ns, h := nsCreateAndEnter(t)
	defer netns.Set(*origns)
	defer origns.Close()
	defer ns.Close()
	defer runtime.UnlockOSThread()

	flow := ConntrackFlow{
		FamilyType: FAMILY_V4,
		Forward: IPTuple{
			SrcIP:    net.IP{234, 234, 234, 234},
			DstIP:    net.IP{123, 123, 123, 123},
			SrcPort:  48385,
			DstPort:  53,
			Protocol: unix.IPPROTO_TCP,
		},
		Reverse: IPTuple{
			SrcIP:    net.IP{123, 123, 123, 123},
			DstIP:    net.IP{234, 234, 234, 234},
			SrcPort:  53,
			DstPort:  48385,
			Protocol: unix.IPPROTO_TCP,
		},
		// No point checking equivalence of timeout, but value must
		// be reasonable to allow for a potentially slow subsequent read.
		TimeOut: 100,
		Mark:    12,
		Labels:  []byte{0, 0, 0, 0, 3, 4, 61, 141, 207, 170, 2, 0, 0, 0, 0, 0},
		ProtoInfo: &ProtoInfoTCP{
			State: nl.TCP_CONNTRACK_SYN_SENT2,
		},
	}

	err = h.ConntrackUpdate(ConntrackTable, nl.FAMILY_V4, &flow)
	if err == nil {
		t.Fatalf("expected an error to occur when trying to update a non-existant conntrack: %+v", flow)
	}

	err = h.ConntrackCreate(ConntrackTable, nl.FAMILY_V4, &flow)
	if err != nil {
		t.Fatalf("failed to insert conntrack: %s", err)
	}

	flows, err := h.ConntrackTableList(ConntrackTable, nl.FAMILY_V4)
	if err != nil {
		t.Fatalf("failed to list conntracks following successful insert: %s", err)
	}

	filter := ConntrackFilter{
		ipNetFilter: map[ConntrackFilterType]*net.IPNet{
			ConntrackOrigSrcIP:  NewIPNet(flow.Forward.SrcIP),
			ConntrackOrigDstIP:  NewIPNet(flow.Forward.DstIP),
			ConntrackReplySrcIP: NewIPNet(flow.Reverse.SrcIP),
			ConntrackReplyDstIP: NewIPNet(flow.Reverse.DstIP),
		},
		portFilter: map[ConntrackFilterType]uint16{
			ConntrackOrigSrcPort: flow.Forward.SrcPort,
			ConntrackOrigDstPort: flow.Forward.DstPort,
		},
		protoFilter: unix.IPPROTO_TCP,
	}

	var match *ConntrackFlow
	for _, f := range flows {
		if filter.MatchConntrackFlow(f) {
			match = f
			break
		}
	}

	if match == nil {
		t.Fatalf("Didn't find any matching conntrack entries for original flow: %+v\n Filter used: %+v", flow, filter)
	} else {
		t.Logf("Found entry in conntrack table matching original flow: %+v labels=%+v", match, match.Labels)
	}
	checkFlowsEqual(t, &flow, match)
	checkProtoInfosEqual(t, flow.ProtoInfo, match.ProtoInfo)

	// Change the conntrack and update the kernel entry.
	flow.Mark = 10
	flow.Labels = make([]byte, 16) // zero labels
	flow.ProtoInfo = &ProtoInfoTCP{
		State: nl.TCP_CONNTRACK_ESTABLISHED,
	}
	err = h.ConntrackUpdate(ConntrackTable, nl.FAMILY_V4, &flow)
	if err != nil {
		t.Fatalf("failed to update conntrack with new mark: %s", err)
	}

	// Look for updated conntrack.
	flows, err = h.ConntrackTableList(ConntrackTable, nl.FAMILY_V4)
	if err != nil {
		t.Fatalf("failed to list conntracks following successful update: %s", err)
	}

	var updatedMatch *ConntrackFlow
	for _, f := range flows {
		if filter.MatchConntrackFlow(f) {
			updatedMatch = f
			break
		}
	}
	if updatedMatch == nil {
		t.Fatalf("Didn't find any matching conntrack entries for updated flow: %+v\n Filter used: %+v", flow, filter)
	} else {
		t.Logf("Found entry in conntrack table matching updated flow: %+v labels=%+v", updatedMatch, updatedMatch.Labels)
	}

	// To clear the labels we send an empty slice, but when reading back
	// from the kernel we get a nil slice.
	flow.Labels = nil
	checkFlowsEqual(t, &flow, updatedMatch)
	checkProtoInfosEqual(t, flow.ProtoInfo, updatedMatch.ProtoInfo)
	// Switch back to the original namespace
	netns.Set(*origns)
}

// TestConntrackFlowToNlData generates a serialized representation of a
// ConntrackFlow and runs the resulting bytes back through `parseRawData` to validate.
func TestConntrackFlowToNlData(t *testing.T) {
	flowV4 := ConntrackFlow{
		FamilyType: FAMILY_V4,
		Forward: IPTuple{
			SrcIP:    net.IP{234, 234, 234, 234},
			DstIP:    net.IP{123, 123, 123, 123},
			SrcPort:  48385,
			DstPort:  53,
			Protocol: unix.IPPROTO_TCP,
		},
		Reverse: IPTuple{
			SrcIP:    net.IP{123, 123, 123, 123},
			DstIP:    net.IP{234, 234, 234, 234},
			SrcPort:  53,
			DstPort:  48385,
			Protocol: unix.IPPROTO_TCP,
		},
		Mark:    5,
		Labels:  []byte{0, 0, 0, 0, 3, 4, 61, 141, 207, 170, 2, 0, 0, 0, 0, 0},
		TimeOut: 10,
		ProtoInfo: &ProtoInfoTCP{
			State: nl.TCP_CONNTRACK_ESTABLISHED,
		},
	}
	flowV6 := ConntrackFlow{
		FamilyType: FAMILY_V6,
		Forward: IPTuple{
			SrcIP:    net.ParseIP("2001:db8::68"),
			DstIP:    net.ParseIP("2001:db9::32"),
			SrcPort:  48385,
			DstPort:  53,
			Protocol: unix.IPPROTO_TCP,
		},
		Reverse: IPTuple{
			SrcIP:    net.ParseIP("2001:db9::32"),
			DstIP:    net.ParseIP("2001:db8::68"),
			SrcPort:  53,
			DstPort:  48385,
			Protocol: unix.IPPROTO_TCP,
		},
		Mark:    5,
		Labels:  []byte{0, 0, 0, 0, 3, 4, 61, 141, 207, 170, 2, 0, 0, 0, 0, 0},
		TimeOut: 10,
		ProtoInfo: &ProtoInfoTCP{
			State: nl.TCP_CONNTRACK_ESTABLISHED,
		},
	}

	var bytesV4, bytesV6 []byte

	attrsV4, err := flowV4.toNlData()
	if err != nil {
		t.Fatalf("Error converting ConntrackFlow to netlink messages: %s", err)
	}
	// Mock nfgenmsg header
	bytesV4 = append(bytesV4, flowV4.FamilyType, 0, 0, 0)
	for _, a := range attrsV4 {
		bytesV4 = append(bytesV4, a.Serialize()...)
	}

	attrsV6, err := flowV6.toNlData()
	if err != nil {
		t.Fatalf("Error converting ConntrackFlow to netlink messages: %s", err)
	}
	// Mock nfgenmsg header
	bytesV6 = append(bytesV6, flowV6.FamilyType, 0, 0, 0)
	for _, a := range attrsV6 {
		bytesV6 = append(bytesV6, a.Serialize()...)
	}

	parsedFlowV4 := parseRawData(bytesV4)
	checkFlowsEqual(t, &flowV4, parsedFlowV4)
	checkProtoInfosEqual(t, flowV4.ProtoInfo, parsedFlowV4.ProtoInfo)

	parsedFlowV6 := parseRawData(bytesV6)
	checkFlowsEqual(t, &flowV6, parsedFlowV6)
	checkProtoInfosEqual(t, flowV6.ProtoInfo, parsedFlowV6.ProtoInfo)
}

func checkFlowsEqual(t *testing.T, f1, f2 *ConntrackFlow) {
	// No point checking timeout as it will differ between reads.
	// Timestart and timestop may also differ.
	if f1.FamilyType != f2.FamilyType {
		t.Logf("Conntrack flow FamilyTypes differ. Tuple1: %d, Tuple2: %d.\n", f1.FamilyType, f2.FamilyType)
		t.Fail()
	}
	if f1.Mark != f2.Mark {
		t.Logf("Conntrack flow Marks differ. Tuple1: %d, Tuple2: %d.\n", f1.Mark, f2.Mark)
		t.Fail()
	}
	if !tuplesEqual(f1.Forward, f2.Forward) {
		t.Logf("Forward tuples mismatch. Tuple1 forward flow: %+v, Tuple2 forward flow: %+v.\n", f1.Forward, f2.Forward)
		t.Fail()
	}
	if !tuplesEqual(f1.Reverse, f2.Reverse) {
		t.Logf("Reverse tuples mismatch. Tuple1 reverse flow: %+v, Tuple2 reverse flow: %+v.\n", f1.Reverse, f2.Reverse)
		t.Fail()
	}

	if !bytes.Equal(f1.Labels, f2.Labels) {
		t.Logf("Conntrack flow Labels differ. Tuple1: %+v, Tuple2: %+v.\n", f1.Labels, f2.Labels)
		t.Fail()
	}
}

func checkProtoInfosEqual(t *testing.T, p1, p2 ProtoInfo) {
	t.Logf("Checking protoinfo fields equal:\n\t p1: %+v\n\t p2: %+v", p1, p2)
	if !protoInfosEqual(p1, p2) {
		t.Logf("Protoinfo structs differ: P1: %+v, P2: %+v", p1, p2)
		t.Fail()
	}
}

func protoInfosEqual(p1, p2 ProtoInfo) bool {
	if p1 == nil {
		return p2 == nil
	} else if p2 != nil {
		return p1.Protocol() == p2.Protocol()
	}

	return false
}

func tuplesEqual(t1, t2 IPTuple) bool {
	if t1.Bytes != t2.Bytes {
		return false
	}

	if !t1.DstIP.Equal(t2.DstIP) {
		return false
	}

	if !t1.SrcIP.Equal(t2.SrcIP) {
		return false
	}

	if t1.DstPort != t2.DstPort {
		return false
	}

	if t1.SrcPort != t2.SrcPort {
		return false
	}

	if t1.Packets != t2.Packets {
		return false
	}

	if t1.Protocol != t2.Protocol {
		return false
	}

	return true
}
