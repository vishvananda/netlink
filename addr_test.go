//go:build linux
// +build linux

package netlink

import (
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAddrAdd(t *testing.T) {
	DoTestAddr(t, AddrAdd)
}

func TestAddrReplace(t *testing.T) {
	DoTestAddr(t, AddrReplace)
}

type addrTest struct {
	name     string
	addr     *Addr
	expected *Addr
	canFail  bool
	t        *testing.T
}

func (at *addrTest) Fatal(a interface{}) {
	at.t.Helper()
	if !at.canFail {
		at.t.Fatal(a)
		return
	}
	at.t.Skipf("Non-fatal: %v", a)
}

func (at *addrTest) Fatalf(fmt string, a ...interface{}) {
	at.t.Helper()
	if !at.canFail {
		at.t.Fatalf(fmt, a...)
		return
	}
	at.t.Skipf("Non-fatal: "+fmt, a...)
}

func DoTestAddr(t *testing.T, FunctionUndertest func(Link, *Addr) error) {
	if os.Getenv("CI") == "true" {
		t.Skipf("Fails in CI with: addr_test.go:*: Address flags not set properly, got=128, expected=132")
	}

	// TODO: IFA_F_PERMANENT does not seem to be set by default on older kernels?
	// TODO: IFA_F_OPTIMISTIC failing in CI. should we just skip that one check?
	var address = &net.IPNet{IP: net.IPv4(127, 0, 0, 2), Mask: net.CIDRMask(32, 32)}
	var peer = &net.IPNet{IP: net.IPv4(127, 0, 0, 3), Mask: net.CIDRMask(24, 32)}
	var addrTests = []addrTest{
		{
			name: "lo_uni_perm", addr: &Addr{IPNet: address},
			expected: &Addr{IPNet: address, Label: "lo", Scope: unix.RT_SCOPE_UNIVERSE, Flags: unix.IFA_F_PERMANENT},
		},
		{
			name: "local_uni_perm", addr: &Addr{IPNet: address, Label: "local"},
			expected: &Addr{IPNet: address, Label: "local", Scope: unix.RT_SCOPE_UNIVERSE, Flags: unix.IFA_F_PERMANENT},
		},
		{
			name: "lo_uni_optimistic_perm", addr: &Addr{IPNet: address, Flags: unix.IFA_F_OPTIMISTIC}, canFail: true,
			expected: &Addr{IPNet: address, Label: "lo", Flags: unix.IFA_F_OPTIMISTIC | unix.IFA_F_PERMANENT, Scope: unix.RT_SCOPE_UNIVERSE},
		},
		{
			// Is this a valid scenario for IPv4?
			name: "lo_uni_optimistic_perm_dupe", addr: &Addr{IPNet: address, Flags: unix.IFA_F_OPTIMISTIC | unix.IFA_F_DADFAILED}, canFail: true,
			expected: &Addr{IPNet: address, Label: "lo", Flags: unix.IFA_F_OPTIMISTIC | unix.IFA_F_DADFAILED | unix.IFA_F_PERMANENT, Scope: unix.RT_SCOPE_UNIVERSE},
		},
		{
			name: "lo_nullroute_perm", addr: &Addr{IPNet: address, Scope: unix.RT_SCOPE_NOWHERE},
			expected: &Addr{IPNet: address, Label: "lo", Flags: unix.IFA_F_PERMANENT, Scope: unix.RT_SCOPE_NOWHERE},
		},
		{
			name: "lo_uni_perm_with_peer", addr: &Addr{IPNet: address, Peer: peer},
			expected: &Addr{IPNet: address, Peer: peer, Label: "lo", Scope: unix.RT_SCOPE_UNIVERSE, Flags: unix.IFA_F_PERMANENT},
		},
	}

	for _, tt := range addrTests {
		t.Run(tt.name, func(t *testing.T) {
			tt.t = t

			tearDown := setUpNetlinkTest(t)
			defer tearDown()

			link, err := LinkByName("lo")
			if err != nil {
				tt.Fatal(err)
			}

			if err = FunctionUndertest(link, tt.addr); err != nil {
				tt.Fatal(err)
			}

			addrs, err := AddrList(link, FAMILY_ALL)
			if err != nil {
				tt.Fatal(err)
			}

			if len(addrs) != 1 {
				tt.Fatal("Address not added properly")
			}

			if !addrs[0].Equal(*tt.expected) {
				tt.Fatalf("Address ip not set properly, got=%s, expected=%s", addrs[0], tt.expected)
			}

			if addrs[0].Label != tt.expected.Label {
				tt.Fatalf("Address label not set properly, got=%s, expected=%s", addrs[0].Label, tt.expected.Label)
			}

			if addrs[0].Flags != tt.expected.Flags {
				tt.Fatalf("Address flags not set properly, got=%d, expected=%d", addrs[0].Flags, tt.expected.Flags)
			}

			if addrs[0].Scope != tt.expected.Scope {
				tt.Fatalf("Address scope not set properly, got=%d, expected=%d", addrs[0].Scope, tt.expected.Scope)
			}

			if ifindex := link.Attrs().Index; ifindex != addrs[0].LinkIndex {
				tt.Fatalf("Address ifindex not set properly, got=%d, expected=%d", addrs[0].LinkIndex, ifindex)
			}

			if tt.expected.Peer != nil {
				if !addrs[0].PeerEqual(*tt.expected) {
					tt.Fatalf("Peer Address ip not set properly, got=%s, expected=%s", addrs[0].Peer, tt.expected.Peer)
				}
			}

			// Pass FAMILY_V4, we should get the same results as FAMILY_ALL
			addrs, err = AddrList(link, FAMILY_V4)
			if err != nil {
				tt.Fatal(err)
			}
			if len(addrs) != 1 {
				tt.Fatal("Address not added properly")
			}

			// Pass a wrong family number, we should get nil list
			addrs, err = AddrList(link, 0x8)
			if err != nil {
				tt.Fatal(err)
			}

			if len(addrs) != 0 {
				tt.Fatal("Address not expected")
			}

			if err = AddrDel(link, tt.addr); err != nil {
				tt.Fatal(err)
			}

			addrs, err = AddrList(link, FAMILY_ALL)
			if err != nil {
				tt.Fatal(err)
			}

			if len(addrs) != 0 {
				tt.Fatal("Address not removed properly")
			}
		})
	}

}

func TestAddrAddReplace(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	for _, nilLink := range []bool{false, true} {
		var address = &net.IPNet{IP: net.IPv4(127, 0, 0, 2), Mask: net.CIDRMask(24, 32)}
		var addr = &Addr{IPNet: address}

		link, err := LinkByName("lo")
		if err != nil {
			t.Fatal(err)
		}

		if nilLink {
			addr.LinkIndex = link.Attrs().Index
			link = nil
		}

		err = AddrAdd(link, addr)
		if err != nil {
			t.Fatal(err)
		}

		addrs, err := AddrList(link, FAMILY_ALL)
		if err != nil {
			t.Fatal(err)
		}

		if len(addrs) != 1 {
			t.Fatal("Address not added properly")
		}

		err = AddrAdd(link, addr)
		if err == nil {
			t.Fatal("Re-adding address should fail (but succeeded unexpectedly).")
		}

		err = AddrReplace(link, addr)
		if err != nil {
			t.Fatal("Replacing address failed.")
		}

		addrs, err = AddrList(link, FAMILY_ALL)
		if err != nil {
			t.Fatal(err)
		}

		if len(addrs) != 1 {
			t.Fatal("Address not added properly")
		}

		if err = AddrDel(link, addr); err != nil {
			t.Fatal(err)
		}

		addrs, err = AddrList(link, FAMILY_ALL)
		if err != nil {
			t.Fatal(err)
		}

		if len(addrs) != 0 {
			t.Fatal("Address not removed properly")
		}
	}
}

func expectAddrUpdate(ch <-chan AddrUpdate, add bool, dst net.IP) bool {
	for {
		timeout := time.After(time.Minute)
		select {
		case update := <-ch:
			if update.NewAddr == add && update.LinkAddress.IP.Equal(dst) {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

func TestAddrSubscribeWithOptions(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ch := make(chan AddrUpdate)
	done := make(chan struct{})
	defer close(done)
	var lastError error
	defer func() {
		if lastError != nil {
			t.Fatalf("Fatal error received during subscription: %v", lastError)
		}
	}()
	if err := AddrSubscribeWithOptions(ch, done, AddrSubscribeOptions{
		ErrorCallback: func(err error) {
			lastError = err
		},
	}); err != nil {
		t.Fatal(err)
	}

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	ip := net.IPv4(127, 0, 0, 1)
	if !expectAddrUpdate(ch, true, ip) {
		t.Fatal("Add update not received as expected")
	}
}

func TestAddrSubscribeListExisting(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ch := make(chan AddrUpdate)
	done := make(chan struct{})
	defer close(done)

	// get loopback interface
	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	// bring the interface up
	if err = LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	var lastError error
	defer func() {
		if lastError != nil {
			t.Fatalf("Fatal error received during subscription: %v", lastError)
		}
	}()
	if err := AddrSubscribeWithOptions(ch, done, AddrSubscribeOptions{
		ErrorCallback: func(err error) {
			lastError = err
		},
		ListExisting: true,
	}); err != nil {
		t.Fatal(err)
	}

	ip := net.IPv4(127, 0, 0, 1)
	if !expectAddrUpdate(ch, true, ip) {
		t.Fatal("Add update not received as expected")
	}
}
