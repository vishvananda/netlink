package netlink

import (
	"net"
	"syscall"
	"testing"
)

func TestAddrAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	addr, err := ParseAddr("127.1.1.1/24 local")
	if err != nil {
		t.Fatal(err)
	}

	if err = AddrAdd(link, addr); err != nil {
		t.Fatal(err)
	}

	addrs, err := AddrList(link, FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}

	if len(addrs) != 1 || !addr.Equal(addrs[0]) || addrs[0].Label != addr.Label {
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

func TestAddrAddDelScope(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	addr := &Addr{
		IPNet: &net.IPNet{
			IP:   net.IPv4(127, 1, 1, 1),
			Mask: net.CIDRMask(24, 32),
		},
		Scope: syscall.RT_SCOPE_LINK,
	}
	if err = AddrAdd(link, addr); err != nil {
		t.Fatal(err)
	}

	addrs, err := AddrList(link, FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}

	if len(addrs) != 1 || !addr.Equal(addrs[0]) {
		t.Fatal("Address not added properly")
	}

	if addrs[0].Scope != addr.Scope {
		t.Fatal("Address scope not added properly")
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

func TestAddrAddDelFlags(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	addr := &Addr{
		IPNet: &net.IPNet{
			IP:   net.IPv4(127, 1, 1, 1),
			Mask: net.CIDRMask(24, 32),
		},
		Flags: syscall.IFA_F_PERMANENT,
	}
	if err = AddrAdd(link, addr); err != nil {
		t.Fatal(err)
	}

	addrs, err := AddrList(link, FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}

	if len(addrs) != 1 || !addr.Equal(addrs[0]) {
		t.Fatal("Address not added properly")
	}

	if addrs[0].Flags != addr.Flags {
		t.Fatal("Address flags not set properly")
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
