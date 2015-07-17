package netlink

import (
	"testing"
)

func TestAddrAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	link, err := LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}

	addr, err := ParseAddr("127.1.1.1/24")
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

	if len(addrs) != 1 || !addr.Equal(addrs[0]) {
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
