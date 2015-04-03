package netlink

import "testing"

func TestLinkAddDelBond(t *testing.T) {
	num_begin, err := LinkList()
	if err != nil {
		t.Fatal(err)
	}

	link := &Bond{LinkAttrs: LinkAttrs{Name: "go_bond_test"}}
	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	link1, err := LinkByName("go_bond_test")
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := link1.(*Bond); !ok {
		t.Fatal("Link is not a bond")
	}

	if err := LinkDel(link); err != nil {
		t.Fatal(err)
	}

	num_end, err := LinkList()
	if err != nil {
		t.Fatal(err)
	}

	if len(num_begin) != len(num_end) {
		t.Fatal("Bond link not removed properly")
	}
}

// TODO: impelement parsing ARP_IP_TARGETS first
// func TestBondArpIpTargets(t *testing.T) {
// 	ip1, ip2 := net.ParseIP("1.2.3.4"), net.ParseIP("9.10.11.12")
// 	link := &Bond{
// 		LinkAttrs:    LinkAttrs{Name: "go_bond_test"},
// 		ArpIpTargets: []net.IP{ip1, ip2},
// 	}
//
// 	if err := LinkAdd(link); err != nil {
// 		t.Fatal(err)
// 	}
//
// 	link1, err := LinkByName("go_bond_test")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
//
// 	bond, ok := link1.(*Bond)
// 	if !ok {
// 		t.Fatal("Link is not a bond")
// 	}
//
// 	l := len(bond.ArpIpTargets)
// 	if l != 2 {
// 		t.Fatalf("Bond arp ip targets invalid lenght\ngot %d, expected %d", l, 2)
// 	}
//
// 	if err := LinkDel(link); err != nil {
// 		t.Fatal(err)
// 	}
// }
