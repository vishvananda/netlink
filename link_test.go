package netlink

import (
	"github.com/vishvananda/netns"
	"testing"
)

func testLinkAddDel(t *testing.T, link *Link) {
	links, err := LinkList()
	if err != nil {
		t.Fatal(err)
	}
	num := len(links)

	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	l, err := LinkByName(link.Name)

	if err != nil {
		t.Fatal(err)
	}

	if l.Type != link.Type {
		t.Fatal("Link.Type doesn't match")
	}

	if l.VlanId != link.VlanId {
		t.Fatal("Link.VlanId id doesn't match")
	}

	if l.Parent == nil && link.Parent != nil {
		t.Fatal("Created link doesn't have a Parent but it should")
	} else if l.Parent != nil && link.Parent == nil {
		t.Fatal("Created link has a Parent but it shouldn't")
	} else if l.Parent != nil && link.Parent != nil {
		if l.Parent.Index != link.Parent.Index {
			t.Fatal("Link.Parent.Index doesn't match")
		}
	}

	if link.PeerName != "" {
		_, err := LinkByName(link.PeerName)
		if err != nil {
			t.Fatal("Peer %s not created", link.PeerName)
		}
	}

	if err = LinkDel(link); err != nil {
		t.Fatal(err)
	}

	links, err = LinkList()
	if err != nil {
		t.Fatal(err)
	}

	if len(links) != num {
		t.Fatal("Link not removed properly")
	}
}

func TestLinkAddDelDummy(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Link{Name: "foo", Type: "dummy"})
}

func TestLinkAddDelBridge(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Link{Name: "foo", Type: "bridge"})
}

func TestLinkAddDelVlan(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Link{Name: "foo", Type: "dummy"}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}
	testLinkAddDel(t, &Link{Name: "bar", Type: "vlan", Parent: parent, VlanId: 900})

	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelMacvlan(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	parent := &Link{Name: "foo", Type: "dummy"}
	if err := LinkAdd(parent); err != nil {
		t.Fatal(err)
	}
	testLinkAddDel(t, &Link{Name: "bar", Type: "macvlan", Parent: parent})

	if err := LinkDel(parent); err != nil {
		t.Fatal(err)
	}
}

func TestLinkAddDelVeth(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	testLinkAddDel(t, &Link{Name: "foo", Type: "veth", PeerName: "bar"})
}

func TestLinkAddDelBridgeMaster(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	master := &Link{Name: "foo", Type: "bridge"}
	if err := LinkAdd(master); err != nil {
		t.Fatal(err)
	}
	testLinkAddDel(t, &Link{Name: "bar", Type: "dummy", Master: master})

	if err := LinkDel(master); err != nil {
		t.Fatal(err)
	}
}

func TestLinkSetUnsetResetMaster(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	master := &Link{Name: "foo", Type: "bridge"}
	if err := LinkAdd(master); err != nil {
		t.Fatal(err)
	}

	newmaster := &Link{Name: "bar", Type: "bridge"}
	if err := LinkAdd(newmaster); err != nil {
		t.Fatal(err)
	}

	slave := &Link{Name: "baz", Type: "dummy"}
	if err := LinkAdd(slave); err != nil {
		t.Fatal(err)
	}

	if err := LinkSetMaster(slave, master); err != nil {
		t.Fatal(err)
	}

	link, err := LinkByName("baz")
	if err != nil {
		t.Fatal(err)
	}

	if link.Master == nil || link.Master.Index != master.Index {
		t.Fatal("Master not set properly")
	}

	if err := LinkSetMaster(slave, newmaster); err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("baz")
	if err != nil {
		t.Fatal(err)
	}

	if link.Master == nil || link.Master.Index != newmaster.Index {
		t.Fatal("Master not reset properly")
	}

	if err := LinkSetMaster(slave, nil); err != nil {
		t.Fatal(err)
	}

	link, err = LinkByName("baz")
	if err != nil {
		t.Fatal(err)
	}

	if link.Master != nil {
		t.Fatal("Master not unset properly")
	}
	if err := LinkDel(slave); err != nil {
		t.Fatal(err)
	}

	if err := LinkDel(newmaster); err != nil {
		t.Fatal(err)
	}

	if err := LinkDel(master); err != nil {
		t.Fatal(err)
	}
}

func TestLinkSetNs(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	basens, err := netns.Get()
	if err != nil {
		t.Fatal("Failed to get basens")
	}
	defer basens.Close()

	newns, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create newns")
	}
	defer newns.Close()

	link := &Link{Name: "foo", Type: "veth", PeerName: "bar"}
	if err := LinkAdd(link); err != nil {
		t.Fatal(err)
	}

	peer, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}

	LinkSetNsFd(peer, int(basens))
	if err != nil {
		t.Fatal("Failed to set newns for link")
	}

	_, err = LinkByName("bar")
	if err == nil {
		t.Fatal("Link bar is still in newns")
	}

	err = netns.Set(basens)
	if err != nil {
		t.Fatal("Failed to set basens")
	}

	peer, err = LinkByName("bar")
	if err != nil {
		t.Fatal("Link is not in basens")
	}

	if err := LinkDel(peer); err != nil {
		t.Fatal(err)
	}

	err = netns.Set(newns)
	if err != nil {
		t.Fatal("Failed to set newns")
	}

	_, err = LinkByName("foo")
	if err == nil {
		t.Fatal("Other half of veth pair not deleted")
	}

}
