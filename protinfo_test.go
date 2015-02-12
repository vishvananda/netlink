package netlink

import "testing"

func TestProtinfo(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	master := &Bridge{LinkAttrs{Name: "foo"}}
	if err := LinkAdd(master); err != nil {
		t.Fatal(err)
	}
	iface1 := &Dummy{LinkAttrs{Name: "bar1", MasterIndex: master.Index}}
	iface2 := &Dummy{LinkAttrs{Name: "bar2", MasterIndex: master.Index}}
	iface3 := &Dummy{LinkAttrs{Name: "bar3"}}

	if err := LinkAdd(iface1); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(iface2); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(iface3); err != nil {
		t.Fatal(err)
	}

	pi1 := Protinfo{
		Hairpin:   true,
		RootBlock: true,
	}

	pi2 := Protinfo{
		Guard:    true,
		Learning: false,
	}

	pi3 := Protinfo{}

	if err := LinkSetProtinfo(iface1, pi1); err != nil {
		t.Fatal(err)
	}

	gpi1, err := LinkGetProtinfo(iface1)
	if err != nil {
		t.Fatal(err)
	}
	if !gpi1.Hairpin {
		t.Fatalf("Hairpin mode is not enabled for %s, but should", iface1.Name)
	}

	if !gpi1.RootBlock {
		t.Fatalf("RootBlock is not enabled for %s, but should", iface1.Name)
	}

	if err := LinkSetProtinfo(iface2, pi2); err != nil {
		t.Fatal(err)
	}
	gpi2, err := LinkGetProtinfo(iface2)
	if err != nil {
		t.Fatal(err)
	}
	if gpi2.Hairpin {
		t.Fatalf("Hairpin mode is enabled for %s, but shouldn't", iface2.Name)
	}

	if !gpi2.Guard {
		t.Fatalf("Guard is not enabled for %s, but should", iface2.Name)
	}

	if gpi2.Learning {
		t.Fatalf("Learning is enabled for %s, but shouldn't", iface2.Name)
	}

	if err := LinkSetProtinfo(iface3, pi3); err == nil || err.Error() != "operation not supported" {
		t.Fatalf("Set protinfo for link without master is not supported, but err: %s", err)
	}
}
