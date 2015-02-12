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

	pi1 := NewProtinfo()
	pi1.Hairpin = 1
	pi1.RootBlock = 1

	oldpi1, err := LinkGetProtinfo(iface1)
	if err != nil {
		t.Fatal(err)
	}

	pi2 := NewProtinfo()
	pi2.Guard = 1
	pi2.Learning = 0

	oldpi2, err := LinkGetProtinfo(iface2)
	if err != nil {
		t.Fatal(err)
	}

	pi3 := NewProtinfo()

	if err := LinkSetProtinfo(iface1, pi1); err != nil {
		t.Fatal(err)
	}

	gpi1, err := LinkGetProtinfo(iface1)
	if err != nil {
		t.Fatal(err)
	}
	if gpi1.Hairpin != 1 {
		t.Fatalf("Hairpin mode is not enabled for %s, but should", iface1.Name)
	}

	if gpi1.RootBlock != 1 {
		t.Fatalf("RootBlock is not enabled for %s, but should", iface1.Name)
	}

	if gpi1.Guard != oldpi1.Guard {
		t.Fatalf("Guard field was changed for %s but shouldn't", iface1.Name)
	}
	if gpi1.FastLeave != oldpi1.FastLeave {
		t.Fatalf("FastLeave field was changed for %s but shouldn't", iface1.Name)
	}
	if gpi1.Learning != oldpi1.Learning {
		t.Fatalf("Learning field was changed for %s but shouldn't", iface1.Name)
	}
	if gpi1.Flood != oldpi1.Flood {
		t.Fatalf("Flood field was changed for %s but shouldn't", iface1.Name)
	}

	if err := LinkSetProtinfo(iface2, pi2); err != nil {
		t.Fatal(err)
	}
	gpi2, err := LinkGetProtinfo(iface2)
	if err != nil {
		t.Fatal(err)
	}
	if gpi2.Hairpin != 0 {
		t.Fatalf("Hairpin mode is enabled for %s, but shouldn't", iface2.Name)
	}

	if gpi2.Guard != 1 {
		t.Fatalf("Guard is not enabled for %s, but should", iface2.Name)
	}

	if gpi2.Learning != 0 {
		t.Fatalf("Learning is enabled for %s, but shouldn't", iface2.Name)
	}
	if gpi2.RootBlock != oldpi2.RootBlock {
		t.Fatalf("RootBlock field was changed for %s but shouldn't", iface2.Name)
	}
	if gpi2.FastLeave != oldpi2.FastLeave {
		t.Fatalf("FastLeave field was changed for %s but shouldn't", iface2.Name)
	}
	if gpi2.Flood != oldpi2.Flood {
		t.Fatalf("Flood field was changed for %s but shouldn't", iface2.Name)
	}

	if err := LinkSetProtinfo(iface3, pi3); err == nil || err.Error() != "operation not supported" {
		t.Fatal("Set protinfo for link without master is not supported, but err: %s", err)
	}
}
