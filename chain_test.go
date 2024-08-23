//go:build linux
// +build linux

package netlink

import (
	"testing"
)

func TestChainAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "bar"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	qdisc := &Ingress{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(0xffff, 0),
			Parent:    HANDLE_INGRESS,
		},
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	_, ok := qdiscs[0].(*Ingress)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	chainVal := new(uint32)
	*chainVal = 20
	chain := NewChain(HANDLE_INGRESS, *chainVal)
	err = ChainAdd(link, chain)
	if err != nil {
		t.Fatal(err)
	}
	chains, err := ChainList(link, HANDLE_INGRESS)
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 1 {
		t.Fatal("Failed to add chain")
	}
	if chains[0].Chain != *chainVal {
		t.Fatal("Incorrect chain added")
	}
	if chains[0].Parent != HANDLE_INGRESS {
		t.Fatal("Incorrect chain parent")
	}
	if err := ChainDel(link, chain); err != nil {
		t.Fatal(err)
	}
	chains, err = ChainList(link, HANDLE_INGRESS)
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 0 {
		t.Fatal("Failed to remove chain")
	}
}
