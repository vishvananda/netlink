package netlink

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/vishvananda/netns"
)

func TestHandleCreateDelete(t *testing.T) {
	h, err := NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	if h.routeSocket == nil || h.xfrmSocket == nil {
		t.Fatalf("Handle socket(s) were not created")
	}

	h.Delete()
	if h.routeSocket != nil || h.xfrmSocket != nil {
		t.Fatalf("Handle socket(s) were not destroyed")
	}
}

func TestHandleCreateNetns(t *testing.T) {
	id := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		t.Fatal(err)
	}
	ifName := "dummy-" + hex.EncodeToString(id)

	// Create an handle on the current netns
	curNs, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer curNs.Close()

	ch, err := NewHandleAt(curNs)
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Delete()

	// Create an handle on a custom netns
	newNs, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer newNs.Close()

	nh, err := NewHandleAt(newNs)
	if err != nil {
		t.Fatal(err)
	}
	defer nh.Delete()

	// Create an interface using the current handle
	err = ch.LinkAdd(&Dummy{LinkAttrs{Name: ifName}})
	if err != nil {
		t.Fatal(err)
	}
	l, err := ch.LinkByName(ifName)
	if err != nil {
		t.Fatal(err)
	}
	if l.Type() != "dummy" {
		t.Fatalf("Unexpected link type: %s", l.Type())
	}

	// Verify the new handle cannot find the interface
	ll, err := nh.LinkByName(ifName)
	if err == nil {
		t.Fatalf("Unexpected link found on netns %s: %v", newNs, ll)
	}

	// Move the interface to the new netns
	err = ch.LinkSetNsFd(l, int(newNs))
	if err != nil {
		t.Fatal(err)
	}

	// Verify new netns handle can find the interface while current cannot
	ll, err = nh.LinkByName(ifName)
	if err != nil {
		t.Fatal(err)
	}
	if ll.Type() != "dummy" {
		t.Fatalf("Unexpected link type: %s", ll.Type())
	}
	ll, err = ch.LinkByName(ifName)
	if err == nil {
		t.Fatalf("Unexpected link found on netns %s: %v", curNs, ll)
	}
}
