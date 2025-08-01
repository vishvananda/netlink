//go:build linux
// +build linux

package netlink

import (
	"net"
	"testing"
)

func TestFouDeserializeMsg(t *testing.T) {
	var msg []byte

	// deserialize a valid message
	msg = []byte{3, 1, 0, 0, 5, 0, 2, 0, 2, 0, 0, 0, 6, 0, 1, 0, 21, 179, 0, 0, 5, 0, 3, 0, 4, 0, 0, 0, 5, 0, 4, 0, 1, 0, 0, 0}
	fou := deserializeFouMsg(msg)
	// check if message was deserialized correctly
	if fou.Family != FAMILY_V4 {
		t.Errorf("expected family %d, got %d", FAMILY_V4, fou.Family)
	}

	if fou.Port != 5555 {
		t.Errorf("expected port 5555, got %d", fou.Port)
	}

	if fou.Protocol != 4 { // ipip
		t.Errorf("expected protocol 4, got %d", fou.Protocol)
	}

	if fou.EncapType != FOU_ENCAP_DIRECT {
		t.Errorf("expected encap type %d, got %d", FOU_ENCAP_DIRECT, fou.EncapType)
	}

	// deserialize a valid message(kernel >= 5.2)
	msg = []byte{3, 1, 0, 0, 5, 0, 2, 0, 2, 0, 0, 0, 6, 0, 1, 0, 43, 103, 0, 0, 6, 0, 10, 0, 86, 206, 0, 0, 5, 0, 3, 0, 0, 0, 0, 0, 5, 0, 4, 0, 2, 0, 0, 0, 8, 0, 11, 0, 0, 0, 0, 0, 8, 0, 6, 0, 1, 2, 3, 4, 8, 0, 8, 0, 5, 6, 7, 8}
	fou = deserializeFouMsg(msg)
	if fou.Family != FAMILY_V4 {
		t.Errorf("expected family %d, got %d", FAMILY_V4, fou.Family)
	}

	if fou.Port != 11111 {
		t.Errorf("expected port 5555, got %d", fou.Port)
	}

	if fou.Protocol != 0 { // gue
		t.Errorf("expected protocol 0, got %d", fou.Protocol)
	}

	if fou.IfIndex != 0 {
		t.Errorf("expected ifindex 0, got %d", fou.Protocol)
	}

	if fou.EncapType != FOU_ENCAP_GUE {
		t.Errorf("expected encap type %d, got %d", FOU_ENCAP_GUE, fou.EncapType)
	}

	if expected := net.IPv4(1, 2, 3, 4); !fou.Local.Equal(expected) {
		t.Errorf("expected local %v, got %v", expected, fou.Local)
	}

	if expected := net.IPv4(5, 6, 7, 8); !fou.Peer.Equal(expected) {
		t.Errorf("expected peer %v, got %v", expected, fou.Peer)
	}

	if fou.PeerPort != 22222 {
		t.Errorf("expected peer port 0, got %d", fou.PeerPort)
	}

	// unknown attribute should be skipped
	msg = []byte{3, 1, 0, 0, 5, 0, 112, 0, 2, 0, 0, 0, 5, 0, 2, 0, 2, 0, 0}
	fou = deserializeFouMsg(msg)
	if fou.Family != 2 {
		t.Errorf("expected family 2, got %d", fou.Family)
	}
}

func TestFouAddDel(t *testing.T) {
	// foo-over-udp was merged in 3.18 so skip these tests if the kernel is too old
	minKernelRequired(t, 3, 18)

	// the fou module is usually not compiled in the kernel so we'll load it
	tearDown := setUpNetlinkTestWithKModule(t, "fou")
	defer tearDown()

	fou := Fou{
		Port:      5555,
		Family:    FAMILY_V4,
		Protocol:  4, // ipip
		EncapType: FOU_ENCAP_DIRECT,
	}

	if err := FouAdd(fou); err != nil {
		t.Fatal(err)
	}

	list, err := FouList(FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	if len(list) != 1 {
		t.Fatalf("expected 1 fou, got %d", len(list))
	}

	if list[0].Port != fou.Port {
		t.Errorf("expected port %d, got %d", fou.Port, list[0].Port)
	}

	if list[0].Family != fou.Family {
		t.Errorf("expected family %d, got %d", fou.Family, list[0].Family)
	}

	if list[0].Protocol != fou.Protocol {
		t.Errorf("expected protocol %d, got %d", fou.Protocol, list[0].Protocol)
	}

	if list[0].EncapType != fou.EncapType {
		t.Errorf("expected encaptype %d, got %d", fou.EncapType, list[0].EncapType)
	}

	if err := FouDel(Fou{Port: fou.Port, Family: fou.Family}); err != nil {
		t.Fatal(err)
	}

	list, err = FouList(FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	if len(list) != 0 {
		t.Fatalf("expected 0 fou, got %d", len(list))
	}
}
