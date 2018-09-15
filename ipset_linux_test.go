package netlink

import (
	"bytes"
	"io/ioutil"
	"net"
	"testing"

	"github.com/vishvananda/netlink/nl"
)

func TestParseIpsetProtocolResult(t *testing.T) {
	msgBytes, err := ioutil.ReadFile("testdata/ipset_protocol_result")
	if err != nil {
		t.Fatalf("reading test fixture failed: %v", err)
	}

	msg := ipsetUnserialize([][]byte{msgBytes})
	if msg.Protocol != 6 {
		t.Errorf("expected msg.Protocol to equal 6, got %d", msg.Protocol)
	}
}

func TestParseIpsetListResult(t *testing.T) {
	msgBytes, err := ioutil.ReadFile("testdata/ipset_list_result")
	if err != nil {
		t.Fatalf("reading test fixture failed: %v", err)
	}

	msg := ipsetUnserialize([][]byte{msgBytes})
	if msg.SetName != "clients" {
		t.Errorf(`expected SetName to equal "clients", got %q`, msg.SetName)
	}
	if msg.TypeName != "hash:mac" {
		t.Errorf(`expected TypeName to equal "hash:mac", got %q`, msg.TypeName)
	}
	if msg.Protocol != 6 {
		t.Errorf("expected Protocol to equal 6, got %d", msg.Protocol)
	}
	if msg.References != 0 {
		t.Errorf("expected References to equal 0, got %d", msg.References)
	}
	if msg.NumEntries != 2 {
		t.Errorf("expected NumEntries to equal 2, got %d", msg.NumEntries)
	}
	if msg.HashSize != 1024 {
		t.Errorf("expected HashSize to equal 1024, got %d", msg.HashSize)
	}
	if *msg.Timeout != 3600 {
		t.Errorf("expected Timeout to equal 3600, got %d", *msg.Timeout)
	}
	if msg.MaxElements != 65536 {
		t.Errorf("expected MaxElements to equal 65536, got %d", msg.MaxElements)
	}
	if msg.CadtFlags != nl.IPSET_FLAG_WITH_COMMENT|nl.IPSET_FLAG_WITH_COUNTERS {
		t.Error("expected CadtFlags to be IPSET_FLAG_WITH_COMMENT and IPSET_FLAG_WITH_COUNTERS")
	}
	if len(msg.Entries) != 2 {
		t.Fatalf("expected 2 Entries, got %d", len(msg.Entries))
	}

	// first entry
	ent := msg.Entries[0]
	if int(*ent.Timeout) != 3577 {
		t.Errorf("expected Timeout for first entry to equal 3577, got %d", *ent.Timeout)
	}
	if int(*ent.Bytes) != 4121 {
		t.Errorf("expected Bytes for first entry to equal 4121, got %d", *ent.Bytes)
	}
	if int(*ent.Packets) != 42 {
		t.Errorf("expected Packets for first entry to equal 42, got %d", *ent.Packets)
	}
	if ent.Comment != "foo bar" {
		t.Errorf("unexpected Comment for first entry: %q", ent.Comment)
	}
	expectedMAC := net.HardwareAddr{0xde, 0xad, 0x0, 0x0, 0xbe, 0xef}
	if !bytes.Equal(ent.MAC, expectedMAC) {
		t.Errorf("expected MAC for first entry to be %s, got %s", expectedMAC.String(), ent.MAC.String())
	}

	// second entry
	ent = msg.Entries[1]
	expectedMAC = net.HardwareAddr{0x1, 0x2, 0x3, 0x0, 0x1, 0x2}
	if !bytes.Equal(ent.MAC, expectedMAC) {
		t.Errorf("expected MAC for second entry to be %s, got %s", expectedMAC.String(), ent.MAC.String())
	}
}
