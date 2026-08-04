package netlink

import (
	"syscall"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func routeAttr(attrType int, value []byte) syscall.NetlinkRouteAttr {
	return syscall.NetlinkRouteAttr{
		Attr:  syscall.RtAttr{Type: uint16(attrType)},
		Value: value,
	}
}

func parseSerializedAttrs(t *testing.T, attrs []*nl.RtAttr) []syscall.NetlinkRouteAttr {
	t.Helper()
	var data []byte
	for _, attr := range attrs {
		data = append(data, attr.Serialize()...)
	}
	parsed, err := nl.ParseRouteAttr(data)
	if err != nil {
		t.Fatalf("failed to parse serialized attributes: %v", err)
	}
	return parsed
}

func attrsByType(attrs []syscall.NetlinkRouteAttr) map[uint16]syscall.NetlinkRouteAttr {
	byType := make(map[uint16]syscall.NetlinkRouteAttr, len(attrs))
	for _, attr := range attrs {
		byType[attr.Attr.Type&nl.NLA_TYPE_MASK] = attr
	}
	return byType
}

func TestNewEthtoolHeader(t *testing.T) {
	header, err := newEthtoolHeader(nl.ETHTOOL_A_RINGS_HEADER, 42)
	if err != nil {
		t.Fatalf("newEthtoolHeader failed: %v", err)
	}
	if header.Type != unix.NLA_F_NESTED|nl.ETHTOOL_A_RINGS_HEADER {
		t.Fatalf("header type = %#x, want %#x", header.Type, unix.NLA_F_NESTED|nl.ETHTOOL_A_RINGS_HEADER)
	}

	outer := parseSerializedAttrs(t, []*nl.RtAttr{header})
	inner, err := nl.ParseRouteAttr(outer[0].Value)
	if err != nil {
		t.Fatalf("failed to parse ethtool header: %v", err)
	}
	if len(inner) != 1 || inner[0].Attr.Type != nl.ETHTOOL_A_HEADER_DEV_INDEX {
		t.Fatalf("header attributes = %#v, want device index", inner)
	}
	if got := native.Uint32(inner[0].Value); got != 42 {
		t.Fatalf("device index = %d, want 42", got)
	}

	if _, err := newEthtoolHeader(nl.ETHTOOL_A_RINGS_HEADER, 0); err == nil {
		t.Fatal("newEthtoolHeader accepted interface index zero")
	}
}
