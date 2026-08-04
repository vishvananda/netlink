package netlink

import (
	"reflect"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink/nl"
)

func TestParseNetDevRSS(t *testing.T) {
	indir := append(nl.Uint32Attr(3), nl.Uint32Attr(1)...)
	key := []byte{0xde, 0xad, 0xbe, 0xef}
	attrs := []syscall.NetlinkRouteAttr{
		routeAttr(nl.ETHTOOL_A_RSS_CONTEXT, nl.Uint32Attr(4)),
		routeAttr(nl.ETHTOOL_A_RSS_HFUNC, nl.Uint32Attr(uint32(NetDevRSSHashFunctionToeplitz))),
		routeAttr(nl.ETHTOOL_A_RSS_INDIR, indir),
		routeAttr(nl.ETHTOOL_A_RSS_HKEY, key),
		routeAttr(nl.ETHTOOL_A_RSS_INPUT_XFRM, nl.Uint32Attr(uint32(NetDevRSSInputTransformationSymmetricXOR))),
	}

	got, err := parseNetDevRSS(attrs, 4)
	if err != nil {
		t.Fatalf("parseNetDevRSS failed: %v", err)
	}
	want := &NetDevRSS{
		Context:             4,
		HashFunction:        NetDevRSSHashFunctionToeplitz,
		IndirectionTable:    []uint32{3, 1},
		HashKey:             []byte{0xde, 0xad, 0xbe, 0xef},
		InputTransformation: NetDevRSSInputTransformationSymmetricXOR,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RSS = %#v, want %#v", got, want)
	}

	key[0] = 0
	if got.HashKey[0] != 0xde {
		t.Fatal("parsed hash key aliases the netlink response buffer")
	}
}

func TestParseNetDevRSSRejectsMalformedIndirectionTable(t *testing.T) {
	attrs := []syscall.NetlinkRouteAttr{
		routeAttr(nl.ETHTOOL_A_RSS_INDIR, []byte{1, 2, 3}),
	}
	if _, err := parseNetDevRSS(attrs, 0); err == nil {
		t.Fatal("parseNetDevRSS accepted a malformed indirection table")
	}
}

func TestParseNetDevRSSContext(t *testing.T) {
	rss, err := parseNetDevRSS(nil, 7)
	if err != nil {
		t.Fatalf("parseNetDevRSS without a context attribute failed: %v", err)
	}
	if rss.Context != 7 {
		t.Fatalf("context = %d, want 7", rss.Context)
	}

	attrs := []syscall.NetlinkRouteAttr{
		routeAttr(nl.ETHTOOL_A_RSS_CONTEXT, nl.Uint32Attr(8)),
	}
	if _, err := parseNetDevRSS(attrs, 7); err == nil {
		t.Fatal("parseNetDevRSS accepted a mismatched context")
	}
}

func TestNewNetDevRSSSetAttrs(t *testing.T) {
	hashFunction := NetDevRSSHashFunctionToeplitz
	inputTransformation := NetDevRSSInputTransformationSymmetricORXOR
	attrs, err := newNetDevRSSSetAttrs(9, 12, NetDevRSSConfig{
		HashFunction:        &hashFunction,
		IndirectionTable:    []uint32{2, 0, 1},
		HashKey:             []byte{1, 2, 3, 4},
		InputTransformation: &inputTransformation,
	})
	if err != nil {
		t.Fatalf("newNetDevRSSSetAttrs failed: %v", err)
	}
	byType := attrsByType(parseSerializedAttrs(t, attrs))
	if len(byType) != 6 {
		t.Fatalf("encoded %d attribute types, want 6", len(byType))
	}
	if got := native.Uint32(byType[nl.ETHTOOL_A_RSS_CONTEXT].Value); got != 12 {
		t.Errorf("context = %d, want 12", got)
	}
	if got := native.Uint32(byType[nl.ETHTOOL_A_RSS_HFUNC].Value); got != uint32(hashFunction) {
		t.Errorf("hash function = %#x, want %#x", got, hashFunction)
	}
	indir := byType[nl.ETHTOOL_A_RSS_INDIR].Value
	if got := []uint32{native.Uint32(indir[0:4]), native.Uint32(indir[4:8]), native.Uint32(indir[8:12])}; !reflect.DeepEqual(got, []uint32{2, 0, 1}) {
		t.Errorf("indirection table = %v, want [2 0 1]", got)
	}
	if got := byType[nl.ETHTOOL_A_RSS_HKEY].Value; !reflect.DeepEqual(got, []byte{1, 2, 3, 4}) {
		t.Errorf("hash key = %v, want [1 2 3 4]", got)
	}
	if got := native.Uint32(byType[nl.ETHTOOL_A_RSS_INPUT_XFRM].Value); got != uint32(inputTransformation) {
		t.Errorf("input transformation = %#x, want %#x", got, inputTransformation)
	}
}

func TestNewNetDevRSSSetAttrsIndirectionTablePresence(t *testing.T) {
	tests := []struct {
		name    string
		table   []uint32
		present bool
	}{
		{name: "omitted", table: nil, present: false},
		{name: "reset", table: []uint32{}, present: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attrs, err := newNetDevRSSSetAttrs(1, 0, NetDevRSSConfig{IndirectionTable: test.table})
			if err != nil {
				t.Fatalf("newNetDevRSSSetAttrs failed: %v", err)
			}
			_, present := attrsByType(parseSerializedAttrs(t, attrs))[nl.ETHTOOL_A_RSS_INDIR]
			if present != test.present {
				t.Fatalf("indirection table present = %t, want %t", present, test.present)
			}
		})
	}
}

func TestNewNetDevRSSSetAttrsRejectsInvalidValues(t *testing.T) {
	zeroHash := NetDevRSSHashFunction(0)
	combinedHash := NetDevRSSHashFunctionToeplitz | NetDevRSSHashFunctionXOR
	largeHash := NetDevRSSHashFunction(0x100)
	unknownHash := NetDevRSSHashFunction(0x08)
	largeTransformation := NetDevRSSInputTransformation(3)
	tests := []struct {
		name   string
		config NetDevRSSConfig
	}{
		{name: "zero hash function", config: NetDevRSSConfig{HashFunction: &zeroHash}},
		{name: "combined hash functions", config: NetDevRSSConfig{HashFunction: &combinedHash}},
		{name: "large hash function", config: NetDevRSSConfig{HashFunction: &largeHash}},
		{name: "unknown hash function", config: NetDevRSSConfig{HashFunction: &unknownHash}},
		{name: "empty hash key", config: NetDevRSSConfig{HashKey: []byte{}}},
		{name: "large hash key", config: NetDevRSSConfig{HashKey: make([]byte, maxEthtoolAttrPayload+1)}},
		{name: "large indirection table", config: NetDevRSSConfig{IndirectionTable: make([]uint32, maxEthtoolAttrPayload/4+1)}},
		{name: "input transformation", config: NetDevRSSConfig{InputTransformation: &largeTransformation}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newNetDevRSSSetAttrs(1, 0, test.config); err == nil {
				t.Fatal("accepted an invalid RSS configuration")
			}
		})
	}
}

func TestNewNetDevRSSSetAttrsRejectsContextTableReset(t *testing.T) {
	_, err := newNetDevRSSSetAttrs(1, 2, NetDevRSSConfig{IndirectionTable: []uint32{}})
	if err == nil {
		t.Fatal("accepted an indirection table reset for an additional RSS context")
	}
}
