package netlink

import (
	"reflect"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink/nl"
)

func TestParseNetDevRings(t *testing.T) {
	attrs := []syscall.NetlinkRouteAttr{
		routeAttr(nl.ETHTOOL_A_RINGS_RX_MAX, nl.Uint32Attr(1)),
		routeAttr(nl.ETHTOOL_A_RINGS_RX_MINI_MAX, nl.Uint32Attr(2)),
		routeAttr(nl.ETHTOOL_A_RINGS_RX_JUMBO_MAX, nl.Uint32Attr(3)),
		routeAttr(nl.ETHTOOL_A_RINGS_TX_MAX, nl.Uint32Attr(4)),
		routeAttr(nl.ETHTOOL_A_RINGS_RX, nl.Uint32Attr(5)),
		routeAttr(nl.ETHTOOL_A_RINGS_RX_MINI, nl.Uint32Attr(6)),
		routeAttr(nl.ETHTOOL_A_RINGS_RX_JUMBO, nl.Uint32Attr(7)),
		routeAttr(nl.ETHTOOL_A_RINGS_TX, nl.Uint32Attr(8)),
		routeAttr(nl.ETHTOOL_A_RINGS_RX_BUF_LEN, nl.Uint32Attr(9)),
		routeAttr(nl.ETHTOOL_A_RINGS_TCP_DATA_SPLIT, []byte{byte(NetDevTCPDataSplitEnabled)}),
		routeAttr(nl.ETHTOOL_A_RINGS_CQE_SIZE, nl.Uint32Attr(10)),
		routeAttr(nl.ETHTOOL_A_RINGS_TX_PUSH, []byte{1}),
		routeAttr(nl.ETHTOOL_A_RINGS_RX_PUSH, []byte{0}),
		routeAttr(nl.ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN, nl.Uint32Attr(11)),
		routeAttr(nl.ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX, nl.Uint32Attr(12)),
		routeAttr(nl.ETHTOOL_A_RINGS_HDS_THRESH, nl.Uint32Attr(13)),
		routeAttr(nl.ETHTOOL_A_RINGS_HDS_THRESH_MAX, nl.Uint32Attr(14)),
	}

	got, err := parseNetDevRings(attrs)
	if err != nil {
		t.Fatalf("parseNetDevRings failed: %v", err)
	}
	want := &NetDevRings{
		RxMax:           1,
		RxMiniMax:       2,
		RxJumboMax:      3,
		TxMax:           4,
		Rx:              5,
		RxMini:          6,
		RxJumbo:         7,
		Tx:              8,
		RxBufLen:        9,
		TCPDataSplit:    NetDevTCPDataSplitEnabled,
		CQESize:         10,
		TxPush:          true,
		RxPush:          false,
		TxPushBufLen:    11,
		TxPushBufLenMax: 12,
		HDSThreshold:    13,
		HDSThresholdMax: 14,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rings = %#v, want %#v", got, want)
	}
}

func TestParseNetDevRingsRejectsMalformedAttributes(t *testing.T) {
	tests := []struct {
		name string
		attr syscall.NetlinkRouteAttr
	}{
		{name: "u32", attr: routeAttr(nl.ETHTOOL_A_RINGS_RX, []byte{1, 2, 3})},
		{name: "u8", attr: routeAttr(nl.ETHTOOL_A_RINGS_TCP_DATA_SPLIT, []byte{1, 2})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseNetDevRings([]syscall.NetlinkRouteAttr{test.attr}); err == nil {
				t.Fatal("parseNetDevRings accepted a malformed attribute")
			}
		})
	}
}

func TestNewNetDevRingsSetAttrs(t *testing.T) {
	rx := uint32(128)
	tx := uint32(256)
	mode := NetDevTCPDataSplitEnabled
	txPush := true
	rxPush := false
	threshold := uint32(64)

	attrs, err := newNetDevRingsSetAttrs(7, NetDevRingsConfig{
		Rx:           &rx,
		Tx:           &tx,
		TCPDataSplit: &mode,
		TxPush:       &txPush,
		RxPush:       &rxPush,
		HDSThreshold: &threshold,
	})
	if err != nil {
		t.Fatalf("newNetDevRingsSetAttrs failed: %v", err)
	}
	byType := attrsByType(parseSerializedAttrs(t, attrs))
	if len(byType) != 7 {
		t.Fatalf("encoded %d attribute types, want 7", len(byType))
	}
	if got := native.Uint32(byType[nl.ETHTOOL_A_RINGS_RX].Value); got != rx {
		t.Errorf("rx = %d, want %d", got, rx)
	}
	if got := native.Uint32(byType[nl.ETHTOOL_A_RINGS_TX].Value); got != tx {
		t.Errorf("tx = %d, want %d", got, tx)
	}
	if got := byType[nl.ETHTOOL_A_RINGS_TCP_DATA_SPLIT].Value[0]; got != byte(mode) {
		t.Errorf("TCP data split = %d, want %d", got, mode)
	}
	if got := byType[nl.ETHTOOL_A_RINGS_TX_PUSH].Value[0]; got != 1 {
		t.Errorf("tx push = %d, want 1", got)
	}
	if got := byType[nl.ETHTOOL_A_RINGS_RX_PUSH].Value[0]; got != 0 {
		t.Errorf("rx push = %d, want 0", got)
	}
	if got := native.Uint32(byType[nl.ETHTOOL_A_RINGS_HDS_THRESH].Value); got != threshold {
		t.Errorf("HDS threshold = %d, want %d", got, threshold)
	}
}

func TestNewNetDevRingsSetAttrsRejectsInvalidDataSplit(t *testing.T) {
	mode := NetDevTCPDataSplit(3)
	_, err := newNetDevRingsSetAttrs(1, NetDevRingsConfig{TCPDataSplit: &mode})
	if err == nil {
		t.Fatal("accepted an invalid TCP data split value")
	}
}

func TestNewNetDevRingsSetAttrsRejectsZeroSizes(t *testing.T) {
	zero := uint32(0)
	tests := []struct {
		name   string
		config NetDevRingsConfig
	}{
		{name: "RX buffer length", config: NetDevRingsConfig{RxBufLen: &zero}},
		{name: "CQE size", config: NetDevRingsConfig{CQESize: &zero}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newNetDevRingsSetAttrs(1, test.config); err == nil {
				t.Fatal("accepted an invalid zero size")
			}
		})
	}
}
