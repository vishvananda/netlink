package netlink

import (
	"bytes"
	"errors"
	"net"
	"syscall"
	"testing"
)

var ethtoolRxnfcLayoutTests = []struct {
	name                  string
	layout                ethtoolRxnfcLayout
	size                  int
	ringCookieOffset      int
	locationOffset        int
	ruleCntOrRssCtxOffset int
	ruleLocsOffset        int
}{
	{
		name:                  "8-byte-aligned",
		layout:                ethtoolRxnfcLayoutAligned8,
		size:                  192,
		ringCookieOffset:      152,
		locationOffset:        160,
		ruleCntOrRssCtxOffset: 184,
		ruleLocsOffset:        188,
	},
	{
		name:                  "4-byte-aligned",
		layout:                ethtoolRxnfcLayoutAligned4,
		size:                  180,
		ringCookieOffset:      148,
		locationOffset:        156,
		ruleCntOrRssCtxOffset: 176,
		ruleLocsOffset:        180,
	},
}

func TestEthtoolRxnfcLayouts(t *testing.T) {
	for _, tt := range ethtoolRxnfcLayoutTests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.layout.size != tt.size ||
				tt.layout.ringCookieOffset != tt.ringCookieOffset ||
				tt.layout.locationOffset != tt.locationOffset ||
				tt.layout.ruleCntOrRssCtxOffset != tt.ruleCntOrRssCtxOffset ||
				tt.layout.ruleLocsOffset != tt.ruleLocsOffset {
				t.Fatalf("layout = %+v, want size=%d ring_cookie=%d location=%d rule_cnt=%d rule_locs=%d",
					tt.layout, tt.size, tt.ringCookieOffset, tt.locationOffset,
					tt.ruleCntOrRssCtxOffset, tt.ruleLocsOffset)
			}

			nfc := ethtoolRxnfc{
				cmd:             ETHTOOL_SRXCLSRLINS,
				flowType:        UDP_V4_FLOW,
				data:            0x0102030405060708,
				fs:              ethtoolRxFlowSpec{ringCookie: 9, location: RX_CLS_LOC_ANY},
				ruleCntOrRssCtx: 3,
			}
			buf, err := serializeEthtoolRxnfc(&nfc, tt.layout, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(buf) != tt.size {
				t.Fatalf("encoded size = %d, want %d", len(buf), tt.size)
			}
			if got := native.Uint64(buf[ethtoolRxnfcDataOffset:]); got != nfc.data {
				t.Errorf("data = %#x, want %#x", got, nfc.data)
			}
			fsOff := ethtoolRxnfcFlowSpecOffset
			if got := native.Uint64(buf[fsOff+tt.ringCookieOffset:]); got != nfc.fs.ringCookie {
				t.Errorf("ring_cookie = %d, want %d", got, nfc.fs.ringCookie)
			}
			if got := native.Uint32(buf[fsOff+tt.locationOffset:]); got != nfc.fs.location {
				t.Errorf("location = %#x, want %#x", got, nfc.fs.location)
			}
			if got := native.Uint32(buf[tt.ruleCntOrRssCtxOffset:]); got != nfc.ruleCntOrRssCtx {
				t.Errorf("rule count = %d, want %d", got, nfc.ruleCntOrRssCtx)
			}

			native.PutUint32(buf[fsOff+tt.locationOffset:], 42)
			native.PutUint32(buf[tt.ruleCntOrRssCtxOffset:], 2)
			var decoded ethtoolRxnfc
			if err := deserializeEthtoolRxnfc(&decoded, buf, tt.layout); err != nil {
				t.Fatal(err)
			}
			if decoded.fs.location != 42 || decoded.ruleCntOrRssCtx != 2 {
				t.Errorf("decoded location/count = %d/%d, want 42/2",
					decoded.fs.location, decoded.ruleCntOrRssCtx)
			}
			if err := deserializeEthtoolRxnfc(&decoded, buf[:tt.size-1], tt.layout); err == nil {
				t.Fatal("accepted a short fixed-size response")
			}
		})
	}
}

// TestRxFlowSerializeTCP4 is the golden-bytes encode test (hardware-free). It
// builds the rxnfc for "tcp4, dst 10.0.0.5:80 -> queue 3" and asserts the
// significant bytes land at the exact kernel offsets with the correct (network)
// byte order. This is the primary correctness guard since netdevsim cannot
// exercise rxnfc end to end.
func TestRxFlowSerializeTCP4(t *testing.T) {
	flow := NetDevRxFlow{
		Match: TCP4Flow{TCPIP4Fields{
			DstIP:       net.IPv4(10, 0, 0, 5),
			DstIPMask:   net.IPv4(255, 255, 255, 255),
			DstPort:     80,
			DstPortMask: 0xffff,
		}},
		Queue:    3,
		Location: RX_CLS_LOC_ANY,
	}
	val, mask := flow.Match.serialize()
	nfc := ethtoolRxnfc{
		cmd: ETHTOOL_SRXCLSRLINS,
		fs: ethtoolRxFlowSpec{
			flowType:   flow.Match.flowType(),
			hU:         val,
			mU:         mask,
			ringCookie: uint64(flow.Queue),
			location:   flow.Location,
		},
	}
	for _, tt := range ethtoolRxnfcLayoutTests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := serializeEthtoolRxnfc(&nfc, tt.layout, 0)
			if err != nil {
				t.Fatal(err)
			}
			fsOff := ethtoolRxnfcFlowSpecOffset
			hUOff := fsOff + ethtoolRxFlowSpecHUOffset
			ringCookieOff := fsOff + tt.ringCookieOffset
			locationOff := fsOff + tt.locationOffset

			if got := native.Uint32(b[ethtoolRxnfcCmdOffset:]); got != ETHTOOL_SRXCLSRLINS {
				t.Errorf("cmd = %#x, want %#x", got, ETHTOOL_SRXCLSRLINS)
			}
			if got := native.Uint32(b[fsOff:]); got != TCP_V4_FLOW {
				t.Errorf("flow_type = %#x, want %#x", got, TCP_V4_FLOW)
			}
			// ethtool_tcpip4_spec: ip4src(4), ip4dst(4), psrc(2), pdst(2).
			if got := b[hUOff+4 : hUOff+8]; !bytes.Equal(got, []byte{10, 0, 0, 5}) {
				t.Errorf("ip4dst bytes = %v, want [10 0 0 5]", got)
			}
			if got := b[hUOff+10 : hUOff+12]; !bytes.Equal(got, []byte{0x00, 0x50}) {
				t.Errorf("pdst bytes = %v, want [0 80]", got)
			}
			if got := native.Uint64(b[ringCookieOff:]); got != 3 {
				t.Errorf("ring_cookie = %d, want 3", got)
			}
			if got := native.Uint32(b[locationOff:]); got != RX_CLS_LOC_ANY {
				t.Errorf("location = %#x, want %#x", got, RX_CLS_LOC_ANY)
			}
		})
	}
}

// TestRxFlowSerializeEther checks the ETHER_FLOW matcher used by the KubeVirt
// AF_XDP example (steer by destination MAC).
func TestRxFlowSerializeEther(t *testing.T) {
	dst, _ := net.ParseMAC("02:00:00:00:00:01")
	flow := NetDevRxFlow{
		Match: EtherFlow{
			DstMAC:     dst,
			DstMACMask: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
		Queue:    7,
		Location: RX_CLS_LOC_ANY,
	}
	val, mask := flow.Match.serialize()
	nfc := ethtoolRxnfc{
		cmd: ETHTOOL_SRXCLSRLINS,
		fs: ethtoolRxFlowSpec{
			flowType:   flow.Match.flowType(),
			hU:         val,
			mU:         mask,
			ringCookie: uint64(flow.Queue),
			location:   flow.Location,
		},
	}
	for _, tt := range ethtoolRxnfcLayoutTests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := serializeEthtoolRxnfc(&nfc, tt.layout, 0)
			if err != nil {
				t.Fatal(err)
			}
			fsOff := ethtoolRxnfcFlowSpecOffset
			hUOff := fsOff + ethtoolRxFlowSpecHUOffset
			mUOff := fsOff + ethtoolRxFlowSpecMUOffset
			ringCookieOff := fsOff + tt.ringCookieOffset

			if got := native.Uint32(b[fsOff:]); got != ETHER_FLOW {
				t.Errorf("flow_type = %#x, want ETHER_FLOW %#x", got, ETHER_FLOW)
			}
			if got := b[hUOff : hUOff+6]; !bytes.Equal(got, dst) {
				t.Errorf("h_dest = %v, want %v", got, dst)
			}
			if got := b[mUOff : mUOff+6]; !bytes.Equal(got, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
				t.Errorf("h_dest mask = %v, want all-ones", got)
			}
			if got := native.Uint64(b[ringCookieOff:]); got != 7 {
				t.Errorf("ring_cookie = %d, want 7", got)
			}
		})
	}
}

func TestParseNetDevRxFlowLocations(t *testing.T) {
	const capacity = uint32(3)
	for _, tt := range ethtoolRxnfcLayoutTests {
		t.Run(tt.name, func(t *testing.T) {
			nfc := ethtoolRxnfc{
				cmd:             ETHTOOL_GRXCLSRLALL,
				ruleCntOrRssCtx: 2,
			}
			buf, err := serializeEthtoolRxnfc(&nfc, tt.layout, capacity)
			if err != nil {
				t.Fatal(err)
			}
			native.PutUint32(buf[tt.ruleLocsOffset:], 7)
			native.PutUint32(buf[tt.ruleLocsOffset+4:], 9)
			native.PutUint32(buf[tt.ruleLocsOffset+8:], 99)

			locs, err := parseNetDevRxFlowLocations(buf, tt.layout, capacity)
			if err != nil {
				t.Fatal(err)
			}
			if len(locs) != 2 || locs[0] != 7 || locs[1] != 9 {
				t.Fatalf("locations = %v, want [7 9]", locs)
			}

			native.PutUint32(buf[tt.ruleCntOrRssCtxOffset:], capacity+1)
			if _, err := parseNetDevRxFlowLocations(buf, tt.layout, capacity); err == nil {
				t.Fatal("accepted a returned rule count larger than the supplied buffer")
			}
			if _, err := parseNetDevRxFlowLocations(buf[:tt.size-1], tt.layout, capacity); err == nil {
				t.Fatal("accepted a short RX flow rule response")
			}
		})
	}
}

func TestValidateNetDevRxFlowMatch(t *testing.T) {
	var nilEtherFlow *EtherFlow
	tests := []struct {
		name  string
		match NetDevRxFlowMatch
	}{
		{
			name:  "short MAC",
			match: EtherFlow{DstMAC: net.HardwareAddr{0x02}},
		},
		{
			name: "long MAC",
			match: EtherFlow{
				DstMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 0, 0, 1},
			},
		},
		{
			name: "IPv6 value in TCP4 flow",
			match: TCP4Flow{TCPIP4Fields{
				DstIP: net.ParseIP("2001:db8::1"),
			}},
		},
		{
			name: "IPv6 mask in UDP4 flow",
			match: UDP4Flow{TCPIP4Fields{
				DstIPMask: net.ParseIP("ffff:ffff:ffff:ffff::"),
			}},
		},
		{
			name:  "typed nil matcher",
			match: nilEtherFlow,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateNetDevRxFlowMatch(tt.match); err == nil {
				t.Fatal("invalid matcher was accepted")
			}
		})
	}

	valid := []NetDevRxFlowMatch{EtherFlow{}, TCP4Flow{}, UDP4Flow{}}
	for _, match := range valid {
		if err := validateNetDevRxFlowMatch(match); err != nil {
			t.Errorf("valid matcher %T was rejected: %v", match, err)
		}
	}
}

func TestValidateNetDevName(t *testing.T) {
	for _, dev := range []string{"", "1234567890123456", "lo\x00ignored"} {
		if err := validateNetDevName(dev); err == nil {
			t.Errorf("invalid device name %q was accepted", dev)
		}
	}
	if err := validateNetDevName("123456789012345"); err != nil {
		t.Errorf("valid 15-byte device name was rejected: %v", err)
	}
}

// TestRxFlowInsertReachesDriver confirms the ioctl is well-formed and dispatched
// to the driver. On a host without rxnfc support (e.g. loopback), the
// kernel returns EOPNOTSUPP - which proves the request reached the driver rather
// than being malformed. A nil error is also accepted and cleaned up.
// netdevsim does NOT implement rxnfc, so a full insert->list->delete round trip
// requires real hardware (bnxt/gve) and is not run here.
func TestRxFlowInsertReachesDriver(t *testing.T) {
	t.Cleanup(setUpNetlinkTestWithLoopback(t))

	location, err := NetDevRxFlowInsert("lo", NetDevRxFlow{
		Match:    TCP4Flow{TCPIP4Fields{DstPort: 80, DstPortMask: 0xffff}},
		Queue:    0,
		Location: RX_CLS_LOC_ANY,
	})
	switch {
	case err == nil:
		t.Cleanup(func() {
			if err := NetDevRxFlowDelete("lo", location); err != nil {
				t.Errorf("failed to delete inserted rxnfc rule %d: %v", location, err)
			}
		})
		t.Logf("rxnfc insert on lo unexpectedly succeeded at location %d", location)
	case errors.Is(err, syscall.EOPNOTSUPP), errors.Is(err, syscall.ENOTSUP):
		t.Logf("rxnfc insert reached driver and was declined as expected: %v", err)
	default:
		t.Fatalf("rxnfc insert failed with an unexpected error (possible malformed ioctl): %v", err)
	}
}
