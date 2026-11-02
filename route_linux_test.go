//go:build linux
// +build linux

package netlink

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// TestDeserializeRouteRejectsUndersizedAddresses verifies that deserializeRoute
// rejects route address attributes that are shorter than the address family width.
func TestDeserializeRouteRejectsUndersizedAddresses(t *testing.T) {
	tests := []struct {
		name      string
		family    int
		attrType  uint16
		attrValue []byte
		wantErr   bool
		desc      string
	}{
		// IPv4 tests
		{
			name:      "IPv4_RTA_DST_3bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_DST,
			attrValue: []byte{192, 168, 0}, // 3 bytes, should be rejected
			wantErr:   true,
			desc:      "IPv4 RTA_DST with 3 bytes should be rejected",
		},
		{
			name:      "IPv4_RTA_DST_4bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_DST,
			attrValue: []byte{192, 168, 0, 0}, // 4 bytes, valid
			wantErr:   false,
			desc:      "IPv4 RTA_DST with 4 bytes should be accepted",
		},
		{
			name:      "IPv4_RTA_DST_8bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_DST,
			attrValue: []byte{192, 168, 0, 0, 17, 18, 19, 20}, // 8 bytes, should clamp to 4
			wantErr:   false,
			desc:      "IPv4 RTA_DST with 8 bytes should be accepted and clamped",
		},
		{
			name:      "IPv4_RTA_GATEWAY_3bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_GATEWAY,
			attrValue: []byte{10, 0, 0}, // 3 bytes, should be rejected
			wantErr:   true,
			desc:      "IPv4 RTA_GATEWAY with 3 bytes should be rejected",
		},
		{
			name:      "IPv4_RTA_GATEWAY_4bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_GATEWAY,
			attrValue: []byte{10, 0, 0, 1}, // 4 bytes, valid
			wantErr:   false,
			desc:      "IPv4 RTA_GATEWAY with 4 bytes should be accepted",
		},
		{
			name:      "IPv4_RTA_GATEWAY_8bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_GATEWAY,
			attrValue: []byte{10, 0, 0, 1, 21, 22, 23, 24}, // 8 bytes, should clamp to 4
			wantErr:   false,
			desc:      "IPv4 RTA_GATEWAY with 8 bytes should be accepted and clamped",
		},
		{
			name:      "IPv4_RTA_PREFSRC_3bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_PREFSRC,
			attrValue: []byte{172, 16, 0}, // 3 bytes, should be rejected
			wantErr:   true,
			desc:      "IPv4 RTA_PREFSRC with 3 bytes should be rejected",
		},
		{
			name:      "IPv4_RTA_PREFSRC_4bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_PREFSRC,
			attrValue: []byte{172, 16, 0, 1}, // 4 bytes, valid
			wantErr:   false,
			desc:      "IPv4 RTA_PREFSRC with 4 bytes should be accepted",
		},
		{
			name:      "IPv4_RTA_PREFSRC_8bytes",
			family:    unix.AF_INET,
			attrType:  unix.RTA_PREFSRC,
			attrValue: []byte{172, 16, 0, 1, 25, 26, 27, 28}, // 8 bytes, should clamp to 4
			wantErr:   false,
			desc:      "IPv4 RTA_PREFSRC with 8 bytes should be accepted and clamped",
		},

		// IPv6 tests
		{
			name:      "IPv6_RTA_DST_15bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_DST,
			attrValue: make([]byte, 15), // 15 bytes, should be rejected
			wantErr:   true,
			desc:      "IPv6 RTA_DST with 15 bytes should be rejected",
		},
		{
			name:      "IPv6_RTA_DST_16bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_DST,
			attrValue: make([]byte, 16), // 16 bytes, valid
			wantErr:   false,
			desc:      "IPv6 RTA_DST with 16 bytes should be accepted",
		},
		{
			name:      "IPv6_RTA_DST_32bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_DST,
			attrValue: append([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, bytes.Repeat([]byte{0x01}, 16)...), // 32 bytes, should clamp to 16
			wantErr:   false,
			desc:      "IPv6 RTA_DST with 32 bytes should be accepted and clamped",
		},
		{
			name:      "IPv6_RTA_GATEWAY_15bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_GATEWAY,
			attrValue: make([]byte, 15), // 15 bytes, should be rejected
			wantErr:   true,
			desc:      "IPv6 RTA_GATEWAY with 15 bytes should be rejected",
		},
		{
			name:      "IPv6_RTA_GATEWAY_16bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_GATEWAY,
			attrValue: make([]byte, 16), // 16 bytes, valid
			wantErr:   false,
			desc:      "IPv6 RTA_GATEWAY with 16 bytes should be accepted",
		},
		{
			name:      "IPv6_RTA_GATEWAY_32bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_GATEWAY,
			attrValue: append([]byte{0x20, 0x01, 0x0d, 0xb9, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}, bytes.Repeat([]byte{0x02}, 16)...), // 32 bytes, should clamp to 16
			wantErr:   false,
			desc:      "IPv6 RTA_GATEWAY with 32 bytes should be accepted and clamped",
		},
		{
			name:      "IPv6_RTA_PREFSRC_15bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_PREFSRC,
			attrValue: make([]byte, 15), // 15 bytes, should be rejected
			wantErr:   true,
			desc:      "IPv6 RTA_PREFSRC with 15 bytes should be rejected",
		},
		{
			name:      "IPv6_RTA_PREFSRC_16bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_PREFSRC,
			attrValue: make([]byte, 16), // 16 bytes, valid
			wantErr:   false,
			desc:      "IPv6 RTA_PREFSRC with 16 bytes should be accepted",
		},
		{
			name:      "IPv6_RTA_PREFSRC_32bytes",
			family:    unix.AF_INET6,
			attrType:  unix.RTA_PREFSRC,
			attrValue: append([]byte{0x20, 0x01, 0x0d, 0xba, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35}, bytes.Repeat([]byte{0x03}, 16)...), // 32 bytes, should clamp to 16
			wantErr:   false,
			desc:      "IPv6 RTA_PREFSRC with 32 bytes should be accepted and clamped",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Construct minimal RtMsg with the test attribute
			msg := buildRtMsg(tt.family, 16, tt.attrType, tt.attrValue)
			route, err := deserializeRoute(msg)

			if (err != nil) != tt.wantErr {
				t.Errorf("%s: got err=%v, wantErr=%v", tt.desc, err, tt.wantErr)
				return
			}

			// For valid cases, verify the address was deserialized correctly
			if !tt.wantErr {
				switch tt.attrType {
				case unix.RTA_DST:
					if route.Dst == nil {
						t.Errorf("%s: expected non-nil Dst, got nil", tt.desc)
						return
					}
					// Verify mask width is correct for address family
					_, bits := route.Dst.Mask.Size()
					expectedBits := 32
					if tt.family == unix.AF_INET6 {
						expectedBits = 128
					}
					if bits != expectedBits {
						t.Errorf("%s: mask width %d != %d", tt.desc, bits, expectedBits)
					}
					// Verify IP length matches family
					expectedLen := 4
					if tt.family == unix.AF_INET6 {
						expectedLen = 16
					}
					expected := tt.attrValue[:expectedLen]
					if !bytes.Equal(route.Dst.IP, expected) {
						t.Errorf("%s: IP = %v, want %v", tt.desc, route.Dst.IP, expected)
					}

				case unix.RTA_GATEWAY:
					if route.Gw == nil {
						t.Errorf("%s: expected non-nil Gw, got nil", tt.desc)
						return
					}
					// Verify address length matches family
					expectedLen := 4
					if tt.family == unix.AF_INET6 {
						expectedLen = 16
					}
					expected := tt.attrValue[:expectedLen]
					if !bytes.Equal(route.Gw, expected) {
						t.Errorf("%s: Gw = %v, want %v", tt.desc, route.Gw, expected)
					}

				case unix.RTA_PREFSRC:
					if route.Src == nil {
						t.Errorf("%s: expected non-nil Src, got nil", tt.desc)
						return
					}
					// Verify address length matches family
					expectedLen := 4
					if tt.family == unix.AF_INET6 {
						expectedLen = 16
					}
					expected := tt.attrValue[:expectedLen]
					if !bytes.Equal(route.Src, expected) {
						t.Errorf("%s: Src = %v, want %v", tt.desc, route.Src, expected)
					}
				}
			}
		})
	}
}

// TestDeserializeRouteBufferAliasingFix verifies the original buffer aliasing
// vulnerability is fixed: oversized RTA_DST attributes no longer propagate
// adjacent buffer data into the route destination.
func TestDeserializeRouteBufferAliasingFix(t *testing.T) {
	dstPayload := []byte{192, 168, 0, 0, 17, 18, 19, 20}
	gwPayload := []byte{10, 0, 0, 1, 21, 22, 23, 24}
	srcPayload := []byte{172, 16, 0, 1, 25, 26, 27, 28}
	msg := buildRtMsgWithAttrs(unix.AF_INET, 16,
		nl.NewRtAttr(unix.RTA_DST, dstPayload),
		nl.NewRtAttr(unix.RTA_GATEWAY, gwPayload),
		nl.NewRtAttr(unix.RTA_PREFSRC, srcPayload),
	)
	route, err := deserializeRoute(msg)

	if err != nil {
		t.Fatalf("deserializeRoute failed: %v", err)
	}

	if !bytes.Equal(route.Dst.IP, dstPayload[:4]) || !bytes.Equal(route.Gw, gwPayload[:4]) || !bytes.Equal(route.Src, srcPayload[:4]) {
		t.Fatalf("decoded addresses do not preserve oversized prefixes: dst=%v gw=%v src=%v", route.Dst.IP, route.Gw, route.Src)
	}

	overwriteRouteAttr(msg, unix.RTA_DST, bytes.Repeat([]byte{0xa1}, len(dstPayload)))
	overwriteRouteAttr(msg, unix.RTA_GATEWAY, bytes.Repeat([]byte{0xb2}, len(gwPayload)))
	overwriteRouteAttr(msg, unix.RTA_PREFSRC, bytes.Repeat([]byte{0xc3}, len(srcPayload)))
	if !bytes.Equal(route.Dst.IP, dstPayload[:4]) || !bytes.Equal(route.Gw, gwPayload[:4]) || !bytes.Equal(route.Src, srcPayload[:4]) {
		t.Fatalf("decoded addresses alias the netlink message: dst=%v gw=%v src=%v", route.Dst.IP, route.Gw, route.Src)
	}
}

func TestDeserializeSpecialRouteTypesWithEmptyDestination(t *testing.T) {
	tests := []struct {
		name      string
		routeType int
	}{
		{name: "unreachable", routeType: unix.RTN_UNREACHABLE},
		{name: "blackhole", routeType: unix.RTN_BLACKHOLE},
		{name: "prohibit", routeType: unix.RTN_PROHIBIT},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := buildRtMsgWithType(unix.AF_INET, 0, tt.routeType, unix.RTA_DST, nil)
			route, err := deserializeRoute(msg)
			if err != nil {
				t.Fatalf("deserializeRoute failed: %v", err)
			}
			if route.Type != tt.routeType {
				t.Fatalf("route type = %d, want %d", route.Type, tt.routeType)
			}
		})
	}
}

// buildRtMsg constructs a minimal netlink RtMsg with a single attribute for
// testing using the canonical serialized layout used throughout the project.
func buildRtMsg(family int, dstLen uint8, attrType uint16, attrValue []byte) []byte {
	return buildRtMsgWithType(family, dstLen, 0, attrType, attrValue)
}

func buildRtMsgWithType(family int, dstLen uint8, routeType int, attrType uint16, attrValue []byte) []byte {
	return buildRtMsgWithAttrsAndType(family, dstLen, routeType, nl.NewRtAttr(int(attrType), attrValue))
}

func buildRtMsgWithAttrs(family int, dstLen uint8, attrs ...*nl.RtAttr) []byte {
	return buildRtMsgWithAttrsAndType(family, dstLen, 0, attrs...)
}

func buildRtMsgWithAttrsAndType(family int, dstLen uint8, routeType int, attrs ...*nl.RtAttr) []byte {
	rtMsg := nl.NewRtMsg()
	rtMsg.Family = uint8(family)
	rtMsg.Dst_len = dstLen
	rtMsg.Src_len = 0
	rtMsg.Tos = 0
	rtMsg.Table = 0
	rtMsg.Protocol = 0
	rtMsg.Scope = 0
	rtMsg.Type = uint8(routeType)
	rtMsg.Flags = 0

	msg := rtMsg.Serialize()
	for _, attr := range attrs {
		msg = append(msg, attr.Serialize()...)
	}
	return msg
}

func overwriteRouteAttr(msg []byte, attrType uint16, value []byte) {
	offset := unix.SizeofRtMsg
	for offset+4 <= len(msg) {
		length := int(binary.LittleEndian.Uint16(msg[offset:]))
		typ := binary.LittleEndian.Uint16(msg[offset+2:])
		if length < 4 || offset+length > len(msg) {
			return
		}
		if typ == attrType {
			copy(msg[offset+4:offset+length], value)
			return
		}
		offset += (length + 3) &^ 3
	}
}
