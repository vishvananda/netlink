package nl

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

/* TcMsg */
func (msg *TcMsg) write(b []byte) {
	native := NativeEndian()
	b[0] = msg.Family
	copy(b[1:4], msg.Pad[:])
	native.PutUint32(b[4:8], uint32(msg.Ifindex))
	native.PutUint32(b[8:12], msg.Handle)
	native.PutUint32(b[12:16], msg.Parent)
	native.PutUint32(b[16:20], msg.Info)
}

func (msg *TcMsg) serializeSafe() []byte {
	length := SizeofTcMsg
	b := make([]byte, length)
	msg.write(b)
	return b
}

func deserializeTcMsgSafe(b []byte) *TcMsg {
	var msg = TcMsg{}
	binary.Read(bytes.NewReader(b[0:SizeofTcMsg]), NativeEndian(), &msg)
	return &msg
}

func TestTcMsgDeserializeSerialize(t *testing.T) {
	var orig = make([]byte, SizeofTcMsg)
	rand.Read(orig)
	safemsg := deserializeTcMsgSafe(orig)
	msg := DeserializeTcMsg(orig)
	testDeserializeSerialize(t, orig, safemsg, msg)
}

/* TcActionMsg */
func (msg *TcActionMsg) write(b []byte) {
	b[0] = msg.Family
	copy(b[1:4], msg.Pad[:])
}

func (msg *TcActionMsg) serializeSafe() []byte {
	length := SizeofTcActionMsg
	b := make([]byte, length)
	msg.write(b)
	return b
}

func deserializeTcActionMsgSafe(b []byte) *TcActionMsg {
	var msg = TcActionMsg{}
	binary.Read(bytes.NewReader(b[0:SizeofTcActionMsg]), NativeEndian(), &msg)
	return &msg
}

func TestTcActionMsgDeserializeSerialize(t *testing.T) {
	var orig = make([]byte, SizeofTcActionMsg)
	rand.Read(orig)
	safemsg := deserializeTcActionMsgSafe(orig)
	msg := DeserializeTcActionMsg(orig)
	testDeserializeSerialize(t, orig, safemsg, msg)
}

/* TcRateSpec */
func (msg *TcRateSpec) write(b []byte) {
	native := NativeEndian()
	b[0] = msg.CellLog
	b[1] = msg.Linklayer
	native.PutUint16(b[2:4], msg.Overhead)
	native.PutUint16(b[4:6], uint16(msg.CellAlign))
	native.PutUint16(b[6:8], msg.Mpu)
	native.PutUint32(b[8:12], msg.Rate)
}

func (msg *TcRateSpec) serializeSafe() []byte {
	length := SizeofTcRateSpec
	b := make([]byte, length)
	msg.write(b)
	return b
}

func deserializeTcRateSpecSafe(b []byte) *TcRateSpec {
	var msg = TcRateSpec{}
	binary.Read(bytes.NewReader(b[0:SizeofTcRateSpec]), NativeEndian(), &msg)
	return &msg
}

func TestTcRateSpecDeserializeSerialize(t *testing.T) {
	var orig = make([]byte, SizeofTcRateSpec)
	rand.Read(orig)
	safemsg := deserializeTcRateSpecSafe(orig)
	msg := DeserializeTcRateSpec(orig)
	testDeserializeSerialize(t, orig, safemsg, msg)
}

/* TcTbfQopt */
func (msg *TcTbfQopt) write(b []byte) {
	native := NativeEndian()
	msg.Rate.write(b[0:SizeofTcRateSpec])
	start := SizeofTcRateSpec
	msg.Peakrate.write(b[start : start+SizeofTcRateSpec])
	start += SizeofTcRateSpec
	native.PutUint32(b[start:start+4], msg.Limit)
	start += 4
	native.PutUint32(b[start:start+4], msg.Buffer)
	start += 4
	native.PutUint32(b[start:start+4], msg.Mtu)
}

func (msg *TcTbfQopt) serializeSafe() []byte {
	length := SizeofTcTbfQopt
	b := make([]byte, length)
	msg.write(b)
	return b
}

func deserializeTcTbfQoptSafe(b []byte) *TcTbfQopt {
	var msg = TcTbfQopt{}
	binary.Read(bytes.NewReader(b[0:SizeofTcTbfQopt]), NativeEndian(), &msg)
	return &msg
}

func TestTcTbfQoptDeserializeSerialize(t *testing.T) {
	var orig = make([]byte, SizeofTcTbfQopt)
	rand.Read(orig)
	safemsg := deserializeTcTbfQoptSafe(orig)
	msg := DeserializeTcTbfQopt(orig)
	testDeserializeSerialize(t, orig, safemsg, msg)
}

/* TcHtbCopt */
func (msg *TcHtbCopt) write(b []byte) {
	native := NativeEndian()
	msg.Rate.write(b[0:SizeofTcRateSpec])
	start := SizeofTcRateSpec
	msg.Ceil.write(b[start : start+SizeofTcRateSpec])
	start += SizeofTcRateSpec
	native.PutUint32(b[start:start+4], msg.Buffer)
	start += 4
	native.PutUint32(b[start:start+4], msg.Cbuffer)
	start += 4
	native.PutUint32(b[start:start+4], msg.Quantum)
	start += 4
	native.PutUint32(b[start:start+4], msg.Level)
	start += 4
	native.PutUint32(b[start:start+4], msg.Prio)
}

func (msg *TcHtbCopt) serializeSafe() []byte {
	length := SizeofTcHtbCopt
	b := make([]byte, length)
	msg.write(b)
	return b
}

func deserializeTcHtbCoptSafe(b []byte) *TcHtbCopt {
	var msg = TcHtbCopt{}
	binary.Read(bytes.NewReader(b[0:SizeofTcHtbCopt]), NativeEndian(), &msg)
	return &msg
}

func TestTcHtbCoptDeserializeSerialize(t *testing.T) {
	var orig = make([]byte, SizeofTcHtbCopt)
	rand.Read(orig)
	safemsg := deserializeTcHtbCoptSafe(orig)
	msg := DeserializeTcHtbCopt(orig)
	testDeserializeSerialize(t, orig, safemsg, msg)
}

func TestParsePeditEthKeys(t *testing.T) {
	tests := []struct {
		name   string
		srcMAC net.HardwareAddr
		dstMAC net.HardwareAddr
	}{
		{
			name:   "Parse source MAC",
			srcMAC: net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		},
		{
			name:   "Parse destination MAC",
			dstMAC: net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		},
		{
			name:   "Parse both MACs",
			srcMAC: net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			dstMAC: net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pedit := &TcPedit{}
			if tt.srcMAC != nil {
				pedit.SetEthSrc(tt.srcMAC)
			}
			if tt.dstMAC != nil {
				pedit.SetEthDst(tt.dstMAC)
			}

			srcMAC, dstMAC := ParsePeditEthKeys(pedit.Keys)

			if !bytes.Equal(srcMAC, tt.srcMAC) {
				t.Errorf("ParsePeditEthKeys() srcMAC = %v, want %v", srcMAC, tt.srcMAC)
			}
			if !bytes.Equal(dstMAC, tt.dstMAC) {
				t.Errorf("ParsePeditEthKeys() dstMAC = %v, want %v", dstMAC, tt.dstMAC)
			}
		})
	}
}

func TestParsePeditIP4Keys(t *testing.T) {
	tests := []struct {
		name  string
		srcIP net.IP
		dstIP net.IP
	}{
		{
			name:  "Parse source IPv4",
			srcIP: net.ParseIP("192.168.1.1"),
		},
		{
			name:  "Parse destination IPv4",
			dstIP: net.ParseIP("10.0.0.1"),
		},
		{
			name:  "Parse both IPv4 addresses",
			srcIP: net.ParseIP("192.168.1.1"),
			dstIP: net.ParseIP("10.0.0.1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pedit := &TcPedit{}
			if tt.srcIP != nil {
				pedit.SetIPv4Src(tt.srcIP)
			}
			if tt.dstIP != nil {
				pedit.SetIPv4Dst(tt.dstIP)
			}

			srcIP, dstIP := ParsePeditIP4Keys(pedit.Keys)

			if !srcIP.Equal(tt.srcIP) {
				t.Errorf("ParsePeditIP4Keys() srcIP = %v, want %v", srcIP, tt.srcIP)
			}
			if !dstIP.Equal(tt.dstIP) {
				t.Errorf("ParsePeditIP4Keys() dstIP = %v, want %v", dstIP, tt.dstIP)
			}
		})
	}
}

func TestParsePeditIP6Keys(t *testing.T) {
	tests := []struct {
		name  string
		srcIP net.IP
		dstIP net.IP
	}{
		{
			name:  "Parse source IPv6",
			srcIP: net.ParseIP("2001:db8::1"),
		},
		{
			name:  "Parse destination IPv6",
			dstIP: net.ParseIP("fe80::1"),
		},
		{
			name:  "Parse both IPv6 addresses",
			srcIP: net.ParseIP("2001:db8::1"),
			dstIP: net.ParseIP("fe80::1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pedit := &TcPedit{}
			if tt.srcIP != nil {
				pedit.SetIPv6Src(tt.srcIP)
			}
			if tt.dstIP != nil {
				pedit.SetIPv6Dst(tt.dstIP)
			}

			srcIP, dstIP := ParsePeditIP6Keys(pedit.Keys)

			if !srcIP.Equal(tt.srcIP) {
				t.Errorf("ParsePeditIP6Keys() srcIP = %v, want %v", srcIP, tt.srcIP)
			}
			if !dstIP.Equal(tt.dstIP) {
				t.Errorf("ParsePeditIP6Keys() dstIP = %v, want %v", dstIP, tt.dstIP)
			}
		})
	}
}

func TestParsePeditL4Keys(t *testing.T) {
	tests := []struct {
		name    string
		srcPort uint16
		dstPort uint16
		proto   uint8
	}{
		{
			name:    "Parse TCP source port",
			srcPort: 8080,
			proto:   unix.IPPROTO_TCP,
		},
		{
			name:    "Parse TCP destination port",
			dstPort: 80,
			proto:   unix.IPPROTO_TCP,
		},
		{
			name:    "Parse both TCP ports",
			srcPort: 8080,
			dstPort: 80,
			proto:   unix.IPPROTO_TCP,
		},
		{
			name:    "Parse UDP source port",
			srcPort: 53,
			proto:   unix.IPPROTO_UDP,
		},
		{
			name:    "Parse UDP destination port",
			dstPort: 5353,
			proto:   unix.IPPROTO_UDP,
		},
		{
			name:    "Parse both UDP ports",
			srcPort: 53,
			dstPort: 5353,
			proto:   unix.IPPROTO_UDP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pedit := &TcPedit{}
			if tt.srcPort != 0 {
				pedit.SetSrcPort(tt.srcPort, tt.proto)
			}
			if tt.dstPort != 0 {
				pedit.SetDstPort(tt.dstPort, tt.proto)
			}

			srcPort, dstPort := ParsePeditL4Keys(pedit.Keys)

			if srcPort != tt.srcPort {
				t.Errorf("ParsePeditL4Keys() srcPort = %v, want %v", srcPort, tt.srcPort)
			}
			if dstPort != tt.dstPort {
				t.Errorf("ParsePeditL4Keys() dstPort = %v, want %v", dstPort, tt.dstPort)
			}
		})
	}
}
