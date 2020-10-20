package nl

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func (msg *BridgeVlanInfo) write(b []byte) {
	nativeEndian.PutUint16(b[0:2], msg.Flags)
	nativeEndian.PutUint16(b[2:4], msg.Vid)
}

func (msg *BridgeVlanInfo) serializeSafe() []byte {
	length := SizeofBridgeVlanInfo
	b := make([]byte, length)
	msg.write(b)
	return b
}

func deserializeBridgeVlanInfoSafe(b []byte) *BridgeVlanInfo {
	var msg = BridgeVlanInfo{}
	binary.Read(bytes.NewReader(b[0:SizeofBridgeVlanInfo]), nativeEndian, &msg)
	return &msg
}

func TestBridgeVlanInfoDeserializeSerialize(t *testing.T) {
	var orig = make([]byte, SizeofBridgeVlanInfo)
	rand.Read(orig)
	safemsg := deserializeBridgeVlanInfoSafe(orig)
	msg := DeserializeBridgeVlanInfo(orig)
	testDeserializeSerialize(t, orig, safemsg, msg)
}
