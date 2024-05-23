package nl

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type testSerializer interface {
	serializeSafe() []byte
	Serialize() []byte
}

func testDeserializeSerialize(t *testing.T, orig []byte, safemsg testSerializer, msg testSerializer) {
	if !reflect.DeepEqual(safemsg, msg) {
		t.Fatal("Deserialization failed.\n", safemsg, "\n", msg)
	}
	safe := msg.serializeSafe()
	if !bytes.Equal(safe, orig) {
		t.Fatal("Safe serialization failed.\n", safe, "\n", orig)
	}
	b := msg.Serialize()
	if !bytes.Equal(b, safe) {
		t.Fatal("Serialization failed.\n", b, "\n", safe)
	}
}

func (msg *IfInfomsg) write(b []byte) {
	native := NativeEndian()
	b[0] = msg.Family
	// pad byte is skipped because it is not exported on linux/s390x
	native.PutUint16(b[2:4], msg.Type)
	native.PutUint32(b[4:8], uint32(msg.Index))
	native.PutUint32(b[8:12], msg.Flags)
	native.PutUint32(b[12:16], msg.Change)
}

func (msg *IfInfomsg) serializeSafe() []byte {
	length := unix.SizeofIfInfomsg
	b := make([]byte, length)
	msg.write(b)
	return b
}

func deserializeIfInfomsgSafe(b []byte) *IfInfomsg {
	var msg = IfInfomsg{}
	binary.Read(bytes.NewReader(b[0:unix.SizeofIfInfomsg]), NativeEndian(), &msg)
	return &msg
}

func TestIfInfomsgDeserializeSerialize(t *testing.T) {
	var orig = make([]byte, unix.SizeofIfInfomsg)
	rand.Read(orig)
	// zero out the pad byte
	orig[1] = 0
	safemsg := deserializeIfInfomsgSafe(orig)
	msg := DeserializeIfInfomsg(orig)
	testDeserializeSerialize(t, orig, safemsg, msg)
}

func TestIfSocketCloses(t *testing.T) {
	nlSock, err := Subscribe(unix.NETLINK_ROUTE, unix.RTNLGRP_NEIGH)
	if err != nil {
		t.Fatalf("Error on creating the socket: %v", err)
	}
	nlSock.SetReceiveTimeout(&unix.Timeval{Sec: 2, Usec: 0})
	endCh := make(chan error)
	go func(sk *NetlinkSocket, endCh chan error) {
		endCh <- nil
		for {
			_, _, err := sk.Receive()
			// Receive returned because of a timeout and the FD == -1 means that the socket got closed
			if nlSock.GetFd() == -1 {
				endCh <- err
				return
			}
		}
	}(nlSock, endCh)

	// first receive nil
	if msg := <-endCh; msg != nil {
		t.Fatalf("Expected nil instead got: %v", msg)
	}
	// this to guarantee that the receive is invoked before the close
	time.Sleep(4 * time.Second)

	// Close the socket
	nlSock.Close()

	// Expect to have an error
	msg := <-endCh
	if msg == nil {
		t.Fatalf("Expected error instead received nil")
	}
}

func (msg *CnMsgOp) write(b []byte) {
	native := NativeEndian()
	native.PutUint32(b[0:4], msg.ID.Idx)
	native.PutUint32(b[4:8], msg.ID.Val)
	native.PutUint32(b[8:12], msg.Seq)
	native.PutUint32(b[12:16], msg.Ack)
	native.PutUint16(b[16:18], msg.Length)
	native.PutUint16(b[18:20], msg.Flags)
	native.PutUint32(b[20:24], msg.Op)
}

func (msg *CnMsgOp) serializeSafe() []byte {
	length := msg.Len()
	b := make([]byte, length)
	msg.write(b)
	return b
}

func deserializeCnMsgOpSafe(b []byte) *CnMsgOp {
	var msg = CnMsgOp{}
	binary.Read(bytes.NewReader(b[0:SizeofCnMsgOp]), NativeEndian(), &msg)
	return &msg
}

func TestCnMsgOpDeserializeSerialize(t *testing.T) {
	var orig = make([]byte, SizeofCnMsgOp)
	rand.Read(orig)
	safemsg := deserializeCnMsgOpSafe(orig)
	msg := DeserializeCnMsgOp(orig)
	testDeserializeSerialize(t, orig, safemsg, msg)
}

func TestParseRouteAttrAsMap(t *testing.T) {
	attr1 := NewRtAttr(0x1, ZeroTerminated("foo"))
	attr2 := NewRtAttr(0x2, ZeroTerminated("bar"))
	raw := make([]byte, 0)
	raw = append(raw, attr1.Serialize()...)
	raw = append(raw, attr2.Serialize()...)
	attrs, err := ParseRouteAttrAsMap(raw)
	if err != nil {
		t.Errorf("failed to parse route attributes %s", err)
	}

	attr, ok := attrs[0x1]
	if !ok || BytesToString(attr.Value) != "foo" {
		t.Error("missing/incorrect \"foo\" attribute")
	}

	attr, ok = attrs[0x2]
	if !ok || BytesToString(attr.Value) != "bar" {
		t.Error("missing/incorrect \"bar\" attribute")
	}
}
