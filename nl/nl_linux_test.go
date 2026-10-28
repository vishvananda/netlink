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

// TestIfSocketCloses checks that closing a socket unblocks a pending Receive with EAGAIN.
func TestIfSocketCloses(t *testing.T) {
	nlSock, err := Subscribe(unix.NETLINK_ROUTE, unix.RTNLGRP_NEIGH)
	if err != nil {
		t.Fatalf("Error on creating the socket: %v", err)
	}
	endCh := make(chan error)
	go func(sk *NetlinkSocket, endCh chan error) {
		endCh <- nil
		for {
			_, _, err := sk.Receive()
			if err == unix.EAGAIN {
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

// TestNewNetlinkSocketFromFd checks that a wrapped fd is left unbound until the first send,
// that a dump over it completes, and that a non-netlink fd is rejected and left open.
func TestNewNetlinkSocketFromFd(t *testing.T) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("Error creating the socket: %v", err)
	}
	nlSock, err := NewNetlinkSocketFromFd(fd)
	if err != nil {
		unix.Close(fd)
		t.Fatalf("Error wrapping the socket: %v", err)
	}
	defer nlSock.Close()

	// Nothing has bound the socket, so it has no port id yet.
	pid, err := nlSock.GetPid()
	if err != nil {
		t.Fatalf("GetPid failed: %v", err)
	}
	if pid != 0 {
		t.Fatalf("Expected an unbound socket, got port id %d", pid)
	}

	// A dump over the unbound socket must still complete. Every host has at least the
	// loopback addresses.
	req := NewNetlinkRequest(unix.RTM_GETADDR, unix.NLM_F_DUMP)
	req.AddData(NewIfAddrmsg(unix.AF_UNSPEC))
	req.Sockets = map[int]*SocketHandle{unix.NETLINK_ROUTE: {Socket: nlSock}}
	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWADDR)
	if err != nil {
		t.Fatalf("RTM_GETADDR dump failed: %v", err)
	}
	if len(msgs) == 0 {
		t.Fatal("RTM_GETADDR dump returned no addresses")
	}

	// The kernel autobinds on the first send.
	pid, err = nlSock.GetPid()
	if err != nil {
		t.Fatalf("GetPid failed: %v", err)
	}
	if pid == 0 {
		t.Fatal("Expected the kernel to assign a port id on send")
	}

	// Anything that is not a netlink socket is rejected and left open for the caller.
	ufd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("Error creating the udp socket: %v", err)
	}
	defer unix.Close(ufd)
	if _, err := NewNetlinkSocketFromFd(ufd); err == nil {
		t.Fatal("Expected a non-netlink fd to be rejected")
	}
}

// TestReceiveTimeout checks that Receive returns EAGAIN once the receive timeout expires.
func TestReceiveTimeout(t *testing.T) {
	nlSock, err := getNetlinkSocket(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("Error creating the socket: %v", err)
	}
	// Even if the test fails because the timeout doesn't work, closing the
	// socket at the end of the test should result in an EAGAIN (as long as
	// TestIfSocketCloses completed, otherwise this test will leak the
	// goroutines running the Receive).
	defer nlSock.Close()
	const failAfter = time.Second

	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{
			name:    "1us timeout", // The smallest value accepted by Handle.SetSocketTimeout
			timeout: time.Microsecond,
		},
		{
			name:    "100ms timeout",
			timeout: 100 * time.Millisecond,
		},
		{
			name:    "500ms timeout",
			timeout: 500 * time.Millisecond,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			timeout := unix.NsecToTimeval(int64(tc.timeout))
			nlSock.SetReceiveTimeout(&timeout)

			doneC := make(chan time.Duration)
			errC := make(chan error)
			go func() {
				start := time.Now()
				_, _, err := nlSock.Receive()
				dur := time.Since(start)
				if err != unix.EAGAIN {
					errC <- err
					return
				}
				doneC <- dur
			}()

			failTimerC := time.After(failAfter)
			select {
			case dur := <-doneC:
				if dur < tc.timeout || dur > (tc.timeout+(100*time.Millisecond)) {
					t.Fatalf("Expected timeout %v got %v", tc.timeout, dur)
				}
			case err := <-errC:
				t.Fatalf("Expected EAGAIN, but got: %v", err)
			case <-failTimerC:
				t.Fatalf("No timeout received")
			}
		})
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
