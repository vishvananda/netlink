package nl

import (
	"errors"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// scriptedReplies replaces only the kernel receive boundary; the request's
// production multipart handling and filtering run unchanged.
type scriptedReplies struct {
	replies [][]syscall.NetlinkMessage
	reads   int
	sender  uint32
}

func (s *scriptedReplies) Receive() ([]syscall.NetlinkMessage, *unix.SockaddrNetlink, error) {
	if s.reads == len(s.replies) {
		return nil, nil, unix.EAGAIN
	}
	msgs := s.replies[s.reads]
	s.reads++
	return msgs, &unix.SockaddrNetlink{Pid: s.sender}, nil
}

func reply(seq, pid uint32, typ, flags uint16) syscall.NetlinkMessage {
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Seq: seq, Pid: pid, Type: typ, Flags: flags}, Data: []byte{1, 0, 0, 0}}
}

func TestStrictReplyMismatch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		seq, pid  uint32
		sender    uint32
		field     string
		got, want uint32
	}{
		{"sequence", 8, 10, 0, "sequence", 8, 7}, {"pid", 7, 11, 0, "pid", 11, 10}, {"sender", 7, 10, 12, "sender", 12, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &NetlinkRequest{NlMsghdr: unix.NlMsghdr{Seq: 7}}
			s := &scriptedReplies{sender: tc.sender, replies: [][]syscall.NetlinkMessage{{reply(tc.seq, tc.pid, 20, unix.NLM_F_MULTI)}}}
			err := req.receiveIter(s, 20, 10, true, true, func([]byte) bool { t.Error("mismatched reply delivered"); return true })
			var mismatch *ReplyMismatchError
			if !errors.As(err, &mismatch) || mismatch.Field != tc.field || mismatch.Got != tc.got || mismatch.Want != tc.want {
				t.Fatalf("got %v, want typed %s mismatch", err, tc.field)
			}
		})
	}
}

func TestLegacyReplyMismatchSkips(t *testing.T) {
	req := &NetlinkRequest{NlMsghdr: unix.NlMsghdr{Seq: 7}}
	done := reply(7, 10, unix.NLMSG_DONE, 0)
	done.Data = nil
	s := &scriptedReplies{replies: [][]syscall.NetlinkMessage{{reply(8, 10, 20, unix.NLM_F_MULTI), reply(7, 11, 20, unix.NLM_F_MULTI), done}}}
	if err := req.receiveIter(s, 20, 10, true, false, func([]byte) bool { t.Error("mismatched reply delivered"); return true }); err != nil {
		t.Fatal(err)
	}
}

func TestStrictReplyDrainAndDumpInterrupted(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		req := &NetlinkRequest{NlMsghdr: unix.NlMsghdr{Seq: 7}, RetryInterrupted: true}
		flags := uint16(0)
		if interrupted {
			flags = unix.NLM_F_DUMP_INTR
		}
		done := reply(7, 10, unix.NLMSG_DONE, flags)
		done.Data = nil
		s := &scriptedReplies{replies: [][]syscall.NetlinkMessage{{reply(7, 10, 20, unix.NLM_F_MULTI)}, {reply(7, 10, 20, unix.NLM_F_MULTI)}, {done}}}
		calls := 0
		err := req.receiveIter(s, 20, 10, true, true, func([]byte) bool { calls++; return false })
		if calls != 1 || s.reads != 3 {
			t.Fatalf("calls=%d reads=%d; want one callback and complete drain", calls, s.reads)
		}
		if interrupted && !errors.Is(err, ErrDumpInterrupted) || !interrupted && err != nil {
			t.Fatalf("interrupted=%v: %v", interrupted, err)
		}
	}
}

func TestReceiveTruncationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lengths   []int
		truncated bool
	}{
		{"valid_prefix", []int{RECEIVE_BUFFER_SIZE, unix.NLMSG_HDRLEN}, true},
		{"inside_header", []int{RECEIVE_BUFFER_SIZE - 4, unix.NLMSG_HDRLEN}, true},
		{"inside_payload", []int{RECEIVE_BUFFER_SIZE + 16}, true},
		{"exact_buffer", []int{RECEIVE_BUFFER_SIZE}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receiver, err := getNetlinkSocket(unix.NETLINK_USERSOCK)
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			sender, err := getNetlinkSocket(unix.NETLINK_USERSOCK)
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			timeout := unix.NsecToTimeval(int64(time.Second))
			receiver.SetReceiveTimeout(&timeout)
			pid, err := receiver.GetPid()
			if err != nil {
				t.Fatal(err)
			}
			to := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: pid}
			var data []byte
			for _, length := range tc.lengths {
				msg := make([]byte, length)
				NativeEndian().PutUint32(msg, uint32(length))
				data = append(data, msg...)
			}
			if err := unix.Sendto(sender.GetFd(), data, 0, to); err != nil {
				t.Fatal(err)
			}
			next := make([]byte, unix.NLMSG_HDRLEN)
			NativeEndian().PutUint32(next, unix.NLMSG_HDRLEN)
			NativeEndian().PutUint32(next[8:], 77)
			if err := unix.Sendto(sender.GetFd(), next, 0, to); err != nil {
				t.Fatal(err)
			}
			msgs, _, err := receiver.Receive()
			if tc.truncated {
				if !errors.Is(err, ErrMessageTruncated) {
					t.Fatalf("got %v, want truncation error before parsing", err)
				}
				if len(msgs) != 0 {
					t.Fatalf("truncated datagram returned %d messages", len(msgs))
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if len(msgs) != 1 || len(msgs[0].Data) != RECEIVE_BUFFER_SIZE-unix.NLMSG_HDRLEN {
					t.Fatalf("exact buffer-sized datagram incomplete: %v", msgs)
				}
			}
			msgs, _, err = receiver.Receive()
			if err != nil {
				t.Fatal(err)
			}
			if len(msgs) != 1 || msgs[0].Header.Seq != 77 {
				t.Fatalf("next datagram not received intact: %v", msgs)
			}
		})
	}
}

func TestExecuteIterStrictCallerSocket(t *testing.T) {
	s, err := getNetlinkSocket(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	req := NewNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_DUMP)
	req.AddData(NewIfInfomsg(unix.AF_UNSPEC))
	req.Sockets = map[int]*SocketHandle{unix.NETLINK_ROUTE: {Socket: s}}
	calls := 0
	if err := req.ExecuteIterStrict(unix.NETLINK_ROUTE, unix.RTM_NEWLINK, func([]byte) bool { calls++; return false }); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("callbacks=%d", calls)
	}
	// Reuse proves callback cancellation consumed NLMSG_DONE and kept ownership.
	if err := req.ExecuteIterStrict(unix.NETLINK_ROUTE, unix.RTM_NEWLINK, func([]byte) bool { return true }); err != nil {
		t.Fatal(err)
	}
}

func TestStrictReceiveCancellation(t *testing.T) {
	for _, closeSocket := range []bool{false, true} {
		s, err := getNetlinkSocket(unix.NETLINK_ROUTE)
		if err != nil {
			t.Fatal(err)
		}
		req := NewNetlinkRequest(unix.RTM_GETLINK, 0)
		if !closeSocket {
			timeout := unix.NsecToTimeval(int64(10 * time.Millisecond))
			s.SetReceiveTimeout(&timeout)
		}
		done := make(chan error, 1)
		go func() { done <- req.receiveIter(s, 0, 0, true, true, func([]byte) bool { return true }) }()
		if closeSocket {
			// Let Receive enter the blocking poll before closing the socket.
			time.Sleep(10 * time.Millisecond)
			s.Close()
		}
		defer s.Close()
		select {
		case err := <-done:
			if err == nil {
				t.Error("cancellation returned nil")
			}
		case <-time.After(time.Second):
			s.Close()
			t.Fatal("receive did not cancel")
		}
	}
}

func TestExecuteIterStrictRejectsStaleReply(t *testing.T) {
	s, err := getNetlinkSocket(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	stale := NewNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_DUMP)
	stale.Seq = 99
	stale.AddData(NewIfInfomsg(unix.AF_UNSPEC))
	if err := s.Send(stale); err != nil {
		t.Fatal(err)
	}
	req := NewNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_DUMP)
	req.AddData(NewIfInfomsg(unix.AF_UNSPEC))
	req.Sockets = map[int]*SocketHandle{unix.NETLINK_ROUTE: {Socket: s}}
	err = req.ExecuteIterStrict(unix.NETLINK_ROUTE, unix.RTM_NEWLINK, func([]byte) bool { t.Error("stale reply delivered"); return true })
	var mismatch *ReplyMismatchError
	if !errors.As(err, &mismatch) || mismatch.Field != "sequence" || mismatch.Got != 99 || mismatch.Want != 1 {
		t.Fatalf("got %v, want stale sequence error", err)
	}
}

func TestExecuteIterStrictIgnoresRetryInterrupted(t *testing.T) {
	s, err := getNetlinkSocket(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	req := NewNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_DUMP)
	req.RetryInterrupted = true
	req.AddData(NewIfInfomsg(unix.AF_UNSPEC))
	req.Sockets = map[int]*SocketHandle{unix.NETLINK_ROUTE: {Socket: s}}
	calls := 0
	err = req.ExecuteIterStrict(unix.NETLINK_ROUTE, unix.RTM_NEWLINK, func([]byte) bool {
		calls++
		// RetryInterrupted's legacy buffering invokes callbacks after unlocking.
		if s.TryLock() {
			s.Unlock()
			t.Error("strict callback ran outside its transaction lock")
		}
		return false
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || req.Sockets[unix.NETLINK_ROUTE].Seq != 1 {
		t.Fatalf("calls=%d transactions=%d", calls, req.Sockets[unix.NETLINK_ROUTE].Seq)
	}
	if !req.RetryInterrupted {
		t.Fatal("strict execution changed caller retry setting")
	}
}
