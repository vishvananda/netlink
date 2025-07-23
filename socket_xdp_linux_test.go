//go:build linux
// +build linux

package netlink

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSocketXDPGetInfo(t *testing.T) {
	xdpsockfd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("creating AF_XDP socket not permitted")
		}
		t.Fatal(err)
	}
	defer unix.Close(xdpsockfd)

	wantFamily := unix.AF_XDP

	var xdpsockstat unix.Stat_t
	err = unix.Fstat(xdpsockfd, &xdpsockstat)
	if err != nil {
		t.Fatal(err)
	}
	wantIno := xdpsockstat.Ino

	result, err := SocketXDPGetInfo(uint32(wantIno), SOCK_ANY_COOKIE)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("kernel lacks support for AF_XDP socket diagnosis")
		}
		t.Fatal(err)
	}

	if got := result.XDPDiagMsg.Family; got != uint8(wantFamily) {
		t.Fatalf("protocol family = %v, want %v", got, wantFamily)
	}
	if got := result.XDPDiagMsg.Ino; got != uint32(wantIno) {
		t.Fatalf("protocol ino = %v, want %v", got, wantIno)
	}
	if result.XDPInfo == nil {
		t.Fatalf("want non-nil XDPInfo, got nil")
	}
	if got := result.XDPInfo.Ifindex; got != 0 {
		t.Fatalf("ifindex = %v, want 0", got)
	}
}
