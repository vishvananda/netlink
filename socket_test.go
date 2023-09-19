//go:build linux
// +build linux

package netlink

import (
	"fmt"
	"log"
	"net"
	"os/user"
	"strconv"
	"syscall"
	"testing"
)

func TestSocketGet(t *testing.T) {
	defer setUpNetlinkTestWithLoopback(t)()

	type Addr struct {
		IP   net.IP
		Port int
	}

	getAddr := func(a net.Addr) Addr {
		var addr Addr
		switch v := a.(type) {
		case *net.UDPAddr:
			addr.IP = v.IP
			addr.Port = v.Port
		case *net.TCPAddr:
			addr.IP = v.IP
			addr.Port = v.Port
		}
		return addr
	}

	checkSocket := func(t *testing.T, local, remote net.Addr) {
		socket, err := SocketGet(local, remote)
		if err != nil {
			t.Fatal(err)
		}

		localAddr, remoteAddr := getAddr(local), getAddr(remote)

		if got, want := socket.ID.Source, localAddr.IP; !got.Equal(want) {
			t.Fatalf("local ip = %v, want %v", got, want)
		}
		if got, want := socket.ID.Destination, remoteAddr.IP; !got.Equal(want) {
			t.Fatalf("remote ip = %v, want %v", got, want)
		}
		if got, want := int(socket.ID.SourcePort), localAddr.Port; got != want {
			t.Fatalf("local port = %d, want %d", got, want)
		}
		if got, want := int(socket.ID.DestinationPort), remoteAddr.Port; got != want {
			t.Fatalf("remote port = %d, want %d", got, want)
		}
		u, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		if got, want := strconv.Itoa(int(socket.UID)), u.Uid; got != want {
			t.Fatalf("UID = %s, want %s", got, want)
		}
	}

	for _, v := range [...]string{"tcp4", "tcp6"} {
		addr, err := net.ResolveTCPAddr(v, "localhost:0")
		if err != nil {
			log.Fatal(err)
		}
		l, err := net.ListenTCP(v, addr)
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()

		conn, err := net.Dial(l.Addr().Network(), l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		checkSocket(t, conn.LocalAddr(), conn.RemoteAddr())
	}

	for _, v := range [...]string{"udp4", "udp6"} {
		addr, err := net.ResolveUDPAddr(v, "localhost:0")
		if err != nil {
			log.Fatal(err)
		}
		l, err := net.ListenUDP(v, addr)
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		conn, err := net.Dial(l.LocalAddr().Network(), l.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		checkSocket(t, conn.LocalAddr(), conn.RemoteAddr())
	}
}

func TestSocketDestroy(t *testing.T) {
	defer setUpNetlinkTestWithLoopback(t)()

	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		log.Fatal(err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	conn, err := net.Dial(l.Addr().Network(), l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	err = SocketDestroy(localAddr, remoteAddr)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSocketDiagTCPInfo(t *testing.T) {
	Family4 := uint8(syscall.AF_INET)
	Family6 := uint8(syscall.AF_INET6)
	families := []uint8{Family4, Family6}
	for _, wantFamily := range families {
		res, err := SocketDiagTCPInfo(wantFamily)
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range res {
			gotFamily := i.InetDiagMsg.Family
			if gotFamily != wantFamily {
				t.Fatalf("Socket family = %d, want %d", gotFamily, wantFamily)
			}
		}
	}
}

func TestSocketDiagUDPnfo(t *testing.T) {
	for _, want := range []uint8{syscall.AF_INET, syscall.AF_INET6} {
		result, err := SocketDiagUDPInfo(want)
		if err != nil {
			t.Fatal(err)
		}

		for _, r := range result {
			if got := r.InetDiagMsg.Family; got != want {
				t.Fatalf("protocol family = %v, want %v", got, want)
			}
		}
	}
}

func TestUnixSocketDiagInfo(t *testing.T) {
	want := syscall.AF_UNIX
	result, err := UnixSocketDiagInfo()
	if err != nil {
		t.Fatal(err)
	}

	for i, r := range result {
		fmt.Println(r.DiagMsg)
		if got := r.DiagMsg.Family; got != uint8(want) {
			t.Fatalf("%d: protocol family = %v, want %v", i, got, want)
		}
	}
}
