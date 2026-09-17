package netlink

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// TestSetGetSocketTimeout checks that a timeout set on the package-level handle is read back unchanged.
func TestSetGetSocketTimeout(t *testing.T) {
	timeout := 10 * time.Second
	if err := SetSocketTimeout(10 * time.Second); err != nil {
		t.Fatalf("Set socket timeout for default handle failed: %v", err)
	}

	if val := GetSocketTimeout(); val != timeout {
		t.Fatalf("Unexpected socket timeout value: got=%v, expected=%v", val, timeout)
	}
}

// TestNewHandleFromSockets checks that a Handle built on a caller-supplied, never-bound socket
// reports the family as supported and can complete a dump over it.
func TestNewHandleFromSockets(t *testing.T) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("Error creating the socket: %v", err)
	}
	s, err := nl.NewNetlinkSocketFromFd(fd)
	if err != nil {
		unix.Close(fd)
		t.Fatalf("Error wrapping the socket: %v", err)
	}

	h := NewHandleFromSockets(map[int]*nl.SocketHandle{unix.NETLINK_ROUTE: {Socket: s}}, HandleOptions{})
	defer h.Close()

	if !h.SupportsNetlinkFamily(unix.NETLINK_ROUTE) {
		t.Fatal("Expected the handle to report NETLINK_ROUTE support")
	}
	if err := h.SetSocketTimeout(time.Second); err != nil {
		t.Fatalf("SetSocketTimeout failed: %v", err)
	}

	// The socket was never bound. Every host has at least the loopback addresses.
	addrs, err := h.AddrList(nil, FAMILY_ALL)
	if err != nil {
		t.Fatalf("AddrList over the unbound socket failed: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("AddrList returned no addresses")
	}
}

// TestNewHandleFromSocketsIgnoresNilEntries checks that nil map entries are dropped so their
// families fall back to a short-lived socket instead of dereferencing nil.
func TestNewHandleFromSocketsIgnoresNilEntries(t *testing.T) {
	h := NewHandleFromSockets(map[int]*nl.SocketHandle{
		unix.NETLINK_ROUTE:   nil,
		unix.NETLINK_GENERIC: {Socket: nil},
	}, HandleOptions{})
	defer h.Close()

	if h.SupportsNetlinkFamily(unix.NETLINK_ROUTE) {
		t.Fatal("Expected a nil SocketHandle to be treated as unmapped")
	}
	if h.SupportsNetlinkFamily(unix.NETLINK_GENERIC) {
		t.Fatal("Expected a SocketHandle with a nil Socket to be treated as unmapped")
	}
	if err := h.SetSocketTimeout(time.Second); err != nil {
		t.Fatalf("SetSocketTimeout failed: %v", err)
	}

	// Unmapped families fall back to a short-lived socket.
	addrs, err := h.AddrList(nil, FAMILY_ALL)
	if err != nil {
		t.Fatalf("AddrList via the fallback socket failed: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("AddrList returned no addresses")
	}
}

// TestConfigureHandle checks that ConfigureHandle applies the options to the package-level handle
// and that it can only be called once.
func TestConfigureHandle(t *testing.T) {
	t.Cleanup(func() {
		pkgOptions = HandleOptions{}
		oncePkgOptions = sync.Once{}
	})

	assert.NoError(t, ConfigureHandle(HandleOptions{DisableVFInfoCollection: true}))
	assert.True(t, pkgOptions.DisableVFInfoCollection)

	assert.Error(t, ConfigureHandle(HandleOptions{}))
}
