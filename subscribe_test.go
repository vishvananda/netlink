//go:build linux
// +build linux

package netlink

import (
	"os"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openSockets counts the socket file descriptors of this process.
func openSockets(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if l, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && strings.HasPrefix(l, "socket:") {
			n++
		}
	}
	return n
}

// waitForSockets waits up to two seconds for the number of open sockets to drop
// to want and returns how many more than want are still open.
func waitForSockets(t *testing.T, want int) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for openSockets(t) > want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return openSockets(t) - want
}

// TestSubscribeClosesSocketOnReceiveError checks that a subscription closes its
// netlink socket when its receive goroutine stops on an error, without waiting
// for done to be closed. A short receive timeout makes Receive fail.
func TestSubscribeClosesSocketOnReceiveError(t *testing.T) {
	// An unreachable socket is eventually closed by the os.File finalizer.
	// Keep the GC from doing that, so only the subscription can close it.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	timeout := func() *unix.Timeval { return &unix.Timeval{Usec: 1000} }
	ignore := func(error) {}

	tests := []struct {
		name      string
		subscribe func(done <-chan struct{}) (wait func(), err error)
	}{
		{"link", func(done <-chan struct{}) (func(), error) {
			ch := make(chan LinkUpdate)
			err := LinkSubscribeWithOptions(ch, done, LinkSubscribeOptions{ErrorCallback: ignore, ReceiveTimeout: timeout()})
			return func() {
				for range ch {
				}
			}, err
		}},
		{"addr", func(done <-chan struct{}) (func(), error) {
			ch := make(chan AddrUpdate)
			err := AddrSubscribeWithOptions(ch, done, AddrSubscribeOptions{ErrorCallback: ignore, ReceiveTimeout: timeout()})
			return func() {
				for range ch {
				}
			}, err
		}},
		{"route", func(done <-chan struct{}) (func(), error) {
			ch := make(chan RouteUpdate)
			err := RouteSubscribeWithOptions(ch, done, RouteSubscribeOptions{ErrorCallback: ignore, ReceiveTimeout: timeout()})
			return func() {
				for range ch {
				}
			}, err
		}},
		{"neigh", func(done <-chan struct{}) (func(), error) {
			ch := make(chan NeighUpdate)
			err := NeighSubscribeWithOptions(ch, done, NeighSubscribeOptions{ErrorCallback: ignore, ReceiveTimeout: timeout()})
			return func() {
				for range ch {
				}
			}, err
		}},
	}

	for _, tt := range tests {
		for _, nilDone := range []bool{false, true} {
			name := tt.name
			if nilDone {
				name += "/nil done"
			}
			t.Run(name, func(t *testing.T) {
				before := openSockets(t)
				var done chan struct{}
				if !nilDone {
					done = make(chan struct{})
					// Once done is closed every socket must be gone, so the
					// next subtest starts from a settled count.
					defer func() {
						close(done)
						waitForSockets(t, before)
					}()
				}

				for i := 0; i < 5; i++ {
					wait, err := tt.subscribe(done)
					if err != nil {
						t.Fatal(err)
					}
					wait() // returns once the receive goroutine has stopped
				}

				// the socket is closed right after the receive goroutine stops
				if leaked := waitForSockets(t, before); leaked > 0 {
					t.Errorf("%d sockets still open after the receive goroutines stopped", leaked)
				}
			})
		}
	}
}
