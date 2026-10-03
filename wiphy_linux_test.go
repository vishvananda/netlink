//go:build linux
// +build linux

package netlink

import (
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func TestWiphySetNsFdRejectsNegativeArguments(t *testing.T) {
	for _, tc := range []struct {
		name  string
		wiphy int
		fd    int
		want  string
	}{
		{name: "negative wiphy", wiphy: -1, fd: 42, want: "wiphy index must be non-negative: -1"},
		{name: "negative namespace fd", wiphy: 7, fd: -1, want: "network namespace fd must be non-negative: -1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := (&Handle{}).WiphySetNsFd(tc.wiphy, tc.fd)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("unexpected error: got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNewWiphySetNsFdRequest(t *testing.T) {
	const (
		family = 0x23
		wiphy  = 7
		fd     = 42
	)

	req := (&Handle{}).newWiphySetNsFdRequest(family, wiphy, fd)
	if req.Type != family {
		t.Fatalf("unexpected netlink message type: got %d, want %d", req.Type, family)
	}
	if want := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK); req.Flags != want {
		t.Fatalf("unexpected netlink flags: got %#x, want %#x", req.Flags, want)
	}

	data := req.Serialize()[unix.SizeofNlMsghdr:]
	genl := nl.DeserializeGenlmsg(data)
	if genl.Command != nl80211CmdSetWiphyNetns {
		t.Fatalf("unexpected generic netlink command: got %d, want %d", genl.Command, nl80211CmdSetWiphyNetns)
	}
	if genl.Version != nl80211GenlVersion {
		t.Fatalf("unexpected generic netlink version: got %d, want %d", genl.Version, nl80211GenlVersion)
	}

	attrs, err := nl.ParseRouteAttr(data[nl.SizeofGenlmsg:])
	if err != nil {
		t.Fatalf("failed to parse attributes: %v", err)
	}
	if len(attrs) != 2 {
		t.Fatalf("unexpected attribute count: got %d, want 2", len(attrs))
	}
	if attrs[0].Attr.Type != nl80211AttrWiphy || native.Uint32(attrs[0].Value) != wiphy {
		t.Fatalf("unexpected wiphy attribute: type=%d value=%d", attrs[0].Attr.Type, native.Uint32(attrs[0].Value))
	}
	if attrs[1].Attr.Type != nl80211AttrNetnsFD || native.Uint32(attrs[1].Value) != fd {
		t.Fatalf("unexpected netns fd attribute: type=%d value=%d", attrs[1].Attr.Type, native.Uint32(attrs[1].Value))
	}
}
