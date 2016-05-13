package netlink

import (
	"bytes"
	"net"
	"testing"
)

func TestXfrmStateAddGetDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	state := &XfrmState{
		Src:   net.ParseIP("127.0.0.1"),
		Dst:   net.ParseIP("127.0.0.2"),
		Proto: XFRM_PROTO_ESP,
		Mode:  XFRM_MODE_TUNNEL,
		Spi:   1,
		Auth: &XfrmStateAlgo{
			Name: "hmac(sha256)",
			Key:  []byte("abcdefghijklmnopqrstuvwzyzABCDEF"),
		},
		Crypt: &XfrmStateAlgo{
			Name: "cbc(aes)",
			Key:  []byte("abcdefghijklmnopqrstuvwzyzABCDEF"),
		},
		Mark: &XfrmMark{
			Value: 0x12340000,
			Mask:  0xffff0000,
		},
	}

	if err := XfrmStateAdd(state); err != nil {
		t.Fatal(err)
	}
	states, err := XfrmStateList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}

	if len(states) != 1 {
		t.Fatal("State not added properly")
	}

	if !compareStates(state, &states[0]) {
		t.Fatalf("unexpected states returned")
	}

	// Get specific state
	sa, err := XfrmStateGet(state)
	if err != nil {
		t.Fatal(err)
	}

	if !compareStates(state, sa) {
		t.Fatalf("unexpected state returned")
	}

	if err = XfrmStateDel(state); err != nil {
		t.Fatal(err)
	}

	states, err = XfrmStateList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 0 {
		t.Fatal("State not removed properly")
	}

	if _, err := XfrmStateGet(state); err == nil {
		t.Fatalf("Unexpected success")
	}
}

func TestXfrmStateFlush(t *testing.T) {
	setUpNetlinkTest(t)()

	state1 := &XfrmState{
		Src:   net.ParseIP("127.0.0.1"),
		Dst:   net.ParseIP("127.0.0.2"),
		Proto: XFRM_PROTO_ESP,
		Mode:  XFRM_MODE_TRANSPORT,
		Spi:   10,
		Crypt: &XfrmStateAlgo{
			Name: "cbc(aes)",
			Key:  []byte("abcdefghijklmnopqrstuvwzyzABCDEF"),
		},
		Mark: &XfrmMark{
			Value: 0x12340000,
			Mask:  0xffff0000,
		},
	}

	state2 := &XfrmState{
		Src:   net.ParseIP("127.1.0.1"),
		Dst:   net.ParseIP("127.1.0.2"),
		Proto: XFRM_PROTO_AH,
		Mode:  XFRM_MODE_TUNNEL,
		Spi:   10,
		Auth: &XfrmStateAlgo{
			Name: "hmac(sha256)",
			Key:  []byte("abcdefghijklmnopqrstuvwzyzABCDEF"),
		},
	}
	if err := XfrmStateAdd(state1); err != nil {
		t.Fatal(err)
	}
	if err := XfrmStateAdd(state2); err != nil {
		t.Fatal(err)
	}

	// flushing proto for which no state is present should return silently
	if err := XfrmStateFlush(XFRM_PROTO_COMP); err != nil {
		t.Fatal(err)
	}

	if err := XfrmStateFlush(XFRM_PROTO_AH); err != nil {
		t.Fatal(err)
	}

	if _, err := XfrmStateGet(state2); err == nil {
		t.Fatalf("Unexpected success")
	}

	if err := XfrmStateAdd(state2); err != nil {
		t.Fatal(err)
	}

	if err := XfrmStateFlush(0); err != nil {
		t.Fatal(err)
	}

	states, err := XfrmStateList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 0 {
		t.Fatal("State not flushed properly")
	}

}
func compareStates(a, b *XfrmState) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Src.Equal(b.Src) && a.Dst.Equal(b.Dst) &&
		a.Mode == b.Mode && a.Spi == b.Spi && a.Proto == b.Proto &&
		a.Auth.Name == b.Auth.Name && bytes.Equal(a.Auth.Key, b.Auth.Key) &&
		a.Crypt.Name == b.Crypt.Name && bytes.Equal(a.Crypt.Key, b.Crypt.Key) &&
		a.Mark.Value == b.Mark.Value && a.Mark.Mask == b.Mark.Mask
}
