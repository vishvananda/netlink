package netlink

import (
	"net"
	"testing"
)

func TestXfrmPolicyAddUpdateDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	src, _ := ParseIPNet("127.1.1.1/32")
	dst, _ := ParseIPNet("127.1.1.2/32")
	policy := XfrmPolicy{
		Src: src,
		Dst: dst,
		Dir: XFRM_DIR_OUT,
		Mark: &XfrmMark{
			Value: 0xabff22,
			Mask:  0xffffffff,
		},
		Priority: 10,
	}
	tmpl := XfrmPolicyTmpl{
		Src:   net.ParseIP("127.0.0.1"),
		Dst:   net.ParseIP("127.0.0.2"),
		Proto: XFRM_PROTO_ESP,
		Mode:  XFRM_MODE_TUNNEL,
	}
	policy.Tmpls = append(policy.Tmpls, tmpl)
	if err := XfrmPolicyAdd(&policy); err != nil {
		t.Fatal(err)
	}
	policies, err := XfrmPolicyList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}

	if len(policies) != 1 {
		t.Fatal("Policy not added properly")
	}

	// Modify the policy
	policy.Priority = 100
	if err := XfrmPolicyUpdate(&policy); err != nil {
		t.Fatal(err)
	}
	policies, err = XfrmPolicyList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	if policies[0].Priority != 100 {
		t.Fatalf("failed to modify the policy")
	}

	if err = XfrmPolicyDel(&policy); err != nil {
		t.Fatal(err)
	}

	policies, err = XfrmPolicyList(FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 0 {
		t.Fatal("Policy not removed properly")
	}
}
