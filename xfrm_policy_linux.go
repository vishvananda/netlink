package netlink

import (
	"syscall"
	"unsafe"
)

const (
	SizeofXfrmUserpolicyId   = 0x40
	SizeofXfrmUserpolicyInfo = 0xa8
	SizeofXfrmUserTmpl       = 0x40
)

// struct xfrm_userpolicy_id {
//   struct xfrm_selector    sel;
//   __u32       index;
//   __u8        dir;
// };
//

type XfrmUserpolicyId struct {
	Sel   XfrmSelector
	Index uint32
	Dir   uint8
	Pad   [3]byte
}

func (msg *XfrmUserpolicyId) Len() int {
	return SizeofXfrmUserpolicyId
}

func DeserializeXfrmUserpolicyId(b []byte) *XfrmUserpolicyId {
	return (*XfrmUserpolicyId)(unsafe.Pointer(&b[0:SizeofXfrmUserpolicyId][0]))
}

func (msg *XfrmUserpolicyId) Serialize() []byte {
	return (*(*[SizeofXfrmUserpolicyId]byte)(unsafe.Pointer(msg)))[:]
}

// struct xfrm_userpolicy_info {
//   struct xfrm_selector    sel;
//   struct xfrm_lifetime_cfg  lft;
//   struct xfrm_lifetime_cur  curlft;
//   __u32       priority;
//   __u32       index;
//   __u8        dir;
//   __u8        action;
// #define XFRM_POLICY_ALLOW 0
// #define XFRM_POLICY_BLOCK 1
//   __u8        flags;
// #define XFRM_POLICY_LOCALOK 1 /* Allow user to override global policy */
//   /* Automatically expand selector to include matching ICMP payloads. */
// #define XFRM_POLICY_ICMP  2
//   __u8        share;
// };

type XfrmUserpolicyInfo struct {
	Sel      XfrmSelector
	Lft      XfrmLifetimeCfg
	Curlft   XfrmLifetimeCur
	Priority uint32
	Index    uint32
	Dir      uint8
	Action   uint8
	Flags    uint8
	Share    uint8
	Pad      [4]byte
}

func (msg *XfrmUserpolicyInfo) Len() int {
	return SizeofXfrmUserpolicyInfo
}

func DeserializeXfrmUserpolicyInfo(b []byte) *XfrmUserpolicyInfo {
	return (*XfrmUserpolicyInfo)(unsafe.Pointer(&b[0:SizeofXfrmUserpolicyInfo][0]))
}

func (msg *XfrmUserpolicyInfo) Serialize() []byte {
	return (*(*[SizeofXfrmUserpolicyInfo]byte)(unsafe.Pointer(msg)))[:]
}

// struct xfrm_user_tmpl {
//   struct xfrm_id    id;
//   __u16     family;
//   xfrm_address_t    saddr;
//   __u32     reqid;
//   __u8      mode;
//   __u8      share;
//   __u8      optional;
//   __u32     aalgos;
//   __u32     ealgos;
//   __u32     calgos;
// }

type XfrmUserTmpl struct {
	XfrmId   XfrmId
	Family   uint16
	Pad1     [2]byte
	Saddr    XfrmAddress
	Reqid    uint32
	Mode     uint8
	Share    uint8
	Optional uint8
	Pad2     byte
	Aalgos   uint32
	Ealgos   uint32
	Calgos   uint32
}

func (msg *XfrmUserTmpl) Len() int {
	return SizeofXfrmUserTmpl
}

func DeserializeXfrmUserTmpl(b []byte) *XfrmUserTmpl {
	return (*XfrmUserTmpl)(unsafe.Pointer(&b[0:SizeofXfrmUserTmpl][0]))
}

func (msg *XfrmUserTmpl) Serialize() []byte {
	return (*(*[SizeofXfrmUserTmpl]byte)(unsafe.Pointer(msg)))[:]
}

// XfrmPolicyAdd will add an xfrm policy to the system.
// Equivalent to: `ip xfrm policy add $policy`
func XfrmPolicyAdd(policy *XfrmPolicy) error {
	req := newNetlinkRequest(XFRM_MSG_NEWPOLICY, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)

	msg := &XfrmUserpolicyInfo{}
	msg.Sel.FromPolicy(policy)
	msg.Priority = uint32(policy.Priority)
	msg.Index = uint32(policy.Index)
	msg.Dir = uint8(policy.Dir)
	msg.Lft.SoftByteLimit = XFRM_INF
	msg.Lft.HardByteLimit = XFRM_INF
	msg.Lft.SoftPacketLimit = XFRM_INF
	msg.Lft.HardPacketLimit = XFRM_INF
	req.AddData(msg)

	tmplData := make([]byte, SizeofXfrmUserTmpl*len(policy.Tmpls))
	for i, tmpl := range policy.Tmpls {
		start := i * SizeofXfrmUserTmpl
		userTmpl := DeserializeXfrmUserTmpl(tmplData[start : start+SizeofXfrmUserTmpl])
		userTmpl.XfrmId.Daddr.FromIP(tmpl.Dst)
		userTmpl.Saddr.FromIP(tmpl.Src)
		userTmpl.XfrmId.Proto = uint8(tmpl.Proto)
		userTmpl.Mode = uint8(tmpl.Mode)
		userTmpl.Reqid = uint32(tmpl.Reqid)
		userTmpl.Aalgos = ^uint32(0)
		userTmpl.Ealgos = ^uint32(0)
		userTmpl.Calgos = ^uint32(0)
	}
	if len(tmplData) > 0 {
		tmpls := newRtAttr(XFRMA_TMPL, tmplData)
		req.AddData(tmpls)
	}

	_, err := req.Execute(syscall.NETLINK_XFRM, 0)
	return err
}

// XfrmPolicyDel will delete an xfrm policy from the system. Note that
// the Tmpls are ignored when matching the policy to delete.
// Equivalent to: `ip xfrm policy del $policy`
func XfrmPolicyDel(policy *XfrmPolicy) error {
	req := newNetlinkRequest(XFRM_MSG_DELPOLICY, syscall.NLM_F_ACK)

	msg := &XfrmUserpolicyId{}
	msg.Sel.FromPolicy(policy)
	msg.Index = uint32(policy.Index)
	msg.Dir = uint8(policy.Dir)
	req.AddData(msg)

	_, err := req.Execute(syscall.NETLINK_XFRM, 0)
	return err
}

// XfrmPolicyList gets a list of xfrm policies in the system.
// Equivalent to: `ip xfrm policy show`.
// The list can be filtered by ip family.
func XfrmPolicyList(family int) ([]XfrmPolicy, error) {
	req := newNetlinkRequest(XFRM_MSG_GETPOLICY, syscall.NLM_F_DUMP)

	msg := newIfInfomsg(family)
	req.AddData(msg)

	msgs, err := req.Execute(syscall.NETLINK_XFRM, XFRM_MSG_NEWPOLICY)
	if err != nil {
		return nil, err
	}

	res := make([]XfrmPolicy, 0)
	for _, m := range msgs {
		msg := DeserializeXfrmUserpolicyInfo(m)

		if family != FAMILY_ALL && family != int(msg.Sel.Family) {
			continue
		}

		var policy XfrmPolicy

		policy.Dst = msg.Sel.Daddr.ToIPNet(msg.Sel.PrefixlenD)
		policy.Src = msg.Sel.Saddr.ToIPNet(msg.Sel.PrefixlenS)
		policy.Priority = int(msg.Priority)
		policy.Index = int(msg.Index)
		policy.Dir = Dir(msg.Dir)

		attrs, err := parseRouteAttr(m[msg.Len():])
		if err != nil {
			return nil, err
		}

		for _, attr := range attrs {
			switch attr.Attr.Type {
			case XFRMA_TMPL:
				max := len(attr.Value)
				for i := 0; i < max; i += SizeofXfrmUserTmpl {
					var resTmpl XfrmPolicyTmpl
					tmpl := DeserializeXfrmUserTmpl(attr.Value[i : i+SizeofXfrmUserTmpl])
					resTmpl.Dst = tmpl.XfrmId.Daddr.ToIP()
					resTmpl.Src = tmpl.Saddr.ToIP()
					resTmpl.Proto = Proto(tmpl.XfrmId.Proto)
					resTmpl.Mode = Mode(tmpl.Mode)
					resTmpl.Reqid = int(tmpl.Reqid)
					policy.Tmpls = append(policy.Tmpls, resTmpl)
				}
			}
		}
		res = append(res, policy)
	}
	return res, nil
}
