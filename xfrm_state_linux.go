package netlink

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	SizeofXfrmUsersaId   = 0x18
	SizeofXfrmStats      = 0x0c
	SizeofXfrmUsersaInfo = 0xe0
	SizeofXfrmAlgo       = 0x44
	SizeofXfrmAlgoAuth   = 0x48
	SizeofXfrmEncapTmpl  = 0x18
)

// struct xfrm_usersa_id {
//   xfrm_address_t      daddr;
//   __be32        spi;
//   __u16       family;
//   __u8        proto;
// };

type XfrmUsersaId struct {
	Daddr  XfrmAddress
	Spi    uint32 // big endian
	Family uint16
	Proto  uint8
	Pad    byte
}

func (msg *XfrmUsersaId) Len() int {
	return SizeofXfrmUsersaId
}

func DeserializeXfrmUsersaId(b []byte) *XfrmUsersaId {
	return (*XfrmUsersaId)(unsafe.Pointer(&b[0:SizeofXfrmUsersaId][0]))
}

func (msg *XfrmUsersaId) Serialize() []byte {
	return (*(*[SizeofXfrmUsersaId]byte)(unsafe.Pointer(msg)))[:]
}

// struct xfrm_stats {
//   __u32 replay_window;
//   __u32 replay;
//   __u32 integrity_failed;
// };

type XfrmStats struct {
	ReplayWindow    uint32
	Replay          uint32
	IntegrityFailed uint32
}

func (msg *XfrmStats) Len() int {
	return SizeofXfrmStats
}

func DeserializeXfrmStats(b []byte) *XfrmStats {
	return (*XfrmStats)(unsafe.Pointer(&b[0:SizeofXfrmStats][0]))
}

func (msg *XfrmStats) Serialize() []byte {
	return (*(*[SizeofXfrmStats]byte)(unsafe.Pointer(msg)))[:]
}

// struct xfrm_usersa_info {
//   struct xfrm_selector    sel;
//   struct xfrm_id      id;
//   xfrm_address_t      saddr;
//   struct xfrm_lifetime_cfg  lft;
//   struct xfrm_lifetime_cur  curlft;
//   struct xfrm_stats   stats;
//   __u32       seq;
//   __u32       reqid;
//   __u16       family;
//   __u8        mode;   /* XFRM_MODE_xxx */
//   __u8        replay_window;
//   __u8        flags;
// #define XFRM_STATE_NOECN  1
// #define XFRM_STATE_DECAP_DSCP 2
// #define XFRM_STATE_NOPMTUDISC 4
// #define XFRM_STATE_WILDRECV 8
// #define XFRM_STATE_ICMP   16
// #define XFRM_STATE_AF_UNSPEC  32
// #define XFRM_STATE_ALIGN4 64
// #define XFRM_STATE_ESN    128
// };
//
// #define XFRM_SA_XFLAG_DONT_ENCAP_DSCP 1
//

type XfrmUsersaInfo struct {
	Sel          XfrmSelector
	Id           XfrmId
	Saddr        XfrmAddress
	Lft          XfrmLifetimeCfg
	Curlft       XfrmLifetimeCur
	Stats        XfrmStats
	Seq          uint32
	Reqid        uint32
	Family       uint16
	Mode         uint8
	ReplayWindow uint8
	Flags        uint8 // TODO: investigate enum
	Pad          [7]byte
}

func (msg *XfrmUsersaInfo) Len() int {
	return SizeofXfrmUsersaInfo
}

func DeserializeXfrmUsersaInfo(b []byte) *XfrmUsersaInfo {
	return (*XfrmUsersaInfo)(unsafe.Pointer(&b[0:SizeofXfrmUsersaInfo][0]))
}

func (msg *XfrmUsersaInfo) Serialize() []byte {
	return (*(*[SizeofXfrmUsersaInfo]byte)(unsafe.Pointer(msg)))[:]
}

// struct xfrm_algo {
//   char    alg_name[64];
//   unsigned int  alg_key_len;    /* in bits */
//   char    alg_key[0];
// };

type XfrmAlgo struct {
	AlgName   [64]byte
	AlgKeyLen uint32
	AlgKey    []byte
}

func (msg *XfrmAlgo) Len() int {
	return SizeofXfrmAlgo + int(msg.AlgKeyLen/8)
}

func DeserializeXfrmAlgo(b []byte) *XfrmAlgo {
	ret := XfrmAlgo{}
	copy(ret.AlgName[:], b[0:64])
	ret.AlgKeyLen = *(*uint32)(unsafe.Pointer(&b[64]))
	ret.AlgKey = b[68:ret.Len()]
	return &ret
}

func (msg *XfrmAlgo) Serialize() []byte {
	b := make([]byte, msg.Len())
	copy(b[0:64], msg.AlgName[:])
	copy(b[64:68], (*(*[4]byte)(unsafe.Pointer(&msg.AlgKeyLen)))[:])
	copy(b[68:msg.Len()], msg.AlgKey[:])
	return b
}

// struct xfrm_algo_auth {
//   char    alg_name[64];
//   unsigned int  alg_key_len;    /* in bits */
//   unsigned int  alg_trunc_len;  /* in bits */
//   char    alg_key[0];
// };

type XfrmAlgoAuth struct {
	AlgName     [64]byte
	AlgKeyLen   uint32
	AlgTruncLen uint32
	AlgKey      []byte
}

func (msg *XfrmAlgoAuth) Len() int {
	return SizeofXfrmAlgoAuth + int(msg.AlgKeyLen/8)
}

func DeserializeXfrmAlgoAuth(b []byte) *XfrmAlgoAuth {
	ret := XfrmAlgoAuth{}
	copy(ret.AlgName[:], b[0:64])
	ret.AlgKeyLen = *(*uint32)(unsafe.Pointer(&b[64]))
	ret.AlgTruncLen = *(*uint32)(unsafe.Pointer(&b[68]))
	ret.AlgKey = b[72:ret.Len()]
	return &ret
}

func (msg *XfrmAlgoAuth) Serialize() []byte {
	b := make([]byte, msg.Len())
	copy(b[0:64], msg.AlgName[:])
	copy(b[64:68], (*(*[4]byte)(unsafe.Pointer(&msg.AlgKeyLen)))[:])
	copy(b[68:72], (*(*[4]byte)(unsafe.Pointer(&msg.AlgTruncLen)))[:])
	copy(b[72:msg.Len()], msg.AlgKey[:])
	return b
}

// struct xfrm_algo_aead {
//   char    alg_name[64];
//   unsigned int  alg_key_len;  /* in bits */
//   unsigned int  alg_icv_len;  /* in bits */
//   char    alg_key[0];
// }

// struct xfrm_encap_tmpl {
//   __u16   encap_type;
//   __be16    encap_sport;
//   __be16    encap_dport;
//   xfrm_address_t  encap_oa;
// };

type XfrmEncapTmpl struct {
	EncapType  uint16
	EncapSport uint16 // big endian
	EncapDport uint16 // big endian
	Pad        [2]byte
	EncapOa    XfrmAddress
}

func (msg *XfrmEncapTmpl) Len() int {
	return SizeofXfrmEncapTmpl
}

func DeserializeXfrmEncapTmpl(b []byte) *XfrmEncapTmpl {
	return (*XfrmEncapTmpl)(unsafe.Pointer(&b[0:SizeofXfrmEncapTmpl][0]))
}

func (msg *XfrmEncapTmpl) Serialize() []byte {
	return (*(*[SizeofXfrmEncapTmpl]byte)(unsafe.Pointer(msg)))[:]
}

func writeStateAlgo(a *XfrmStateAlgo) []byte {
	algo := XfrmAlgo{
		AlgKeyLen: uint32(len(a.Key) * 8),
		AlgKey:    a.Key,
	}
	end := len(a.Name)
	if end > 64 {
		end = 64
	}
	copy(algo.AlgName[:end], a.Name)
	return algo.Serialize()
}

func writeStateAlgoAuth(a *XfrmStateAlgo) []byte {
	algo := XfrmAlgoAuth{
		AlgKeyLen:   uint32(len(a.Key) * 8),
		AlgTruncLen: uint32(a.TruncateLen),
		AlgKey:      a.Key,
	}
	end := len(a.Name)
	if end > 64 {
		end = 64
	}
	copy(algo.AlgName[:end], a.Name)
	return algo.Serialize()
}

// XfrmStateAdd will add an xfrm state to the system.
// Equivalent to: `ip xfrm state add $state`
func XfrmStateAdd(state *XfrmState) error {
	// A state with spi 0 can't be deleted so don't allow it to be set
	if state.Spi == 0 {
		return fmt.Errorf("Spi must be set when adding xfrm state.")
	}
	req := newNetlinkRequest(XFRM_MSG_NEWSA, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)

	msg := &XfrmUsersaInfo{}
	msg.Family = uint16(GetIPFamily(state.Dst))
	msg.Id.Daddr.FromIP(state.Dst)
	msg.Saddr.FromIP(state.Src)
	msg.Id.Proto = uint8(state.Proto)
	msg.Mode = uint8(state.Mode)
	msg.Id.Spi = swap32(uint32(state.Spi))
	msg.Reqid = uint32(state.Reqid)
	msg.ReplayWindow = uint8(state.ReplayWindow)
	msg.Lft.SoftByteLimit = XFRM_INF
	msg.Lft.HardByteLimit = XFRM_INF
	msg.Lft.SoftPacketLimit = XFRM_INF
	msg.Lft.HardPacketLimit = XFRM_INF
	req.AddData(msg)

	if state.Auth != nil {
		out := newRtAttr(XFRMA_ALG_AUTH_TRUNC, writeStateAlgoAuth(state.Auth))
		req.AddData(out)
	}
	if state.Crypt != nil {
		out := newRtAttr(XFRMA_ALG_CRYPT, writeStateAlgo(state.Crypt))
		req.AddData(out)
	}
	if state.Encap != nil {
		encapData := make([]byte, SizeofXfrmEncapTmpl)
		encap := DeserializeXfrmEncapTmpl(encapData)
		encap.EncapType = uint16(state.Encap.Type)
		encap.EncapSport = swap16(uint16(state.Encap.SrcPort))
		encap.EncapDport = swap16(uint16(state.Encap.DstPort))
		encap.EncapOa.FromIP(state.Encap.OriginalAddress)
		out := newRtAttr(XFRMA_ENCAP, encapData)
		req.AddData(out)
	}

	_, err := req.Execute(syscall.NETLINK_XFRM, 0)
	return err
}

// XfrmStateDel will delete an xfrm state from the system. Note that
// the Algos are ignored when matching the state to delete.
// Equivalent to: `ip xfrm state del $state`
func XfrmStateDel(state *XfrmState) error {
	req := newNetlinkRequest(XFRM_MSG_DELSA, syscall.NLM_F_ACK)

	msg := &XfrmUsersaId{}
	msg.Daddr.FromIP(state.Dst)
	msg.Family = uint16(GetIPFamily(state.Dst))
	msg.Proto = uint8(state.Proto)
	msg.Spi = swap32(uint32(state.Spi))
	req.AddData(msg)

	saddr := XfrmAddress{}
	saddr.FromIP(state.Src)
	srcdata := newRtAttr(XFRMA_SRCADDR, saddr.Serialize())

	req.AddData(srcdata)

	_, err := req.Execute(syscall.NETLINK_XFRM, 0)
	return err
}

// XfrmStateList gets a list of xfrm states in the system.
// Equivalent to: `ip xfrm state show`.
// The list can be filtered by ip family.
func XfrmStateList(family int) ([]XfrmState, error) {
	req := newNetlinkRequest(XFRM_MSG_GETSA, syscall.NLM_F_DUMP)

	msg := newIfInfomsg(family)
	req.AddData(msg)

	msgs, err := req.Execute(syscall.NETLINK_XFRM, XFRM_MSG_NEWSA)
	if err != nil {
		return nil, err
	}

	res := make([]XfrmState, 0)
	for _, m := range msgs {
		msg := DeserializeXfrmUsersaInfo(m)

		if family != FAMILY_ALL && family != int(msg.Family) {
			continue
		}

		var state XfrmState

		state.Dst = msg.Id.Daddr.ToIP()
		state.Src = msg.Saddr.ToIP()
		state.Proto = Proto(msg.Id.Proto)
		state.Mode = Mode(msg.Mode)
		state.Spi = int(swap32(msg.Id.Spi))
		state.Reqid = int(msg.Reqid)
		state.ReplayWindow = int(msg.ReplayWindow)

		attrs, err := parseRouteAttr(m[msg.Len():])
		if err != nil {
			return nil, err
		}

		for _, attr := range attrs {
			switch attr.Attr.Type {
			case XFRMA_ALG_AUTH, XFRMA_ALG_CRYPT:
				var resAlgo *XfrmStateAlgo
				if attr.Attr.Type == XFRMA_ALG_AUTH {
					if state.Auth == nil {
						state.Auth = new(XfrmStateAlgo)
					}
					resAlgo = state.Auth
				} else {
					state.Crypt = new(XfrmStateAlgo)
					resAlgo = state.Crypt
				}
				algo := DeserializeXfrmAlgo(attr.Value[:])
				(*resAlgo).Name = bytesToString(algo.AlgName[:])
				(*resAlgo).Key = algo.AlgKey
			case XFRMA_ALG_AUTH_TRUNC:
				if state.Auth == nil {
					state.Auth = new(XfrmStateAlgo)
				}
				algo := DeserializeXfrmAlgoAuth(attr.Value[:])
				state.Auth.Name = bytesToString(algo.AlgName[:])
				state.Auth.Key = algo.AlgKey
				state.Auth.TruncateLen = int(algo.AlgTruncLen)
			case XFRMA_ENCAP:
				encap := DeserializeXfrmEncapTmpl(attr.Value[:])
				state.Encap = new(XfrmStateEncap)
				state.Encap.Type = EncapType(encap.EncapType)
				state.Encap.SrcPort = int(swap16(encap.EncapSport))
				state.Encap.DstPort = int(swap16(encap.EncapDport))
				state.Encap.OriginalAddress = encap.EncapOa.ToIP()
			}

		}
		res = append(res, state)
	}
	return res, nil
}
