package netlink

import (
	"bytes"
	"fmt"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
	"net"
	"unsafe"
)

type Filter interface {
	Attrs() *FilterAttrs
	Type() string
}

// FilterAttrs represents a netlink filter. A filter is associated with a link,
// has a handle and a parent. The root filter of a device should have a
// parent == HANDLE_ROOT.
type FilterAttrs struct {
	LinkIndex int
	Handle    uint32
	Parent    uint32
	Priority  uint16 // lower is higher priority
	Protocol  uint16 // unix.ETH_P_*
	Chain     *uint32
}

func (q FilterAttrs) String() string {
	return fmt.Sprintf("{LinkIndex: %d, Handle: %s, Parent: %s, Priority: %d, Protocol: %d}", q.LinkIndex, HandleStr(q.Handle), HandleStr(q.Parent), q.Priority, q.Protocol)
}

type TcAct int32

const (
	TC_ACT_EXT_SHIFT    = 28
	TC_ACT_EXT_VAL_MASK = (1 << TC_ACT_EXT_SHIFT) - 1
)

const (
	TC_ACT_UNSPEC     TcAct = -1
	TC_ACT_OK         TcAct = 0
	TC_ACT_RECLASSIFY TcAct = 1
	TC_ACT_SHOT       TcAct = 2
	TC_ACT_PIPE       TcAct = 3
	TC_ACT_STOLEN     TcAct = 4
	TC_ACT_QUEUED     TcAct = 5
	TC_ACT_REPEAT     TcAct = 6
	TC_ACT_REDIRECT   TcAct = 7
	TC_ACT_JUMP       TcAct = 0x10000000
)

func getTcActExt(local int32) int32 {
	return local << TC_ACT_EXT_SHIFT
}

func getTcActGotoChain() TcAct {
	return TcAct(getTcActExt(2))
}

func getTcActExtOpcode(combined int32) int32 {
	return combined & (^TC_ACT_EXT_VAL_MASK)
}

func TcActExtCmp(combined int32, opcode int32) bool {
	return getTcActExtOpcode(combined) == opcode
}

func (a TcAct) String() string {
	switch a {
	case TC_ACT_UNSPEC:
		return "unspec"
	case TC_ACT_OK:
		return "ok"
	case TC_ACT_RECLASSIFY:
		return "reclassify"
	case TC_ACT_SHOT:
		return "shot"
	case TC_ACT_PIPE:
		return "pipe"
	case TC_ACT_STOLEN:
		return "stolen"
	case TC_ACT_QUEUED:
		return "queued"
	case TC_ACT_REPEAT:
		return "repeat"
	case TC_ACT_REDIRECT:
		return "redirect"
	case TC_ACT_JUMP:
		return "jump"
	}
	if TcActExtCmp(int32(a), int32(getTcActGotoChain())) {
		return "goto"
	}
	return fmt.Sprintf("0x%x", int32(a))
}

type TcPolAct int32

const (
	TC_POLICE_UNSPEC     TcPolAct = TcPolAct(TC_ACT_UNSPEC)
	TC_POLICE_OK         TcPolAct = TcPolAct(TC_ACT_OK)
	TC_POLICE_RECLASSIFY TcPolAct = TcPolAct(TC_ACT_RECLASSIFY)
	TC_POLICE_SHOT       TcPolAct = TcPolAct(TC_ACT_SHOT)
	TC_POLICE_PIPE       TcPolAct = TcPolAct(TC_ACT_PIPE)
)

func (a TcPolAct) String() string {
	switch a {
	case TC_POLICE_UNSPEC:
		return "unspec"
	case TC_POLICE_OK:
		return "ok"
	case TC_POLICE_RECLASSIFY:
		return "reclassify"
	case TC_POLICE_SHOT:
		return "shot"
	case TC_POLICE_PIPE:
		return "pipe"
	}
	return fmt.Sprintf("0x%x", int32(a))
}

type ActionAttrs struct {
	Index   int
	Capab   int
	Action  TcAct
	Refcnt  int
	Bindcnt int
}

func (q ActionAttrs) String() string {
	return fmt.Sprintf("{Index: %d, Capab: %x, Action: %s, Refcnt: %d, Bindcnt: %d}", q.Index, q.Capab, q.Action.String(), q.Refcnt, q.Bindcnt)
}

// Action represents an action in any supported filter.
type Action interface {
	Attrs() *ActionAttrs
	Type() string
}

type GenericAction struct {
	ActionAttrs
	Chain int32
}

func (action *GenericAction) Type() string {
	return "generic"
}

func (action *GenericAction) Attrs() *ActionAttrs {
	return &action.ActionAttrs
}

type BpfAction struct {
	ActionAttrs
	Fd   int
	Name string
}

func (action *BpfAction) Type() string {
	return "bpf"
}

func (action *BpfAction) Attrs() *ActionAttrs {
	return &action.ActionAttrs
}

type ConnmarkAction struct {
	ActionAttrs
	Zone uint16
}

func (action *ConnmarkAction) Type() string {
	return "connmark"
}

func (action *ConnmarkAction) Attrs() *ActionAttrs {
	return &action.ActionAttrs
}

func NewConnmarkAction() *ConnmarkAction {
	return &ConnmarkAction{
		ActionAttrs: ActionAttrs{
			Action: TC_ACT_PIPE,
		},
	}
}

type CsumUpdateFlags uint32

const (
	TCA_CSUM_UPDATE_FLAG_IPV4HDR CsumUpdateFlags = 1
	TCA_CSUM_UPDATE_FLAG_ICMP    CsumUpdateFlags = 2
	TCA_CSUM_UPDATE_FLAG_IGMP    CsumUpdateFlags = 4
	TCA_CSUM_UPDATE_FLAG_TCP     CsumUpdateFlags = 8
	TCA_CSUM_UPDATE_FLAG_UDP     CsumUpdateFlags = 16
	TCA_CSUM_UPDATE_FLAG_UDPLITE CsumUpdateFlags = 32
	TCA_CSUM_UPDATE_FLAG_SCTP    CsumUpdateFlags = 64
)

type CsumAction struct {
	ActionAttrs
	UpdateFlags CsumUpdateFlags
}

func (action *CsumAction) Type() string {
	return "csum"
}

func (action *CsumAction) Attrs() *ActionAttrs {
	return &action.ActionAttrs
}

func NewCsumAction() *CsumAction {
	return &CsumAction{
		ActionAttrs: ActionAttrs{
			Action: TC_ACT_PIPE,
		},
	}
}

type MirredAct uint8

func (a MirredAct) String() string {
	switch a {
	case TCA_EGRESS_REDIR:
		return "egress redir"
	case TCA_EGRESS_MIRROR:
		return "egress mirror"
	case TCA_INGRESS_REDIR:
		return "ingress redir"
	case TCA_INGRESS_MIRROR:
		return "ingress mirror"
	}
	return "unknown"
}

const (
	TCA_EGRESS_REDIR   MirredAct = 1 /* packet redirect to EGRESS*/
	TCA_EGRESS_MIRROR  MirredAct = 2 /* mirror packet to EGRESS */
	TCA_INGRESS_REDIR  MirredAct = 3 /* packet redirect to INGRESS*/
	TCA_INGRESS_MIRROR MirredAct = 4 /* mirror packet to INGRESS */
)

type MirredAction struct {
	ActionAttrs
	MirredAction MirredAct
	Ifindex      int
}

func (action *MirredAction) Type() string {
	return "mirred"
}

func (action *MirredAction) Attrs() *ActionAttrs {
	return &action.ActionAttrs
}

func NewMirredAction(redirIndex int) *MirredAction {
	return &MirredAction{
		ActionAttrs: ActionAttrs{
			Action: TC_ACT_STOLEN,
		},
		MirredAction: TCA_EGRESS_REDIR,
		Ifindex:      redirIndex,
	}
}

type TunnelKeyAct int8

const (
	TCA_TUNNEL_KEY_SET   TunnelKeyAct = 1 // set tunnel key
	TCA_TUNNEL_KEY_UNSET TunnelKeyAct = 2 // unset tunnel key
)

type TunnelKeyAction struct {
	ActionAttrs
	Action   TunnelKeyAct
	SrcAddr  net.IP
	DstAddr  net.IP
	KeyID    uint32
	DestPort uint16
}

func (action *TunnelKeyAction) Type() string {
	return "tunnel_key"
}

func (action *TunnelKeyAction) Attrs() *ActionAttrs {
	return &action.ActionAttrs
}

func NewTunnelKeyAction() *TunnelKeyAction {
	return &TunnelKeyAction{
		ActionAttrs: ActionAttrs{
			Action: TC_ACT_PIPE,
		},
	}
}

type SkbEditAction struct {
	ActionAttrs
	QueueMapping *uint16
	PType        *uint16
	Priority     *uint32
	Mark         *uint32
	Mask         *uint32
}

func (action *SkbEditAction) Type() string {
	return "skbedit"
}

func (action *SkbEditAction) Attrs() *ActionAttrs {
	return &action.ActionAttrs
}

func NewSkbEditAction() *SkbEditAction {
	return &SkbEditAction{
		ActionAttrs: ActionAttrs{
			Action: TC_ACT_PIPE,
		},
	}
}

type PoliceAction struct {
	ActionAttrs
	Rate            uint32 // in byte per second
	Burst           uint32 // in byte
	RCellLog        int
	Mtu             uint32
	Mpu             uint16 // in byte
	PeakRate        uint32 // in byte per second
	PCellLog        int
	AvRate          uint32 // in byte per second
	Overhead        uint16
	LinkLayer       int
	ExceedAction    TcPolAct
	NotExceedAction TcPolAct
}

func (action *PoliceAction) Type() string {
	return "police"
}

func (action *PoliceAction) Attrs() *ActionAttrs {
	return &action.ActionAttrs
}

func NewPoliceAction() *PoliceAction {
	return &PoliceAction{
		RCellLog:        -1,
		PCellLog:        -1,
		LinkLayer:       1, // ETHERNET
		ExceedAction:    TC_POLICE_RECLASSIFY,
		NotExceedAction: TC_POLICE_OK,
	}
}

// MatchAll filters match all packets
type MatchAll struct {
	FilterAttrs
	ClassId uint32
	Actions []Action
}

func (filter *MatchAll) Attrs() *FilterAttrs {
	return &filter.FilterAttrs
}

func (filter *MatchAll) Type() string {
	return "matchall"
}

type FwFilter struct {
	FilterAttrs
	ClassId uint32
	InDev   string
	Mask    uint32
	Police  *PoliceAction
	Actions []Action
}

func (filter *FwFilter) Attrs() *FilterAttrs {
	return &filter.FilterAttrs
}

func (filter *FwFilter) Type() string {
	return "fw"
}

type BpfFilter struct {
	FilterAttrs
	ClassId      uint32
	Fd           int
	Name         string
	DirectAction bool
	Id           int
	Tag          string
}

func (filter *BpfFilter) Type() string {
	return "bpf"
}

func (filter *BpfFilter) Attrs() *FilterAttrs {
	return &filter.FilterAttrs
}

// GenericFilter filters represent types that are not currently understood
// by this netlink library.
type GenericFilter struct {
	FilterAttrs
	FilterType string
}

func (filter *GenericFilter) Attrs() *FilterAttrs {
	return &filter.FilterAttrs
}

func (filter *GenericFilter) Type() string {
	return filter.FilterType
}

type PeditAction struct {
	Sel    nl.TcPeditSel
	Keys   []nl.TcPeditKey
	KeysEx []nl.TcPeditKeyEx
	Extend uint8
}

func (p *PeditAction) Attrs() *ActionAttrs {
	attr := &ActionAttrs{}
	toAttrs(&p.Sel.TcGen, attr)
	return attr
}

func (p *PeditAction) Type() string {
	return "pedit"
}

func (p *PeditAction) Encode(parent *nl.RtAttr) {
	parent.AddRtAttr(nl.TCA_ACT_KIND, nl.ZeroTerminated("pedit"))
	actOpts := parent.AddRtAttr(nl.TCA_ACT_OPTIONS, nil)

	bbuf := bytes.NewBuffer(make([]byte, 0, int(unsafe.Sizeof(p.Sel)+unsafe.Sizeof(p.Keys))))

	bbuf.Write((*(*[nl.SizeOfPeditSel]byte)(unsafe.Pointer(&p.Sel)))[:])

	for i := uint8(0); i < p.Sel.NKeys; i++ {
		bbuf.Write((*(*[nl.SizeOfPeditKey]byte)(unsafe.Pointer(&p.Keys[i])))[:])
	}
	actOpts.AddRtAttr(nl.TCA_PEDIT_PARMS_EX, bbuf.Bytes())

	exAttrs := actOpts.AddRtAttr(int(nl.TCA_PEDIT_KEYS_EX|nl.NLA_F_NESTED), nil)
	for i := uint8(0); i < p.Sel.NKeys; i++ {
		keyAttr := exAttrs.AddRtAttr(int(nl.TCA_PEDIT_KEY_EX|nl.NLA_F_NESTED), nil)

		htypeBuf := make([]byte, 2)
		cmdBuf := make([]byte, 2)

		nl.NativeEndian().PutUint16(htypeBuf, uint16(p.KeysEx[i].HeaderType))
		nl.NativeEndian().PutUint16(cmdBuf, uint16(p.KeysEx[i].Cmd))

		keyAttr.AddRtAttr(nl.TCA_PEDIT_KEY_EX_HTYPE, htypeBuf)
		keyAttr.AddRtAttr(nl.TCA_PEDIT_KEY_EX_CMD, cmdBuf)
	}
}

func (p *PeditAction) SetEthDst(mac net.HardwareAddr) {
	u32 := nl.NativeEndian().Uint32(mac)
	u16 := nl.NativeEndian().Uint16(mac[4:])

	tKey := nl.TcPeditKey{}
	tKeyEx := nl.TcPeditKeyEx{}

	tKey.Val = u32

	tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_ETH
	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)
	p.Sel.NKeys++

	tKey = nl.TcPeditKey{}
	tKeyEx = nl.TcPeditKeyEx{}

	tKey.Val = uint32(u16)
	tKey.Mask = 0xffff0000
	tKey.Off = 4
	tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_ETH
	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)

	p.Sel.NKeys++
}

func (p *PeditAction) SetEthSrc(mac net.HardwareAddr) {
	u16 := nl.NativeEndian().Uint16(mac)
	u32 := nl.NativeEndian().Uint32(mac[2:])

	tKey := nl.TcPeditKey{}
	tKeyEx := nl.TcPeditKeyEx{}

	tKey.Val = uint32(u16) << 16
	tKey.Mask = 0x0000ffff
	tKey.Off = 4

	tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_ETH
	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)
	p.Sel.NKeys++

	tKey = nl.TcPeditKey{}
	tKeyEx = nl.TcPeditKeyEx{}

	tKey.Val = u32
	tKey.Mask = 0
	tKey.Off = 8

	tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_ETH
	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)

	p.Sel.NKeys++
}

func (p *PeditAction) SetIPv6Src(ip6 net.IP) {
	u32 := nl.NativeEndian().Uint32(ip6[:4])

	tKey := nl.TcPeditKey{}
	tKeyEx := nl.TcPeditKeyEx{}

	tKey.Val = u32
	tKey.Off = 8
	tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_IP6
	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)
	p.Sel.NKeys++

	u32 = nl.NativeEndian().Uint32(ip6[4:8])
	tKey = nl.TcPeditKey{}
	tKeyEx = nl.TcPeditKeyEx{}

	tKey.Val = u32
	tKey.Off = 12
	tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_IP6
	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)

	p.Sel.NKeys++

	u32 = nl.NativeEndian().Uint32(ip6[8:12])
	tKey = nl.TcPeditKey{}
	tKeyEx = nl.TcPeditKeyEx{}

	tKey.Val = u32
	tKey.Off = 16
	tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_IP6
	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)

	p.Sel.NKeys++

	u32 = nl.NativeEndian().Uint32(ip6[12:16])
	tKey = nl.TcPeditKey{}
	tKeyEx = nl.TcPeditKeyEx{}

	tKey.Val = u32
	tKey.Off = 20
	tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_IP6
	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)

	p.Sel.NKeys++
}

func (p *PeditAction) SetIPv6Dst(ip6 net.IP) {
	u32 := nl.NativeEndian().Uint32(ip6[:4])

	tKey := nl.TcPeditKey{}
	tKeyEx := nl.TcPeditKeyEx{}

	tKey.Val = u32
	tKey.Off = 24
	tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_IP6
	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)
	p.Sel.NKeys++

	u32 = nl.NativeEndian().Uint32(ip6[4:8])
	tKey = nl.TcPeditKey{}
	tKeyEx = nl.TcPeditKeyEx{}

	tKey.Val = u32
	tKey.Off = 28
	tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_IP6
	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)

	p.Sel.NKeys++

	u32 = nl.NativeEndian().Uint32(ip6[8:12])
	tKey = nl.TcPeditKey{}
	tKeyEx = nl.TcPeditKeyEx{}

	tKey.Val = u32
	tKey.Off = 32
	tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_IP6
	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)

	p.Sel.NKeys++

	u32 = nl.NativeEndian().Uint32(ip6[12:16])
	tKey = nl.TcPeditKey{}
	tKeyEx = nl.TcPeditKeyEx{}

	tKey.Val = u32
	tKey.Off = 36
	tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_IP6
	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)

	p.Sel.NKeys++
}

// SetDstPort only tcp and udp are supported to set port
func (p *PeditAction) SetDstPort(dstPort uint16, protocol uint8) {
	tKey := nl.TcPeditKey{}
	tKeyEx := nl.TcPeditKeyEx{}

	switch protocol {
	case unix.IPPROTO_TCP:
		tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_TCP
	case unix.IPPROTO_UDP:
		tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_UDP
	default:
		return
	}

	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	tKey.Val = uint32(nl.Swap16(dstPort)) << 16
	tKey.Mask = 0x0000ffff
	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)
	p.Sel.NKeys++
}

// SetSrcPort only tcp and udp are supported to set port
func (p *PeditAction) SetSrcPort(srcPort uint16, protocol uint8) {
	tKey := nl.TcPeditKey{}
	tKeyEx := nl.TcPeditKeyEx{}

	switch protocol {
	case unix.IPPROTO_TCP:
		tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_TCP
	case unix.IPPROTO_UDP:
		tKeyEx.HeaderType = nl.TCA_PEDIT_KEY_EX_HDR_TYPE_UDP
	default:
		return
	}

	tKeyEx.Cmd = nl.TCA_PEDIT_KEY_EX_CMD_SET

	tKey.Val = uint32(nl.Swap16(srcPort))
	tKey.Mask = 0xffff0000
	p.Keys = append(p.Keys, tKey)
	p.KeysEx = append(p.KeysEx, tKeyEx)
	p.Sel.NKeys++
}

func NewPeditAction(action TcAct) *PeditAction {
	return &PeditAction{
		Sel: nl.TcPeditSel{
			TcGen: nl.TcGen{
				Action: int32(action),
			},
		},
	}
}
