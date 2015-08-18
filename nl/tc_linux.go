package nl

import (
	"unsafe"
)

// Message types
const (
	TCA_UNSPEC = iota
	TCA_KIND
	TCA_OPTIONS
	TCA_STATS
	TCA_XSTATS
	TCA_RATE
	TCA_FCNT
	TCA_STATS2
	TCA_STAB
	TCA_MAX = TCA_STAB
)

const (
	TCA_ACT_TAB = 1
	TCAA_MAX    = 1
)

const (
	TCA_PRIO_UNSPEC = iota
	TCA_PRIO_MQ
	TCA_PRIO_MAX = TCA_PRIO_MQ
)

const (
	SizeofTcMsg       = 0x14
	SizeofTcActionMsg = 0x04
	SizeofTcPrioMap   = 0x14
	SizeofTcRateSpec  = 0x0c
	SizeofTcTbfQopt   = 2*SizeofTcRateSpec + 0x0c
)

// struct tcmsg {
//   unsigned char tcm_family;
//   unsigned char tcm__pad1;
//   unsigned short  tcm__pad2;
//   int   tcm_ifindex;
//   __u32   tcm_handle;
//   __u32   tcm_parent;
//   __u32   tcm_info;
// };

type TcMsg struct {
	Family  uint8
	Pad     [3]byte
	Ifindex int32
	Handle  uint32
	Parent  uint32
	Info    uint32
}

func (msg *TcMsg) Len() int {
	return SizeofTcMsg
}

func DeserializeTcMsg(b []byte) *TcMsg {
	return (*TcMsg)(unsafe.Pointer(&b[0:SizeofTcMsg][0]))
}

func (x *TcMsg) Serialize() []byte {
	return (*(*[SizeofTcMsg]byte)(unsafe.Pointer(x)))[:]
}

// struct tcamsg {
//   unsigned char tca_family;
//   unsigned char tca__pad1;
//   unsigned short  tca__pad2;
// };

type TcActionMsg struct {
	Family uint8
	Pad    [3]byte
}

func (msg *TcActionMsg) Len() int {
	return SizeofTcActionMsg
}

func DeserializeTcActionMsg(b []byte) *TcActionMsg {
	return (*TcActionMsg)(unsafe.Pointer(&b[0:SizeofTcActionMsg][0]))
}

func (x *TcActionMsg) Serialize() []byte {
	return (*(*[SizeofTcActionMsg]byte)(unsafe.Pointer(x)))[:]
}

const (
	TC_PRIO_MAX = 15
)

// struct tc_prio_qopt {
// 	int bands;      /* Number of bands */
// 	__u8  priomap[TC_PRIO_MAX+1]; /* Map: logical priority -> PRIO band */
// };

type TcPrioMap struct {
	Bands   int32
	Priomap [TC_PRIO_MAX + 1]uint8
}

func DeserializeTcPrioMap(b []byte) *TcPrioMap {
	return (*TcPrioMap)(unsafe.Pointer(&b[0:SizeofTcPrioMap][0]))
}

func (x *TcPrioMap) Serialize() []byte {
	return (*(*[SizeofTcPrioMap]byte)(unsafe.Pointer(x)))[:]
}

const (
	TCA_TBF_UNSPEC = iota
	TCA_TBF_PARMS
	TCA_TBF_RTAB
	TCA_TBF_PTAB
	TCA_TBF_RATE64
	TCA_TBF_PRATE64
	TCA_TBF_BURST
	TCA_TBF_PBURST
	TCA_TBF_MAX = TCA_TBF_PBURST
)

// struct tc_ratespec {
//   unsigned char cell_log;
//   __u8    linklayer; /* lower 4 bits */
//   unsigned short  overhead;
//   short   cell_align;
//   unsigned short  mpu;
//   __u32   rate;
// };

type TcRateSpec struct {
	CellLog   uint8
	Linklayer uint8
	Overhead  uint16
	CellAlign int16
	Mpu       uint16
	Rate      uint32
}

func DeserializeTcRateSpec(b []byte) *TcRateSpec {
	return (*TcRateSpec)(unsafe.Pointer(&b[0:SizeofTcRateSpec][0]))
}

func (x *TcRateSpec) Serialize() []byte {
	return (*(*[SizeofTcRateSpec]byte)(unsafe.Pointer(x)))[:]
}

// struct tc_tbf_qopt {
//   struct tc_ratespec rate;
//   struct tc_ratespec peakrate;
//   __u32   limit;
//   __u32   buffer;
//   __u32   mtu;
// };

type TcTbfQopt struct {
	Rate     TcRateSpec
	Peakrate TcRateSpec
	Limit    uint32
	Buffer   uint32
	Mtu      uint32
}

func DeserializeTcTbfQopt(b []byte) *TcTbfQopt {
	return (*TcTbfQopt)(unsafe.Pointer(&b[0:SizeofTcTbfQopt][0]))
}

func (x *TcTbfQopt) Serialize() []byte {
	return (*(*[SizeofTcTbfQopt]byte)(unsafe.Pointer(x)))[:]
}
