package nl

import (
	"unsafe"
)

const SizeofGenlmsg = 4

const (
	GENL_ID_CTRL      = 0x10
	GENL_CTRL_VERSION = 2
	GENL_CTRL_NAME    = "nlctrl"
)

const (
	GENL_CTRL_CMD_GETFAMILY = 3
)

const (
	GENL_CTRL_ATTR_UNSPEC = iota
	GENL_CTRL_ATTR_FAMILY_ID
	GENL_CTRL_ATTR_FAMILY_NAME
	GENL_CTRL_ATTR_VERSION
	GENL_CTRL_ATTR_HDRSIZE
	GENL_CTRL_ATTR_MAXATTR
	GENL_CTRL_ATTR_OPS
	GENL_CTRL_ATTR_MCAST_GROUPS
)

const (
	GENL_CTRL_ATTR_OP_UNSPEC = iota
	GENL_CTRL_ATTR_OP_ID
	GENL_CTRL_ATTR_OP_FLAGS
)

const (
	GENL_ADMIN_PERM = 1 << iota
	GENL_CMD_CAP_DO
	GENL_CMD_CAP_DUMP
	GENL_CMD_CAP_HASPOL
)

const (
	GENL_CTRL_ATTR_MCAST_GRP_UNSPEC = iota
	GENL_CTRL_ATTR_MCAST_GRP_NAME
	GENL_CTRL_ATTR_MCAST_GRP_ID
)

type Genlmsg struct {
	Command uint8
	Version uint8
}

func (msg *Genlmsg) Len() int {
	return SizeofGenlmsg
}

func DeserializeGenlmsg(b []byte) *Genlmsg {
	return (*Genlmsg)(unsafe.Pointer(&b[0:SizeofGenlmsg][0]))
}

func (msg *Genlmsg) Serialize() []byte {
	return (*(*[SizeofGenlmsg]byte)(unsafe.Pointer(msg)))[:]
}
