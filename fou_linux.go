// +build linux

package netlink

import (
	"encoding/binary"
	"errors"
	"log"
	"net"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	FOU_GENL_NAME = "fou"
)

const (
	FOU_CMD_UNSPEC uint8 = iota
	FOU_CMD_ADD
	FOU_CMD_DEL
	FOU_CMD_GET
	FOU_CMD_MAX = FOU_CMD_GET
)

const (
	FOU_ATTR_UNSPEC = iota

	FOU_ATTR_PORT              /* u16 */
	FOU_ATTR_AF                /* u8 */
	FOU_ATTR_IPPROTO           /* u8 */
	FOU_ATTR_TYPE              /* u8 */
	FOU_ATTR_REMCSUM_NOPARTIAL /* flag */
	FOU_ATTR_LOCAL_V4          /* u32 */
	FOU_ATTR_LOCAL_V6          /* in6_addr */
	FOU_ATTR_PEER_V4           /* u32 */
	FOU_ATTR_PEER_V6           /* in6_addr */
	FOU_ATTR_PEER_PORT         /* u16 */
	FOU_ATTR_IFINDEX           /* s32 */

	FOU_ATTR_MAX
)

const (
	FOU_ENCAP_UNSPEC = iota
	FOU_ENCAP_DIRECT
	FOU_ENCAP_GUE
	FOU_ENCAP_MAX = FOU_ENCAP_GUE
)

var fouFamilyID int

func FouFamilyId() (int, error) {
	if fouFamilyID != 0 {
		return fouFamilyID, nil
	}

	fam, err := GenlFamilyGet(FOU_GENL_NAME)
	if err != nil {
		return -1, err
	}

	fouFamilyID = int(fam.ID)
	return fouFamilyID, nil
}

func FouAdd(f Fou) error {
	return pkgHandle.FouAdd(f)
}

func (h *Handle) FouAdd(f Fou) error {
	// setting ip protocol conflicts with encapsulation type GUE
	if f.EncapType == FOU_ENCAP_GUE && f.Protocol != 0 {
		return errors.New("GUE encapsulation doesn't specify an IP protocol")
	}

	return h.fouAddDel(&f, FOU_CMD_ADD)
}

func FouDel(f Fou) error {
	return pkgHandle.FouDel(f)
}

func (h *Handle) FouDel(f Fou) error {
	return h.fouAddDel(&f, FOU_CMD_DEL)
}

func FouList(fam int) ([]Fou, error) {
	return pkgHandle.FouList(fam)
}

func (h *Handle) FouList(fam int) ([]Fou, error) {
	req, err := h.newFouRequest(unix.NLM_F_DUMP, FOU_CMD_GET)
	if err != nil {
		return nil, err
	}

	req.AddRtAttr(FOU_ATTR_AF, []byte{uint8(fam)})

	msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		return nil, err
	}

	fous := make([]Fou, len(msgs))
	for i := range msgs {
		fous[i] = deserializeFouMsg(msgs[i])
	}

	return fous, nil
}

func (h *Handle) newFouRequest(flags int, cmd uint8) (*nl.NetlinkRequest, error) {
	familyID, err := FouFamilyId()
	if err != nil {
		return nil, err
	}

	return h.newNetlinkRequest(familyID, flags).AddRawData([]byte{cmd, 1, 0, 0}), nil
}

func (h *Handle) fouAddDel(f *Fou, cmd uint8) error {
	req, err := h.newFouRequest(unix.NLM_F_ACK, cmd)
	if err != nil {
		return err
	}

	req.AddRtAttr(FOU_ATTR_TYPE, []byte{uint8(f.EncapType)}).
		AddRtAttr(FOU_ATTR_AF, []byte{uint8(f.Family)}).
		AddRtAttr(FOU_ATTR_IPPROTO, []byte{uint8(f.Protocol)})

	// local port
	bp := make([]byte, 2)
	binary.BigEndian.PutUint16(bp[0:2], uint16(f.Port))
	req.AddRtAttr(FOU_ATTR_PORT, bp)

	// peer port
	if f.PeerPort > 0 {
		bp = make([]byte, 2)
		binary.BigEndian.PutUint16(bp[0:2], uint16(f.PeerPort))
		req.AddRtAttr(FOU_ATTR_PEER_PORT, bp)
	}

	// local IP address
	if !f.LocalAddr.IsUnspecified() {
		if f.Family == nl.FAMILY_V4 {
			req.AddRtAttr(FOU_ATTR_LOCAL_V4, f.LocalAddr.To4())
		} else {
			req.AddRtAttr(FOU_ATTR_LOCAL_V6, f.LocalAddr.To16())
		}
	}

	// peer IP address
	if !f.PeerAddr.IsUnspecified() {
		if f.Family == nl.FAMILY_V4 {
			req.AddRtAttr(FOU_ATTR_PEER_V4, f.PeerAddr.To4())
		} else {
			req.AddRtAttr(FOU_ATTR_PEER_V6, f.PeerAddr.To16())
		}
	}

	// ifindex
	if f.IfIndex > 0 {
		buf := make([]byte, 4)
		native.PutUint32(buf, uint32(f.IfIndex))
		req.AddRtAttr(FOU_ATTR_IFINDEX, buf)
	}

	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

func deserializeFouMsg(msg []byte) (fou Fou) {
	for attr := range nl.ParseAttributes(msg[4:]) {
		switch attr.Type {
		case FOU_ATTR_AF:
			fou.Family = int(attr.Value[0])
		case FOU_ATTR_PORT:
			fou.Port = int(binary.BigEndian.Uint16(attr.Value))
		case FOU_ATTR_PEER_PORT:
			fou.PeerPort = int(binary.BigEndian.Uint16(attr.Value))
		case FOU_ATTR_IPPROTO:
			fou.Protocol = int(attr.Value[0])
		case FOU_ATTR_TYPE:
			fou.EncapType = int(attr.Value[0])
		case FOU_ATTR_LOCAL_V4, FOU_ATTR_LOCAL_V6:
			fou.LocalAddr = net.IP(attr.Value)
		case FOU_ATTR_PEER_V4, FOU_ATTR_PEER_V6:
			fou.PeerAddr = net.IP(attr.Value)
		case FOU_ATTR_IFINDEX:
			fou.IfIndex = int(attr.Int32())
		default:
			log.Printf("unknown attribute: %02x", attr)
		}
	}
	return
}
