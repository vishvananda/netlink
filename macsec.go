package netlink

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// MACsec-specific netlink attributes (based on linux/if_macsec.h)
const (
	IFLA_MACSEC_SCI = iota + 1
	IFLA_MACSEC_PORT
	IFLA_MACSEC_ICV_LEN
	IFLA_MACSEC_CIPHER_SUITE
	IFLA_MACSEC_WINDOW
	IFLA_MACSEC_ENCODING_SA
	IFLA_MACSEC_ENCRYPT
	IFLA_MACSEC_PROTECT
	IFLA_MACSEC_INC_SCI
	IFLA_MACSEC_ES
	IFLA_MACSEC_SCB
	IFLA_MACSEC_REPLAY_PROTECT
	IFLA_MACSEC_VALIDATION
	IFLA_MACSEC_PAD
	IFLA_MACSEC_OFFLOAD
)

// MACsec SA and RXSC attributes (based on linux/if_macsec.h)
const (
	MACSEC_SA_ATTR           = 1
	MACSEC_SA_ATTR_AN        = 2
	MACSEC_SA_ATTR_PN        = 3
	MACSEC_SA_ATTR_ACTIVE    = 4
	MACSEC_SA_ATTR_KEYID     = 5
	MACSEC_SA_ATTR_KEY       = 6
	MACSEC_RXSC_ATTR         = 7
	MACSEC_RXSC_ATTR_SCI     = 8
	MACSEC_RXSC_ATTR_PORT    = 9
	MACSEC_RXSC_ATTR_ACTIVE  = 10
	MACSEC_RXSC_ATTR_ADDRESS = 11
)

// MACsec validation modes
const (
	MACSEC_VALIDATE_DISABLED = iota
	MACSEC_VALIDATE_CHECK
	MACSEC_VALIDATE_STRICT
)

// MACsec offload modes
const (
	MACSEC_OFFLOAD_OFF = iota
	MACSEC_OFFLOAD_PHY
	MACSEC_OFFLOAD_MAC
)

// MACsec cipher suites
const (
	MACSEC_CIPHER_ID_GCM_AES_128 = 0x00800201
	MACSEC_CIPHER_ID_GCM_AES_256 = 0x00800202
)

// Macsec represents a MACsec link device.
type Macsec struct {
	LinkAttrs
	Port          uint16           // Port number (1..65535)
	SCI           uint64           // Secure Channel Identifier
	Address       net.HardwareAddr // Link-layer address (optional)
	CipherSuite   uint64           // Cipher suite (e.g., GCM-AES-128)
	ICVLen        uint16           // Integrity Check Value length (default 16)
	Encrypt       bool             // Enable encryption
	ProtectFrames bool             // Protect frames
	SendSCI       bool             // Include SCI in packets
	EndStation    bool             // End station bit
	SCB           bool             // Single Copy Broadcast
	ReplayProtect bool             // Enable replay protection
	Window        uint32           // Replay window size
	Validation    uint8            // Validation mode: 0=disabled, 1=check, 2=strict
	EncodingSA    uint8            // Encoding Secure Association (0..3)
	Offload       uint8            // Offload mode: 0=off, 1=phy, 2=mac
}

// MacsecTxSA represents a transmit secure association.
type MacsecTxSA struct {
	ID     uint8  // SA ID (0..3)
	PN     uint32 // Packet Number (1..2^32-1)
	Active bool   // SA active state
	KeyID  uint8  // Key identifier
	Key    []byte // Encryption key (16 or 32 bytes)
}

// MacsecRxSC represents a receive secure channel.
type MacsecRxSC struct {
	Port    uint16           // Port number
	Address net.HardwareAddr // Link-layer address
	SCI     uint64           // Secure Channel Identifier
	Active  bool             // SC active state
}

// MacsecRxSA represents a receive secure association.
type MacsecRxSA struct {
	ID     uint8  // SA ID (0..3)
	PN     uint32 // Packet Number
	Active bool   // SA active state
	KeyID  uint8  // Key identifier
	Key    []byte // Encryption key (16 or 32 bytes)
}

// Attrs returns the link attributes.
func (macsec *Macsec) Attrs() *LinkAttrs {
	return &macsec.LinkAttrs
}

// Type returns the link type.
func (macsec *Macsec) Type() string {
	return "macsec"
}

// LinkAddMacsec creates a new MACsec link.
func LinkAddMacsec(macsec *Macsec) error {
	return pkgHandle.LinkAddMacsec(macsec)
}

func (h *Handle) LinkAddMacsec(macsec *Macsec) error {
	base := macsec.Attrs()
	if base.Name == "" {
		return fmt.Errorf("link name is required")
	}
	if base.ParentIndex == 0 {
		return fmt.Errorf("parent interface required for MACsec")
	}

	req := h.newNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Type = unix.ARPHRD_ETHER // MACsec uses Ethernet type, specified via IFLA_INFO_KIND
	msg.Flags = uint32(base.Flags)
	req.AddData(msg)

	// Add link attributes
	req.AddData(nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(base.Name)))
	req.AddData(nl.NewRtAttr(unix.IFLA_LINK, nl.Uint32Attr(uint32(base.ParentIndex))))

	// Add MACsec-specific attributes under IFLA_LINKINFO
	linkInfo := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(nl.IFLA_INFO_KIND, nl.ZeroTerminated("macsec"))

	infoData := nl.NewRtAttr(nl.IFLA_INFO_DATA, nil)
	if macsec.SCI != 0 {
		infoData.AddRtAttr(IFLA_MACSEC_SCI, nl.Uint64Attr(macsec.SCI))
	}
	if macsec.Port != 0 {
		infoData.AddRtAttr(IFLA_MACSEC_PORT, nl.Uint16Attr(macsec.Port))
	}
	if macsec.CipherSuite != 0 {
		infoData.AddRtAttr(IFLA_MACSEC_CIPHER_SUITE, nl.Uint64Attr(macsec.CipherSuite))
	}
	if macsec.ICVLen != 0 {
		infoData.AddRtAttr(IFLA_MACSEC_ICV_LEN, nl.Uint16Attr(macsec.ICVLen))
	}
	if macsec.Window != 0 {
		infoData.AddRtAttr(IFLA_MACSEC_WINDOW, nl.Uint32Attr(macsec.Window))
	}
	if macsec.EncodingSA != 0 {
		infoData.AddRtAttr(IFLA_MACSEC_ENCODING_SA, nl.Uint8Attr(macsec.EncodingSA))
	}
	infoData.AddRtAttr(IFLA_MACSEC_ENCRYPT, nl.Uint8Attr(boolToUint8(macsec.Encrypt)))
	infoData.AddRtAttr(IFLA_MACSEC_PROTECT, nl.Uint8Attr(boolToUint8(macsec.ProtectFrames)))
	infoData.AddRtAttr(IFLA_MACSEC_INC_SCI, nl.Uint8Attr(boolToUint8(macsec.SendSCI)))
	infoData.AddRtAttr(IFLA_MACSEC_ES, nl.Uint8Attr(boolToUint8(macsec.EndStation)))
	infoData.AddRtAttr(IFLA_MACSEC_SCB, nl.Uint8Attr(boolToUint8(macsec.SCB)))
	infoData.AddRtAttr(IFLA_MACSEC_REPLAY_PROTECT, nl.Uint8Attr(boolToUint8(macsec.ReplayProtect)))
	infoData.AddRtAttr(IFLA_MACSEC_VALIDATION, nl.Uint8Attr(macsec.Validation))
	infoData.AddRtAttr(IFLA_MACSEC_OFFLOAD, nl.Uint8Attr(macsec.Offload))

	// Serialize infoData before adding to linkInfo
	linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, infoData.Serialize())
	req.AddData(linkInfo)

	_, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWLINK)
	return err
}

// MacsecAddTxSA adds a transmit secure association.
func (h *Handle) MacsecAddTxSA(link Link, sa *MacsecTxSA) error {
	if sa.ID > 3 {
		return fmt.Errorf("invalid SA ID: %d, must be 0..3", sa.ID)
	}
	if len(sa.Key) != 16 && len(sa.Key) != 32 {
		return fmt.Errorf("invalid key length: %d, must be 16 or 32 bytes", len(sa.Key))
	}

	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(link.Attrs().Index)
	req.AddData(msg)

	linkInfo := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(nl.IFLA_INFO_KIND, nl.ZeroTerminated("macsec"))
	infoData := nl.NewRtAttr(nl.IFLA_INFO_DATA, nil)

	saData := nl.NewRtAttr(MACSEC_SA_ATTR, nil)
	saData.AddRtAttr(MACSEC_SA_ATTR_AN, nl.Uint8Attr(sa.ID))
	saData.AddRtAttr(MACSEC_SA_ATTR_PN, nl.Uint32Attr(sa.PN))
	saData.AddRtAttr(MACSEC_SA_ATTR_ACTIVE, nl.Uint8Attr(boolToUint8(sa.Active)))
	saData.AddRtAttr(MACSEC_SA_ATTR_KEYID, nl.Uint8Attr(sa.KeyID))
	saData.AddRtAttr(MACSEC_SA_ATTR_KEY, sa.Key)

	// Serialize saData before adding to infoData
	infoData.AddRtAttr(MACSEC_SA_ATTR, saData.Serialize())
	// Serialize infoData before adding to linkInfo
	linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, infoData.Serialize())
	req.AddData(linkInfo)

	_, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_SETLINK)
	return err
}

// MacsecAddRxSC adds a receive secure channel.
func (h *Handle) MacsecAddRxSC(link Link, sc *MacsecRxSC) error {
	if sc.SCI == 0 {
		return fmt.Errorf("SCI is required for receive secure channel")
	}

	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(link.Attrs().Index)
	req.AddData(msg)

	linkInfo := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(nl.IFLA_INFO_KIND, nl.ZeroTerminated("macsec"))
	infoData := nl.NewRtAttr(nl.IFLA_INFO_DATA, nil)

	scData := nl.NewRtAttr(MACSEC_RXSC_ATTR, nil)
	scData.AddRtAttr(MACSEC_RXSC_ATTR_SCI, nl.Uint64Attr(sc.SCI))
	if sc.Port != 0 {
		scData.AddRtAttr(MACSEC_RXSC_ATTR_PORT, nl.Uint16Attr(sc.Port))
	}
	scData.AddRtAttr(MACSEC_RXSC_ATTR_ACTIVE, nl.Uint8Attr(boolToUint8(sc.Active)))
	if sc.Address != nil {
		scData.AddRtAttr(MACSEC_RXSC_ATTR_ADDRESS, sc.Address)
	}

	// Serialize scData before adding to infoData
	infoData.AddRtAttr(MACSEC_RXSC_ATTR, scData.Serialize())
	// Serialize infoData before adding to linkInfo
	linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, infoData.Serialize())
	req.AddData(linkInfo)

	_, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_SETLINK)
	return err
}

// MacsecAddRxSA adds a receive secure association to a secure channel.
func (h *Handle) MacsecAddRxSA(link Link, sc *MacsecRxSC, sa *MacsecRxSA) error {
	if sa.ID > 3 {
		return fmt.Errorf("invalid SA ID: %d, must be 0..3", sa.ID)
	}
	if len(sa.Key) != 16 && len(sa.Key) != 32 {
		return fmt.Errorf("invalid key length: %d, must be 16 or 32 bytes", len(sa.Key))
	}
	if sc.SCI == 0 {
		return fmt.Errorf("SCI is required for receive secure channel")
	}

	req := h.newNetlinkRequest(unix.RTM_SETLINK, unix.NLM_F_ACK)
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(link.Attrs().Index)
	req.AddData(msg)

	linkInfo := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(nl.IFLA_INFO_KIND, nl.ZeroTerminated("macsec"))
	infoData := nl.NewRtAttr(nl.IFLA_INFO_DATA, nil)

	scData := nl.NewRtAttr(MACSEC_RXSC_ATTR, nil)
	scData.AddRtAttr(MACSEC_RXSC_ATTR_SCI, nl.Uint64Attr(sc.SCI))
	if sc.Port != 0 {
		scData.AddRtAttr(MACSEC_RXSC_ATTR_PORT, nl.Uint16Attr(sc.Port))
	}
	scData.AddRtAttr(MACSEC_RXSC_ATTR_ACTIVE, nl.Uint8Attr(boolToUint8(sc.Active)))
	if sc.Address != nil {
		scData.AddRtAttr(MACSEC_RXSC_ATTR_ADDRESS, sc.Address)
	}

	saData := nl.NewRtAttr(MACSEC_SA_ATTR, nil)
	saData.AddRtAttr(MACSEC_SA_ATTR_AN, nl.Uint8Attr(sa.ID))
	saData.AddRtAttr(MACSEC_SA_ATTR_PN, nl.Uint32Attr(sa.PN))
	saData.AddRtAttr(MACSEC_SA_ATTR_ACTIVE, nl.Uint8Attr(boolToUint8(sa.Active)))
	saData.AddRtAttr(MACSEC_SA_ATTR_KEYID, nl.Uint8Attr(sa.KeyID))
	saData.AddRtAttr(MACSEC_SA_ATTR_KEY, sa.Key)

	// Serialize saData before adding to scData
	scData.AddRtAttr(MACSEC_SA_ATTR, saData.Serialize())
	// Serialize scData before adding to infoData
	infoData.AddRtAttr(MACSEC_RXSC_ATTR, scData.Serialize())
	// Serialize infoData before adding to linkInfo
	linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, infoData.Serialize())
	req.AddData(linkInfo)

	_, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_SETLINK)
	return err
}

// Helper functions
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func Uint16ToBytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func Uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func Uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}
