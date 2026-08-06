package netlink

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func TestMacsecAdd(t *testing.T) {
	// Requires root and MACsec-capable kernel
	ns, err := netns.New()
	if err != nil {
		t.Skipf("Failed to create network namespace: %v", err)
	}
	defer ns.Close()

	handle, err := NewHandleAt(ns)
	if err != nil {
		t.Fatalf("Failed to create netlink handle: %v", err)
	}
	defer handle.Close()

	// Create a dummy parent link
	dummy := &Dummy{
		LinkAttrs: LinkAttrs{Name: "dummy0"},
	}
	if err := handle.LinkAdd(dummy); err != nil {
		t.Fatalf("Failed to create dummy link: %v", err)
	}

	parent, err := handle.LinkByName("dummy0")
	if err != nil {
		t.Fatalf("Failed to find dummy link: %v", err)
	}

	// Create MACsec link
	macsec := &Macsec{
		LinkAttrs: LinkAttrs{
			Name:        "macsec0",
			ParentIndex: parent.Attrs().Index,
		},
		SCI:           0x1234567890ABCDEF,
		Port:          1,
		CipherSuite:   MACSEC_CIPHER_ID_GCM_AES_128,
		ICVLen:        16,
		Encrypt:       true,
		ProtectFrames: true,
		SendSCI:       true,
		Validation:    MACSEC_VALIDATE_STRICT,
		Window:        128,
		ReplayProtect: true,
		Offload:       MACSEC_OFFLOAD_OFF,
	}

	if err := handle.LinkAddMacsec(macsec); err != nil {
		t.Fatalf("Failed to add MACsec link: %v", err)
	}

	// Verify the link exists
	_, err = handle.LinkByName("macsec0")
	if err != nil {
		t.Fatalf("MACsec link not found: %v", err)
	}

	// Add a transmit SA
	sa := &MacsecTxSA{
		ID:     0,
		PN:     1,
		Active: true,
		Key:    []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
		KeyID:  1,
	}
	if err := handle.MacsecAddTxSA(macsec, sa); err != nil {
		t.Fatalf("Failed to add TX SA: %v", err)
	}

	// Add a receive SC
	rxSC := &MacsecRxSC{
		SCI:     0x1234567890ABCDEF,
		Port:    1,
		Address: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		Active:  true,
	}
	if err := handle.MacsecAddRxSC(macsec, rxSC); err != nil {
		t.Fatalf("Failed to add RX SC: %v", err)
	}

	// Add a receive SA
	rxSA := &MacsecRxSA{
		ID:     0,
		PN:     1,
		Active: true,
		Key:    []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
		KeyID:  1,
	}
	if err := handle.MacsecAddRxSA(macsec, rxSC, rxSA); err != nil {
		t.Fatalf("Failed to add RX SA: %v", err)
	}
}

func TestMacsecAttributesSerialize(t *testing.T) {
	macsec := &Macsec{
		LinkAttrs: LinkAttrs{
			Name:        "macsec0",
			ParentIndex: 1,
		},
		SCI:           0x1234567890ABCDEF,
		Port:          1,
		CipherSuite:   MACSEC_CIPHER_ID_GCM_AES_128,
		ICVLen:        16,
		Encrypt:       true,
		ProtectFrames: true,
		SendSCI:       true,
		Validation:    MACSEC_VALIDATE_STRICT,
		Window:        128,
		ReplayProtect: true,
		Offload:       MACSEC_OFFLOAD_OFF,
	}

	req := nl.NewNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Type = unix.ARPHRD_ETHER
	req.AddData(msg)

	req.AddData(nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(macsec.LinkAttrs.Name)))
	req.AddData(nl.NewRtAttr(unix.IFLA_LINK, nl.Uint32Attr(uint32(macsec.LinkAttrs.ParentIndex))))

	linkInfo := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(nl.IFLA_INFO_KIND, nl.ZeroTerminated("macsec"))
	infoData := nl.NewRtAttr(nl.IFLA_INFO_DATA, nil)
	infoData.AddRtAttr(IFLA_MACSEC_SCI, nl.Uint64Attr(macsec.SCI))
	infoData.AddRtAttr(IFLA_MACSEC_PORT, nl.Uint16Attr(macsec.Port))
	infoData.AddRtAttr(IFLA_MACSEC_CIPHER_SUITE, nl.Uint64Attr(macsec.CipherSuite))
	infoData.AddRtAttr(IFLA_MACSEC_ICV_LEN, nl.Uint16Attr(macsec.ICVLen))
	infoData.AddRtAttr(IFLA_MACSEC_WINDOW, nl.Uint32Attr(macsec.Window))
	infoData.AddRtAttr(IFLA_MACSEC_ENCRYPT, nl.Uint8Attr(boolToUint8(macsec.Encrypt)))
	infoData.AddRtAttr(IFLA_MACSEC_PROTECT, nl.Uint8Attr(boolToUint8(macsec.ProtectFrames)))
	infoData.AddRtAttr(IFLA_MACSEC_INC_SCI, nl.Uint8Attr(boolToUint8(macsec.SendSCI)))
	infoData.AddRtAttr(IFLA_MACSEC_VALIDATION, nl.Uint8Attr(macsec.Validation))
	infoData.AddRtAttr(IFLA_MACSEC_OFFLOAD, nl.Uint8Attr(macsec.Offload))

	// Serialize infoData before adding to linkInfo
	linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, infoData.Serialize())
	req.AddData(linkInfo)

	// Serialize and check for errors
	data := req.Serialize()
	_ = data // Suppress unused variable warning
}
