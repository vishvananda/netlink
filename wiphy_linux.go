//go:build linux
// +build linux

package netlink

import (
	"fmt"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Values from include/uapi/linux/nl80211.h in the Linux kernel source.
const (
	nl80211GenlName    = "nl80211"
	nl80211GenlVersion = 1

	nl80211CmdSetWiphyNetns = 49
	nl80211AttrWiphy        = 1
	nl80211AttrNetnsFD      = 219
)

// WiphySetNsFd moves a wireless PHY to the network namespace specified by fd.
// All interfaces associated with the wiphy must be down before it can be moved.
func WiphySetNsFd(wiphy, fd int) error {
	return pkgHandle.WiphySetNsFd(wiphy, fd)
}

// WiphySetNsFd moves a wireless PHY to the network namespace specified by fd.
// All interfaces associated with the wiphy must be down before it can be moved.
func (h *Handle) WiphySetNsFd(wiphy, fd int) error {
	if wiphy < 0 {
		return fmt.Errorf("wiphy index must be non-negative: %d", wiphy)
	}
	if fd < 0 {
		return fmt.Errorf("network namespace fd must be non-negative: %d", fd)
	}

	family, err := h.GenlFamilyGet(nl80211GenlName)
	if err != nil {
		return err
	}

	req := h.newWiphySetNsFdRequest(int(family.ID), wiphy, fd)
	_, err = req.Execute(unix.NETLINK_GENERIC, 0)
	return err
}

func (h *Handle) newWiphySetNsFdRequest(family, wiphy, fd int) *nl.NetlinkRequest {
	req := h.newNetlinkRequest(family, unix.NLM_F_ACK)
	req.AddData(&nl.Genlmsg{
		Command: nl80211CmdSetWiphyNetns,
		Version: nl80211GenlVersion,
	})
	req.AddData(nl.NewRtAttr(nl80211AttrWiphy, nl.Uint32Attr(uint32(wiphy))))
	req.AddData(nl.NewRtAttr(nl80211AttrNetnsFD, nl.Uint32Attr(uint32(fd))))
	return req
}
