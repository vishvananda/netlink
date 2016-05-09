package netlink

import (
	"fmt"
	"syscall"

	"github.com/vishvananda/netlink/nl"
)

func writeStateAlgo(a *XfrmStateAlgo) []byte {
	algo := nl.XfrmAlgo{
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
	algo := nl.XfrmAlgoAuth{
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

func writeMark(m *XfrmMark) []byte {
	mark := &nl.XfrmMark{
		Value: m.Value,
		Mask:  m.Mask,
	}
	if mark.Mask == 0 {
		mark.Mask = ^uint32(0)
	}
	return mark.Serialize()
}

// XfrmStateAdd will add an xfrm state to the system.
// Equivalent to: `ip xfrm state add $state`
func XfrmStateAdd(state *XfrmState) error {
	return pkgHandle.XfrmStateAdd(state)
}

// XfrmStateAdd will add an xfrm state to the system.
// Equivalent to: `ip xfrm state add $state`
func (h *Handle) XfrmStateAdd(state *XfrmState) error {
	return h.xfrmStateAddOrUpdate(state, nl.XFRM_MSG_NEWSA)
}

// XfrmStateUpdate will update an xfrm state to the system.
// Equivalent to: `ip xfrm state update $state`
func XfrmStateUpdate(state *XfrmState) error {
	return pkgHandle.XfrmStateUpdate(state)
}

// XfrmStateUpdate will update an xfrm state to the system.
// Equivalent to: `ip xfrm state update $state`
func (h *Handle) XfrmStateUpdate(state *XfrmState) error {
	return h.xfrmStateAddOrUpdate(state, nl.XFRM_MSG_UPDSA)
}

func (h *Handle) xfrmStateAddOrUpdate(state *XfrmState, nlProto int) error {
	// A state with spi 0 can't be deleted so don't allow it to be set
	if state.Spi == 0 {
		return fmt.Errorf("Spi must be set when adding xfrm state.")
	}
	req := h.newNetlinkRequest(nlProto, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)

	msg := &nl.XfrmUsersaInfo{}
	msg.Family = uint16(nl.GetIPFamily(state.Dst))
	msg.Id.Daddr.FromIP(state.Dst)
	msg.Saddr.FromIP(state.Src)
	msg.Id.Proto = uint8(state.Proto)
	msg.Mode = uint8(state.Mode)
	msg.Id.Spi = nl.Swap32(uint32(state.Spi))
	msg.Reqid = uint32(state.Reqid)
	msg.ReplayWindow = uint8(state.ReplayWindow)
	msg.Lft.SoftByteLimit = nl.XFRM_INF
	msg.Lft.HardByteLimit = nl.XFRM_INF
	msg.Lft.SoftPacketLimit = nl.XFRM_INF
	msg.Lft.HardPacketLimit = nl.XFRM_INF
	req.AddData(msg)

	if state.Auth != nil {
		out := nl.NewRtAttr(nl.XFRMA_ALG_AUTH_TRUNC, writeStateAlgoAuth(state.Auth))
		req.AddData(out)
	}
	if state.Crypt != nil {
		out := nl.NewRtAttr(nl.XFRMA_ALG_CRYPT, writeStateAlgo(state.Crypt))
		req.AddData(out)
	}
	if state.Encap != nil {
		encapData := make([]byte, nl.SizeofXfrmEncapTmpl)
		encap := nl.DeserializeXfrmEncapTmpl(encapData)
		encap.EncapType = uint16(state.Encap.Type)
		encap.EncapSport = nl.Swap16(uint16(state.Encap.SrcPort))
		encap.EncapDport = nl.Swap16(uint16(state.Encap.DstPort))
		encap.EncapOa.FromIP(state.Encap.OriginalAddress)
		out := nl.NewRtAttr(nl.XFRMA_ENCAP, encapData)
		req.AddData(out)
	}
	if state.Mark != nil {
		out := nl.NewRtAttr(nl.XFRMA_MARK, writeMark(state.Mark))
		req.AddData(out)
	}

	_, err := req.Execute(syscall.NETLINK_XFRM, 0)
	return err
}

// XfrmStateDel will delete an xfrm state from the system. Note that
// the Algos are ignored when matching the state to delete.
// Equivalent to: `ip xfrm state del $state`
func XfrmStateDel(state *XfrmState) error {
	return pkgHandle.XfrmStateDel(state)
}

// XfrmStateDel will delete an xfrm state from the system. Note that
// the Algos are ignored when matching the state to delete.
// Equivalent to: `ip xfrm state del $state`
func (h *Handle) XfrmStateDel(state *XfrmState) error {
	req := h.newNetlinkRequest(nl.XFRM_MSG_DELSA, syscall.NLM_F_ACK)

	msg := &nl.XfrmUsersaId{}
	msg.Daddr.FromIP(state.Dst)
	msg.Family = uint16(nl.GetIPFamily(state.Dst))
	msg.Proto = uint8(state.Proto)
	msg.Spi = nl.Swap32(uint32(state.Spi))
	req.AddData(msg)

	saddr := nl.XfrmAddress{}
	saddr.FromIP(state.Src)
	srcdata := nl.NewRtAttr(nl.XFRMA_SRCADDR, saddr.Serialize())

	req.AddData(srcdata)
	if state.Mark != nil {
		out := nl.NewRtAttr(nl.XFRMA_MARK, writeMark(state.Mark))
		req.AddData(out)
	}
	_, err := req.Execute(syscall.NETLINK_XFRM, 0)
	return err
}

// XfrmStateList gets a list of xfrm states in the system.
// Equivalent to: `ip [-4|-6] xfrm state show`.
// The list can be filtered by ip family.
func XfrmStateList(family int) ([]XfrmState, error) {
	return pkgHandle.XfrmStateList(family)
}

// XfrmStateList gets a list of xfrm states in the system.
// Equivalent to: `ip xfrm state show`.
// The list can be filtered by ip family.
func (h *Handle) XfrmStateList(family int) ([]XfrmState, error) {
	req := h.newNetlinkRequest(nl.XFRM_MSG_GETSA, syscall.NLM_F_DUMP)

	msgs, err := req.Execute(syscall.NETLINK_XFRM, nl.XFRM_MSG_NEWSA)
	if err != nil {
		return nil, err
	}

	var res []XfrmState
	for _, m := range msgs {
		if state, err := parseXfrmState(m, family); err == nil {
			res = append(res, *state)
		} else if err == familyError {
			continue
		} else {
			return nil, err
		}
	}
	return res, nil
}

// XfrmStateGet gets the xfrm state described by the ID, if found.
// Equivalent to: `ip xfrm state get ID [ mark MARK [ mask MASK ] ]`.
// Only the fields which constitue the SA ID must be filled in:
// ID := [ src ADDR ] [ dst ADDR ] [ proto XFRM-PROTO ] [ spi SPI ]
// mark is optional
func XfrmStateGet(state *XfrmState) (*XfrmState, error) {
	req := nl.NewNetlinkRequest(nl.XFRM_MSG_GETSA, syscall.NLM_F_DUMP)

	msg := &nl.XfrmUsersaInfo{}
	msg.Family = uint16(nl.GetIPFamily(state.Dst))
	msg.Id.Daddr.FromIP(state.Dst)
	msg.Saddr.FromIP(state.Src)
	msg.Id.Proto = uint8(state.Proto)
	msg.Id.Spi = nl.Swap32(uint32(state.Spi))
	req.AddData(msg)

	if state.Mark != nil {
		out := nl.NewRtAttr(nl.XFRMA_MARK, writeMark(state.Mark))
		req.AddData(out)
	}

	msgs, err := req.Execute(syscall.NETLINK_XFRM, nl.XFRM_MSG_NEWSA)
	if err != nil {
		return nil, err
	}

	if state, err := parseXfrmState(msgs[0], FAMILY_ALL); err == nil {
		return state, nil
	} else {
		return nil, err
	}
}

var familyError = fmt.Errorf("family error")

func parseXfrmState(m []byte, family int) (*XfrmState, error) {
	msg := nl.DeserializeXfrmUsersaInfo(m)

	// This is mainly for the state dump
	if family != FAMILY_ALL && family != int(msg.Family) {
		return nil, familyError
	}

	var state XfrmState

	state.Dst = msg.Id.Daddr.ToIP()
	state.Src = msg.Saddr.ToIP()
	state.Proto = Proto(msg.Id.Proto)
	state.Mode = Mode(msg.Mode)
	state.Spi = int(nl.Swap32(msg.Id.Spi))
	state.Reqid = int(msg.Reqid)
	state.ReplayWindow = int(msg.ReplayWindow)

	attrs, err := nl.ParseRouteAttr(m[nl.SizeofXfrmUsersaInfo:])
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		switch attr.Attr.Type {
		case nl.XFRMA_ALG_AUTH, nl.XFRMA_ALG_CRYPT:
			var resAlgo *XfrmStateAlgo
			if attr.Attr.Type == nl.XFRMA_ALG_AUTH {
				if state.Auth == nil {
					state.Auth = new(XfrmStateAlgo)
				}
				resAlgo = state.Auth
			} else {
				state.Crypt = new(XfrmStateAlgo)
				resAlgo = state.Crypt
			}
			algo := nl.DeserializeXfrmAlgo(attr.Value[:])
			(*resAlgo).Name = nl.BytesToString(algo.AlgName[:])
			(*resAlgo).Key = algo.AlgKey
		case nl.XFRMA_ALG_AUTH_TRUNC:
			if state.Auth == nil {
				state.Auth = new(XfrmStateAlgo)
			}
			algo := nl.DeserializeXfrmAlgoAuth(attr.Value[:])
			state.Auth.Name = nl.BytesToString(algo.AlgName[:])
			state.Auth.Key = algo.AlgKey
			state.Auth.TruncateLen = int(algo.AlgTruncLen)
		case nl.XFRMA_ENCAP:
			encap := nl.DeserializeXfrmEncapTmpl(attr.Value[:])
			state.Encap = new(XfrmStateEncap)
			state.Encap.Type = EncapType(encap.EncapType)
			state.Encap.SrcPort = int(nl.Swap16(encap.EncapSport))
			state.Encap.DstPort = int(nl.Swap16(encap.EncapDport))
			state.Encap.OriginalAddress = encap.EncapOa.ToIP()
		case nl.XFRMA_MARK:
			mark := nl.DeserializeXfrmMark(attr.Value[:])
			state.Mark = new(XfrmMark)
			state.Mark.Value = mark.Value
			state.Mark.Mask = mark.Mask
		}
	}

	return &state, nil
}
