package netlink

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// NOTE function is here because it uses other linux functions
func NewNetem(attrs QdiscAttrs, nattrs NetemQdiscAttrs) *Netem {
	var limit uint32 = 1000
	var lossCorr, delayCorr, duplicateCorr uint32
	var reorderProb, reorderCorr uint32
	var corruptProb, corruptCorr uint32
	var rate64 uint64

	latency := nattrs.Latency
	loss := Percentage2u32(nattrs.Loss)
	gap := nattrs.Gap
	duplicate := Percentage2u32(nattrs.Duplicate)
	jitter := nattrs.Jitter

	// Correlation
	if latency > 0 && jitter > 0 {
		delayCorr = Percentage2u32(nattrs.DelayCorr)
	}
	if loss > 0 {
		lossCorr = Percentage2u32(nattrs.LossCorr)
	}
	if duplicate > 0 {
		duplicateCorr = Percentage2u32(nattrs.DuplicateCorr)
	}
	// FIXME should validate values(like loss/duplicate are percentages...)
	latency = time2Tick(latency)

	if nattrs.Limit != 0 {
		limit = nattrs.Limit
	}
	// Jitter is only value if latency is > 0
	if latency > 0 {
		jitter = time2Tick(jitter)
	}

	reorderProb = Percentage2u32(nattrs.ReorderProb)
	reorderCorr = Percentage2u32(nattrs.ReorderCorr)

	if reorderProb > 0 {
		// ERROR if lantency == 0
		if gap == 0 {
			gap = 1
		}
	}

	corruptProb = Percentage2u32(nattrs.CorruptProb)
	corruptCorr = Percentage2u32(nattrs.CorruptCorr)
	rate64 = nattrs.Rate64

	return &Netem{
		QdiscAttrs:    attrs,
		Latency:       latency,
		DelayCorr:     delayCorr,
		Limit:         limit,
		Loss:          loss,
		LossCorr:      lossCorr,
		Gap:           gap,
		Duplicate:     duplicate,
		DuplicateCorr: duplicateCorr,
		Jitter:        jitter,
		ReorderProb:   reorderProb,
		ReorderCorr:   reorderCorr,
		CorruptProb:   corruptProb,
		CorruptCorr:   corruptCorr,
		Rate64:        rate64,
	}
}

// QdiscDel will delete a qdisc from the system.
// Equivalent to: `tc qdisc del $qdisc`
func QdiscDel(qdisc Qdisc) error {
	return pkgHandle.QdiscDel(qdisc)
}

// QdiscDel will delete a qdisc from the system.
// Equivalent to: `tc qdisc del $qdisc`
func (h *Handle) QdiscDel(qdisc Qdisc) error {
	return h.qdiscModify(unix.RTM_DELQDISC, 0, qdisc)
}

// QdiscChange will change a qdisc in place
// Equivalent to: `tc qdisc change $qdisc`
// The parent and handle MUST NOT be changed.
func QdiscChange(qdisc Qdisc) error {
	return pkgHandle.QdiscChange(qdisc)
}

// QdiscChange will change a qdisc in place
// Equivalent to: `tc qdisc change $qdisc`
// The parent and handle MUST NOT be changed.
func (h *Handle) QdiscChange(qdisc Qdisc) error {
	return h.qdiscModify(unix.RTM_NEWQDISC, 0, qdisc)
}

// QdiscReplace will replace a qdisc to the system.
// Equivalent to: `tc qdisc replace $qdisc`
// The handle MUST change.
func QdiscReplace(qdisc Qdisc) error {
	return pkgHandle.QdiscReplace(qdisc)
}

// QdiscReplace will replace a qdisc to the system.
// Equivalent to: `tc qdisc replace $qdisc`
// The handle MUST change.
func (h *Handle) QdiscReplace(qdisc Qdisc) error {
	return h.qdiscModify(
		unix.RTM_NEWQDISC,
		unix.NLM_F_CREATE|unix.NLM_F_REPLACE,
		qdisc)
}

// QdiscAdd will add a qdisc to the system.
// Equivalent to: `tc qdisc add $qdisc`
func QdiscAdd(qdisc Qdisc) error {
	return pkgHandle.QdiscAdd(qdisc)
}

// QdiscAdd will add a qdisc to the system.
// Equivalent to: `tc qdisc add $qdisc`
func (h *Handle) QdiscAdd(qdisc Qdisc) error {
	return h.qdiscModify(
		unix.RTM_NEWQDISC,
		unix.NLM_F_CREATE|unix.NLM_F_EXCL,
		qdisc)
}

func (h *Handle) qdiscModify(cmd, flags int, qdisc Qdisc) error {
	req := h.newNetlinkRequest(cmd, flags|unix.NLM_F_ACK)
	base := qdisc.Attrs()
	msg := &nl.TcMsg{
		Family:  nl.FAMILY_ALL,
		Ifindex: int32(base.LinkIndex),
		Handle:  base.Handle,
		Parent:  base.Parent,
	}
	req.AddData(msg)

	// When deleting don't bother building the rest of the netlink payload
	if cmd != unix.RTM_DELQDISC {
		if err := qdiscPayload(req, qdisc); err != nil {
			return err
		}
	}

	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func qdiscPayload(req *nl.NetlinkRequest, qdisc Qdisc) error {

	req.AddData(nl.NewRtAttr(nl.TCA_KIND, nl.ZeroTerminated(qdisc.Type())))
	if qdisc.Attrs().IngressBlock != nil {
		req.AddData(nl.NewRtAttr(nl.TCA_INGRESS_BLOCK, nl.Uint32Attr(*qdisc.Attrs().IngressBlock)))
	}

	options := nl.NewRtAttr(nl.TCA_OPTIONS, nil)

	switch qdisc := qdisc.(type) {
	case *Prio:
		tcmap := nl.TcPrioMap{
			Bands:   int32(qdisc.Bands),
			Priomap: qdisc.PriorityMap,
		}
		options = nl.NewRtAttr(nl.TCA_OPTIONS, tcmap.Serialize())
	case *Tbf:
		if qdisc.Linklayer == nl.LINKLAYER_UNSPEC {
			qdisc.Linklayer = nl.LINKLAYER_ETHERNET
		}
		opt := nl.TcTbfQopt{}
		opt.Limit = qdisc.Limit
		if opt.Limit == 0 {
			return fmt.Errorf("tbf: Limit is required")
		}
		if qdisc.Rate >= uint64(1<<32) {
			opt.Rate.Rate = ^uint32(0)
			options.AddRtAttr(nl.TCA_TBF_RATE64, nl.Uint64Attr(qdisc.Rate))
		} else {
			opt.Rate.Rate = uint32(qdisc.Rate)
		}
		if qdisc.Peakrate >= uint64(1<<32) {
			opt.Peakrate.Rate = ^uint32(0)
			options.AddRtAttr(nl.TCA_TBF_PRATE64, nl.Uint64Attr(qdisc.Peakrate))
		} else {
			opt.Peakrate.Rate = uint32(qdisc.Peakrate)
		}
		options.AddRtAttr(nl.TCA_TBF_BURST, nl.Uint32Attr(qdisc.Burst))
		opt.Buffer = Xmittime(uint64(opt.Rate.Rate), qdisc.Burst)
		opt.Rate.Mpu = qdisc.Mpu
		opt.Rate.Overhead = qdisc.Overhead
		rtab, err := calcTbfRtable(&opt.Rate, qdisc.Minburst, qdisc.BurstCell, qdisc.Linklayer)
		if err != nil {
			return err
		}
		options.AddRtAttr(nl.TCA_TBF_RTAB, rtab[0:])
		if opt.Peakrate.Rate > 0 {
			options.AddRtAttr(nl.TCA_TBF_PBURST, nl.Uint32Attr(qdisc.Minburst))
			opt.Mtu = Xmittime(uint64(opt.Peakrate.Rate), qdisc.Minburst)
			opt.Peakrate.Mpu = qdisc.Mpu
			opt.Peakrate.Overhead = qdisc.Overhead
			ptab, err := calcTbfRtable(&opt.Peakrate, qdisc.Minburst, qdisc.MinburstCell, qdisc.Linklayer)
			if err != nil {
				return err
			}
			options.AddRtAttr(nl.TCA_TBF_PTAB, ptab[0:])
		}
		options.AddRtAttr(nl.TCA_TBF_PARMS, opt.Serialize())
	case *Htb:
		opt := nl.TcHtbGlob{}
		opt.Version = qdisc.Version
		opt.Rate2Quantum = qdisc.Rate2Quantum
		opt.Defcls = qdisc.Defcls
		// TODO: Handle Debug properly. For now default to 0
		opt.Debug = qdisc.Debug
		opt.DirectPkts = qdisc.DirectPkts
		options.AddRtAttr(nl.TCA_HTB_INIT, opt.Serialize())
		if qdisc.DirectQlen != nil {
			options.AddRtAttr(nl.TCA_HTB_DIRECT_QLEN, nl.Uint32Attr(*qdisc.DirectQlen))
		}
	case *Hfsc:
		opt := nl.TcHfscOpt{}
		opt.Defcls = qdisc.Defcls
		options = nl.NewRtAttr(nl.TCA_OPTIONS, opt.Serialize())
	case *Netem:
		opt := nl.TcNetemQopt{}
		opt.Latency = qdisc.Latency
		opt.Limit = qdisc.Limit
		opt.Loss = qdisc.Loss
		opt.Gap = qdisc.Gap
		opt.Duplicate = qdisc.Duplicate
		opt.Jitter = qdisc.Jitter
		options = nl.NewRtAttr(nl.TCA_OPTIONS, opt.Serialize())
		// Correlation
		corr := nl.TcNetemCorr{}
		corr.DelayCorr = qdisc.DelayCorr
		corr.LossCorr = qdisc.LossCorr
		corr.DupCorr = qdisc.DuplicateCorr

		if corr.DelayCorr > 0 || corr.LossCorr > 0 || corr.DupCorr > 0 {
			options.AddRtAttr(nl.TCA_NETEM_CORR, corr.Serialize())
		}
		// Corruption
		corruption := nl.TcNetemCorrupt{}
		corruption.Probability = qdisc.CorruptProb
		corruption.Correlation = qdisc.CorruptCorr
		if corruption.Probability > 0 {
			options.AddRtAttr(nl.TCA_NETEM_CORRUPT, corruption.Serialize())
		}
		// Reorder
		reorder := nl.TcNetemReorder{}
		reorder.Probability = qdisc.ReorderProb
		reorder.Correlation = qdisc.ReorderCorr
		if reorder.Probability > 0 {
			options.AddRtAttr(nl.TCA_NETEM_REORDER, reorder.Serialize())
		}
		// Rate
		if qdisc.Rate64 > 0 {
			rate := nl.TcNetemRate{}
			if qdisc.Rate64 >= uint64(1<<32) {
				options.AddRtAttr(nl.TCA_NETEM_RATE64, nl.Uint64Attr(qdisc.Rate64))
				rate.Rate = ^uint32(0)
			} else {
				rate.Rate = uint32(qdisc.Rate64)
			}
			options.AddRtAttr(nl.TCA_NETEM_RATE, rate.Serialize())
		}
	case *Clsact:
		options = nil
	case *Ingress:
		// ingress filters must use the proper handle
		if qdisc.Attrs().Parent != HANDLE_INGRESS {
			return fmt.Errorf("Ingress filters must set Parent to HANDLE_INGRESS")
		}
	case *FqCodel:
		options.AddRtAttr(nl.TCA_FQ_CODEL_ECN, nl.Uint32Attr((uint32(qdisc.ECN))))
		if qdisc.Limit > 0 {
			options.AddRtAttr(nl.TCA_FQ_CODEL_LIMIT, nl.Uint32Attr((uint32(qdisc.Limit))))
		}
		if qdisc.Interval > 0 {
			options.AddRtAttr(nl.TCA_FQ_CODEL_INTERVAL, nl.Uint32Attr((uint32(qdisc.Interval))))
		}
		if qdisc.Flows > 0 {
			options.AddRtAttr(nl.TCA_FQ_CODEL_FLOWS, nl.Uint32Attr((uint32(qdisc.Flows))))
		}
		if qdisc.Quantum > 0 {
			options.AddRtAttr(nl.TCA_FQ_CODEL_QUANTUM, nl.Uint32Attr((uint32(qdisc.Quantum))))
		}
		if qdisc.CEThreshold > 0 {
			options.AddRtAttr(nl.TCA_FQ_CODEL_CE_THRESHOLD, nl.Uint32Attr(qdisc.CEThreshold))
		}
		if qdisc.DropBatchSize > 0 {
			options.AddRtAttr(nl.TCA_FQ_CODEL_DROP_BATCH_SIZE, nl.Uint32Attr(qdisc.DropBatchSize))
		}
		if qdisc.MemoryLimit > 0 {
			options.AddRtAttr(nl.TCA_FQ_CODEL_MEMORY_LIMIT, nl.Uint32Attr(qdisc.MemoryLimit))
		}
	case *Fq:
		options.AddRtAttr(nl.TCA_FQ_RATE_ENABLE, nl.Uint32Attr((uint32(qdisc.Pacing))))

		if qdisc.Buckets > 0 {
			options.AddRtAttr(nl.TCA_FQ_BUCKETS_LOG, nl.Uint32Attr((uint32(qdisc.Buckets))))
		}
		if qdisc.PacketLimit > 0 {
			options.AddRtAttr(nl.TCA_FQ_PLIMIT, nl.Uint32Attr((uint32(qdisc.PacketLimit))))
		}
		if qdisc.LowRateThreshold > 0 {
			options.AddRtAttr(nl.TCA_FQ_LOW_RATE_THRESHOLD, nl.Uint32Attr((uint32(qdisc.LowRateThreshold))))
		}
		if qdisc.Quantum > 0 {
			options.AddRtAttr(nl.TCA_FQ_QUANTUM, nl.Uint32Attr((uint32(qdisc.Quantum))))
		}
		if qdisc.InitialQuantum > 0 {
			options.AddRtAttr(nl.TCA_FQ_INITIAL_QUANTUM, nl.Uint32Attr((uint32(qdisc.InitialQuantum))))
		}
		if qdisc.FlowRefillDelay > 0 {
			options.AddRtAttr(nl.TCA_FQ_FLOW_REFILL_DELAY, nl.Uint32Attr((uint32(qdisc.FlowRefillDelay))))
		}
		if qdisc.FlowPacketLimit > 0 {
			options.AddRtAttr(nl.TCA_FQ_FLOW_PLIMIT, nl.Uint32Attr((uint32(qdisc.FlowPacketLimit))))
		}
		if qdisc.FlowMaxRate > 0 {
			options.AddRtAttr(nl.TCA_FQ_FLOW_MAX_RATE, nl.Uint32Attr((uint32(qdisc.FlowMaxRate))))
		}
		if qdisc.FlowDefaultRate > 0 {
			options.AddRtAttr(nl.TCA_FQ_FLOW_DEFAULT_RATE, nl.Uint32Attr((uint32(qdisc.FlowDefaultRate))))
		}
		if qdisc.Horizon > 0 {
			options.AddRtAttr(nl.TCA_FQ_HORIZON, nl.Uint32Attr(qdisc.Horizon))
		}
		if qdisc.HorizonDropPolicy != HORIZON_DROP_POLICY_DEFAULT {
			options.AddRtAttr(nl.TCA_FQ_HORIZON_DROP, nl.Uint8Attr(qdisc.HorizonDropPolicy))
		}
	case *Sfq:
		opt := nl.TcSfqQoptV1{}
		opt.TcSfqQopt.Quantum = qdisc.Quantum
		opt.TcSfqQopt.Perturb = qdisc.Perturb
		opt.TcSfqQopt.Limit = qdisc.Limit
		opt.TcSfqQopt.Divisor = qdisc.Divisor

		options = nl.NewRtAttr(nl.TCA_OPTIONS, opt.Serialize())
	default:
		options = nil
	}

	if options != nil {
		req.AddData(options)
	}
	return nil
}

// QdiscList gets a list of qdiscs in the system.
// Equivalent to: `tc qdisc show`.
// The list can be filtered by link.
//
// If the returned error is [ErrDumpInterrupted], results may be inconsistent
// or incomplete.
func QdiscList(link Link) ([]Qdisc, error) {
	return pkgHandle.QdiscList(link)
}

// QdiscList gets a list of qdiscs in the system.
// Equivalent to: `tc qdisc show`.
// The list can be filtered by link.
//
// If the returned error is [ErrDumpInterrupted], results may be inconsistent
// or incomplete.
func (h *Handle) QdiscList(link Link) ([]Qdisc, error) {
	req := h.newNetlinkRequest(unix.RTM_GETQDISC, unix.NLM_F_DUMP)
	index := int32(0)
	if link != nil {
		base := link.Attrs()
		h.ensureIndex(base)
		index = int32(base.Index)
	}
	msg := &nl.TcMsg{
		Family:  nl.FAMILY_ALL,
		Ifindex: index,
	}
	req.AddData(msg)

	msgs, executeErr := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWQDISC)
	if executeErr != nil && !errors.Is(executeErr, ErrDumpInterrupted) {
		return nil, executeErr
	}

	var res []Qdisc
	for _, m := range msgs {
		msg := nl.DeserializeTcMsg(m)

		attrs, err := nl.ParseRouteAttr(m[msg.Len():])
		if err != nil {
			return nil, err
		}

		// skip qdiscs from other interfaces
		if link != nil && msg.Ifindex != index {
			continue
		}

		base := QdiscAttrs{
			LinkIndex: int(msg.Ifindex),
			Handle:    msg.Handle,
			Parent:    msg.Parent,
			Refcnt:    msg.Info,
		}
		var qdisc Qdisc
		qdiscType := ""
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case nl.TCA_KIND:
				qdiscType = string(attr.Value[:len(attr.Value)-1])
				switch qdiscType {
				case "pfifo_fast":
					qdisc = &PfifoFast{}
				case "prio":
					qdisc = &Prio{}
				case "tbf":
					qdisc = &Tbf{}
				case "ingress":
					qdisc = &Ingress{}
				case "htb":
					qdisc = &Htb{}
				case "fq":
					qdisc = &Fq{}
				case "hfsc":
					qdisc = &Hfsc{}
				case "fq_codel":
					qdisc = &FqCodel{}
				case "netem":
					qdisc = &Netem{}
				case "sfq":
					qdisc = &Sfq{}
				case "clsact":
					qdisc = &Clsact{}
				default:
					qdisc = &GenericQdisc{QdiscType: qdiscType}
				}
			case nl.TCA_OPTIONS:
				switch qdiscType {
				case "pfifo_fast":
					// pfifo returns TcPrioMap directly without wrapping it in rtattr
					if err := parsePfifoFastData(qdisc, attr.Value); err != nil {
						return nil, err
					}
				case "prio":
					// prio returns TcPrioMap directly without wrapping it in rtattr
					if err := parsePrioData(qdisc, attr.Value); err != nil {
						return nil, err
					}
				case "tbf":
					data, err := nl.ParseRouteAttr(attr.Value)
					if err != nil {
						return nil, err
					}
					if err := parseTbfData(qdisc, data); err != nil {
						return nil, err
					}
				case "hfsc":
					if err := parseHfscData(qdisc, attr.Value); err != nil {
						return nil, err
					}
				case "htb":
					data, err := nl.ParseRouteAttr(attr.Value)
					if err != nil {
						return nil, err
					}
					if err := parseHtbData(qdisc, data); err != nil {
						return nil, err
					}
				case "fq":
					data, err := nl.ParseRouteAttr(attr.Value)
					if err != nil {
						return nil, err
					}
					if err := parseFqData(qdisc, data); err != nil {
						return nil, err
					}
				case "fq_codel":
					data, err := nl.ParseRouteAttr(attr.Value)
					if err != nil {
						return nil, err
					}
					if err := parseFqCodelData(qdisc, data); err != nil {
						return nil, err
					}
				case "netem":
					if err := parseNetemData(qdisc, attr.Value); err != nil {
						return nil, err
					}
				case "sfq":
					if err := parseSfqData(qdisc, attr.Value); err != nil {
						return nil, err
					}

					// no options for ingress
				}
			case nl.TCA_INGRESS_BLOCK:
				ingressBlock := new(uint32)
				*ingressBlock = native.Uint32(attr.Value)
				base.IngressBlock = ingressBlock
			case nl.TCA_STATS:
				s, err := parseTcStats(attr.Value)
				if err != nil {
					return nil, err
				}
				base.Statistics = (*QdiscStatistics)(s)
			case nl.TCA_STATS2:
				s, err := parseTcStats2(attr.Value)
				if err != nil {
					return nil, err
				}
				base.Statistics = (*QdiscStatistics)(s)
			}
		}
		*qdisc.Attrs() = base
		res = append(res, qdisc)
	}

	return res, executeErr
}

func parsePfifoFastData(qdisc Qdisc, value []byte) error {
	pfifo := qdisc.(*PfifoFast)
	tcmap := nl.DeserializeTcPrioMap(value)
	pfifo.PriorityMap = tcmap.Priomap
	pfifo.Bands = uint8(tcmap.Bands)
	return nil
}

func parsePrioData(qdisc Qdisc, value []byte) error {
	prio := qdisc.(*Prio)
	tcmap := nl.DeserializeTcPrioMap(value)
	prio.PriorityMap = tcmap.Priomap
	prio.Bands = uint8(tcmap.Bands)
	return nil
}

func parseHtbData(qdisc Qdisc, data []syscall.NetlinkRouteAttr) error {
	htb := qdisc.(*Htb)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.TCA_HTB_INIT:
			opt := nl.DeserializeTcHtbGlob(datum.Value)
			htb.Version = opt.Version
			htb.Rate2Quantum = opt.Rate2Quantum
			htb.Defcls = opt.Defcls
			htb.Debug = opt.Debug
			htb.DirectPkts = opt.DirectPkts
		case nl.TCA_HTB_DIRECT_QLEN:
			directQlen := native.Uint32(datum.Value)
			htb.DirectQlen = &directQlen
		}
	}
	return nil
}

func parseFqCodelData(qdisc Qdisc, data []syscall.NetlinkRouteAttr) error {
	fqCodel := qdisc.(*FqCodel)
	for _, datum := range data {

		switch datum.Attr.Type {
		case nl.TCA_FQ_CODEL_TARGET:
			fqCodel.Target = native.Uint32(datum.Value)
		case nl.TCA_FQ_CODEL_LIMIT:
			fqCodel.Limit = native.Uint32(datum.Value)
		case nl.TCA_FQ_CODEL_INTERVAL:
			fqCodel.Interval = native.Uint32(datum.Value)
		case nl.TCA_FQ_CODEL_ECN:
			fqCodel.ECN = native.Uint32(datum.Value)
		case nl.TCA_FQ_CODEL_FLOWS:
			fqCodel.Flows = native.Uint32(datum.Value)
		case nl.TCA_FQ_CODEL_QUANTUM:
			fqCodel.Quantum = native.Uint32(datum.Value)
		case nl.TCA_FQ_CODEL_CE_THRESHOLD:
			fqCodel.CEThreshold = native.Uint32(datum.Value)
		case nl.TCA_FQ_CODEL_DROP_BATCH_SIZE:
			fqCodel.DropBatchSize = native.Uint32(datum.Value)
		case nl.TCA_FQ_CODEL_MEMORY_LIMIT:
			fqCodel.MemoryLimit = native.Uint32(datum.Value)
		}
	}
	return nil
}

func parseHfscData(qdisc Qdisc, data []byte) error {
	Hfsc := qdisc.(*Hfsc)
	Hfsc.Defcls = native.Uint16(data)
	return nil
}

func parseFqData(qdisc Qdisc, data []syscall.NetlinkRouteAttr) error {
	fq := qdisc.(*Fq)
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.TCA_FQ_BUCKETS_LOG:
			fq.Buckets = native.Uint32(datum.Value)
		case nl.TCA_FQ_LOW_RATE_THRESHOLD:
			fq.LowRateThreshold = native.Uint32(datum.Value)
		case nl.TCA_FQ_QUANTUM:
			fq.Quantum = native.Uint32(datum.Value)
		case nl.TCA_FQ_RATE_ENABLE:
			fq.Pacing = native.Uint32(datum.Value)
		case nl.TCA_FQ_INITIAL_QUANTUM:
			fq.InitialQuantum = native.Uint32(datum.Value)
		case nl.TCA_FQ_ORPHAN_MASK:
			// TODO
		case nl.TCA_FQ_FLOW_REFILL_DELAY:
			fq.FlowRefillDelay = native.Uint32(datum.Value)
		case nl.TCA_FQ_FLOW_PLIMIT:
			fq.FlowPacketLimit = native.Uint32(datum.Value)
		case nl.TCA_FQ_PLIMIT:
			fq.PacketLimit = native.Uint32(datum.Value)
		case nl.TCA_FQ_FLOW_MAX_RATE:
			fq.FlowMaxRate = native.Uint32(datum.Value)
		case nl.TCA_FQ_FLOW_DEFAULT_RATE:
			fq.FlowDefaultRate = native.Uint32(datum.Value)
		case nl.TCA_FQ_HORIZON:
			fq.Horizon = native.Uint32(datum.Value)
		case nl.TCA_FQ_HORIZON_DROP:
			fq.HorizonDropPolicy = datum.Value[0]

		}
	}
	return nil
}

func parseNetemData(qdisc Qdisc, value []byte) error {
	netem := qdisc.(*Netem)
	opt := nl.DeserializeTcNetemQopt(value)
	netem.Latency = opt.Latency
	netem.Limit = opt.Limit
	netem.Loss = opt.Loss
	netem.Gap = opt.Gap
	netem.Duplicate = opt.Duplicate
	netem.Jitter = opt.Jitter
	data, err := nl.ParseRouteAttr(value[nl.SizeofTcNetemQopt:])
	if err != nil {
		return err
	}
	var rate *nl.TcNetemRate
	var rate64 uint64
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.TCA_NETEM_CORR:
			opt := nl.DeserializeTcNetemCorr(datum.Value)
			netem.DelayCorr = opt.DelayCorr
			netem.LossCorr = opt.LossCorr
			netem.DuplicateCorr = opt.DupCorr
		case nl.TCA_NETEM_CORRUPT:
			opt := nl.DeserializeTcNetemCorrupt(datum.Value)
			netem.CorruptProb = opt.Probability
			netem.CorruptCorr = opt.Correlation
		case nl.TCA_NETEM_REORDER:
			opt := nl.DeserializeTcNetemReorder(datum.Value)
			netem.ReorderProb = opt.Probability
			netem.ReorderCorr = opt.Correlation
		case nl.TCA_NETEM_RATE:
			rate = nl.DeserializeTcNetemRate(datum.Value)
		case nl.TCA_NETEM_RATE64:
			rate64 = native.Uint64(datum.Value)
		}
	}
	if rate != nil {
		netem.Rate64 = uint64(rate.Rate)
		if rate64 > 0 {
			netem.Rate64 = rate64
		}
	}

	return nil
}

func calcTbfRtable(rate *nl.TcRateSpec, mtu uint32, cell uint32, linklayer int) ([1024]byte, error) {
	bps := rate.Rate
	mpu := rate.Mpu
	var sz uint
	var i uint32
	var token uint32
	var cellLog uint32
	var rtab [256]uint32
	var byteTab [1024]byte
	var mtuToken uint32

	if mtu == 0 {
		mtu = 2047
	}
	mtuToken = Xmittime(uint64(bps), mtu)
	if cell > 0 {
		_cellLog := -1
		for i = 0; i < 32; i++ {
			if (1 << i) == cell {
				_cellLog = int(i)
				break
			}
		}
		if _cellLog == -1 {
			return byteTab, fmt.Errorf("invalid cell value %d", cell)
		}
		cellLog = uint32(_cellLog)
	} else {
		cellLog = 0
		for mtu>>cellLog > 255 {
			cellLog++
		}
	}
	for {
		for i = 0; i < 256; i++ {
			sz = AdjustSize(uint((i+1)<<uint32(cellLog)), uint(mpu), linklayer)
			token = Xmittime(uint64(bps), uint32(sz))
			rtab[i] = token
			native.PutUint32(byteTab[i<<2:i<<2+4], token)
		}
		// avoid "max_size" bug
		// from https://github.com/torvalds/linux/commit/b757c9336d63f94c6b57532bb4e8651d8b28786f
		// end  https://github.com/torvalds/linux/commit/cc106e441a63bec3b1cb72948df82ea15945c449
		if cellLog > 0 {
			for i = 0; i < 256; i++ {
				if rtab[i] > mtuToken {
					break
				}
			}
			maxSize := i<<cellLog - 1
			maxSizeToken := Xmittime(uint64(bps), maxSize)
			if maxSizeToken >= mtuToken {
				cellLog--
			} else {
				break
			}
		}
	}
	rate.CellAlign = -1
	rate.CellLog = uint8(cellLog)
	rate.Linklayer = uint8(linklayer & nl.TC_LINKLAYER_MASK)
	return byteTab, nil
}

func parseTbfData(qdisc Qdisc, data []syscall.NetlinkRouteAttr) error {
	tbf := qdisc.(*Tbf)
	rate64 := uint64(0)
	prate64 := uint64(0)
	var opt *nl.TcTbfQopt
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.TCA_TBF_PARMS:
			opt = nl.DeserializeTcTbfQopt(datum.Value)
		case nl.TCA_TBF_RATE64:
			rate64 = native.Uint64(datum.Value[0:8])
		case nl.TCA_TBF_PRATE64:
			prate64 = native.Uint64(datum.Value[0:8])
		}
	}
	tbf.Limit = opt.Limit
	if rate64 > 0 {
		tbf.Rate = rate64
	} else {
		tbf.Rate = uint64(opt.Rate.Rate)
	}
	if prate64 > 0 {
		tbf.Peakrate = prate64
	} else {
		tbf.Peakrate = uint64(opt.Peakrate.Rate)
	}
	tbf.Burst = Xmitsize(tbf.Rate, opt.Buffer)
	tbf.BurstCell = 1 << opt.Rate.CellLog
	if tbf.Peakrate > 0 {
		tbf.Minburst = Xmitsize(tbf.Peakrate, opt.Mtu)
		tbf.MinburstCell = 1 << opt.Peakrate.CellLog
	}
	tbf.Mpu = opt.Rate.Mpu
	tbf.Overhead = opt.Rate.Overhead
	tbf.Linklayer = int(opt.Rate.Linklayer & nl.TC_LINKLAYER_MASK)
	return nil
}

func parseSfqData(qdisc Qdisc, value []byte) error {
	sfq := qdisc.(*Sfq)
	opt := nl.DeserializeTcSfqQoptV1(value)
	sfq.Quantum = opt.TcSfqQopt.Quantum
	sfq.Perturb = opt.TcSfqQopt.Perturb
	sfq.Limit = opt.TcSfqQopt.Limit
	sfq.Divisor = opt.TcSfqQopt.Divisor

	return nil
}

const (
	TIME_UNITS_PER_SEC = 1000000
)

var (
	tickInUsec  float64
	clockFactor float64
	hz          float64

	// Without this, the go race detector may report races.
	initClockMutex sync.Mutex
)

func initClock() {
	data, err := ioutil.ReadFile("/proc/net/psched")
	if err != nil {
		return
	}
	parts := strings.Split(strings.TrimSpace(string(data)), " ")
	if len(parts) < 4 {
		return
	}
	var vals [4]uint64
	for i := range vals {
		val, err := strconv.ParseUint(parts[i], 16, 32)
		if err != nil {
			return
		}
		vals[i] = val
	}
	// compatibility
	if vals[2] == 1000000000 {
		vals[0] = vals[1]
	}
	clockFactor = float64(vals[2]) / TIME_UNITS_PER_SEC
	tickInUsec = float64(vals[0]) / float64(vals[1]) * clockFactor
	if vals[2] == 1000000 {
		// ref https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/lib/utils.c#n963
		hz = float64(vals[3])
	} else {
		hz = 100
	}
}

func TickInUsec() float64 {
	initClockMutex.Lock()
	defer initClockMutex.Unlock()
	if tickInUsec == 0.0 {
		initClock()
	}
	return tickInUsec
}

func ClockFactor() float64 {
	initClockMutex.Lock()
	defer initClockMutex.Unlock()
	if clockFactor == 0.0 {
		initClock()
	}
	return clockFactor
}

func Hz() float64 {
	initClockMutex.Lock()
	defer initClockMutex.Unlock()
	if hz == 0.0 {
		initClock()
	}
	return hz
}

func time2Tick(time uint32) uint32 {
	return uint32(float64(time) * TickInUsec())
}

func tick2Time(tick uint32) uint32 {
	return uint32(float64(tick) / TickInUsec())
}

func time2Ktime(time uint32) uint32 {
	return uint32(float64(time) * ClockFactor())
}

func ktime2Time(ktime uint32) uint32 {
	return uint32(float64(ktime) / ClockFactor())
}

func burst(rate uint64, buffer uint32) uint32 {
	return uint32(float64(rate) * float64(tick2Time(buffer)) / TIME_UNITS_PER_SEC)
}

func latency(rate uint64, limit, buffer uint32) float64 {
	return TIME_UNITS_PER_SEC*(float64(limit)/float64(rate)) - float64(tick2Time(buffer))
}

func Xmittime(rate uint64, size uint32) uint32 {
	// https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/tc/tc_core.c#n62
	return time2Tick(uint32(TIME_UNITS_PER_SEC * (float64(size) / float64(rate))))
}

func Xmitsize(rate uint64, ticks uint32) uint32 {
	return uint32((float64(rate) * float64(tick2Time(ticks))) / TIME_UNITS_PER_SEC)
}
