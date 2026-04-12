//go:build linux
// +build linux

package netlink

import (
	"math"
	"testing"
)

func TestTbfAddDel(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	qdisc := &Tbf{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(1, 0),
			Parent:    HANDLE_ROOT,
		},
		Rate:   131072,
		Limit:  1220703,
		Buffer: 16793,
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	tbf, ok := qdiscs[0].(*Tbf)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	if tbf.Rate != qdisc.Rate {
		t.Fatal("Rate doesn't match")
	}
	if tbf.Limit != qdisc.Limit {
		t.Fatal("Limit doesn't match")
	}
	if tbf.Buffer != qdisc.Buffer {
		t.Fatal("Buffer doesn't match")
	}
	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestHtbAddDel(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	attrs := QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    MakeHandle(1, 0),
		Parent:    HANDLE_ROOT,
	}

	qdisc := NewHtb(attrs)
	qdisc.Rate2Quantum = 5
	directQlen := uint32(10)
	qdisc.DirectQlen = &directQlen
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}

	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	htb, ok := qdiscs[0].(*Htb)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	if htb.Defcls != qdisc.Defcls {
		t.Fatal("Defcls doesn't match")
	}
	if htb.Rate2Quantum != qdisc.Rate2Quantum {
		t.Fatal("Rate2Quantum doesn't match")
	}
	if htb.Debug != qdisc.Debug {
		t.Fatal("Debug doesn't match")
	}
	if htb.DirectQlen == nil || *htb.DirectQlen != directQlen {
		t.Fatalf("DirectQlen doesn't match. Expected %d, got %v", directQlen, htb.DirectQlen)
	}
	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestSfqAddDel(t *testing.T) {
	t.Cleanup(setUpNetlinkTestWithKModule(t, "sch_sfq"))
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	attrs := QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    MakeHandle(1, 0),
		Parent:    HANDLE_ROOT,
	}

	qdisc := Sfq{
		QdiscAttrs: attrs,
		Quantum:    2,
		Perturb:    11,
		Limit:      123,
		Divisor:    4,
	}
	if err := QdiscAdd(&qdisc); err != nil {
		t.Fatal(err)
	}

	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	sfq, ok := qdiscs[0].(*Sfq)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	if sfq.Quantum != qdisc.Quantum {
		t.Fatal("Quantum doesn't match")
	}
	if sfq.Perturb != qdisc.Perturb {
		t.Fatal("Perturb doesn't match")
	}
	if sfq.Limit != qdisc.Limit {
		t.Fatal("Limit doesn't match")
	}
	if sfq.Divisor != qdisc.Divisor {
		t.Fatal("Divisor doesn't match")
	}
	if err := QdiscDel(&qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestPrioAddDel(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	qdisc := NewPrio(QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    MakeHandle(1, 0),
		Parent:    HANDLE_ROOT,
	})
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	_, ok := qdiscs[0].(*Prio)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestTbfAddHtbReplaceDel(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// Add
	attrs := QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    MakeHandle(1, 0),
		Parent:    HANDLE_ROOT,
	}
	qdisc := &Tbf{
		QdiscAttrs: attrs,
		Rate:       131072,
		Limit:      1220703,
		Buffer:     16793,
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	tbf, ok := qdiscs[0].(*Tbf)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	if tbf.Rate != qdisc.Rate {
		t.Fatal("Rate doesn't match")
	}
	if tbf.Limit != qdisc.Limit {
		t.Fatal("Limit doesn't match")
	}
	if tbf.Buffer != qdisc.Buffer {
		t.Fatal("Buffer doesn't match")
	}
	// Replace
	// For replace to work, the handle MUST be different that the running one
	attrs.Handle = MakeHandle(2, 0)
	qdisc2 := NewHtb(attrs)
	qdisc2.Rate2Quantum = 5
	if err := QdiscReplace(qdisc2); err != nil {
		t.Fatal(err)
	}

	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	htb, ok := qdiscs[0].(*Htb)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	if htb.Defcls != qdisc2.Defcls {
		t.Fatal("Defcls doesn't match")
	}
	if htb.Rate2Quantum != qdisc2.Rate2Quantum {
		t.Fatal("Rate2Quantum doesn't match")
	}
	if htb.Debug != qdisc2.Debug {
		t.Fatal("Debug doesn't match")
	}

	if err := QdiscDel(qdisc2); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestTbfAddTbfChangeDel(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// Add
	attrs := QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    MakeHandle(1, 0),
		Parent:    HANDLE_ROOT,
	}
	qdisc := &Tbf{
		QdiscAttrs: attrs,
		Rate:       131072,
		Limit:      1220703,
		Buffer:     16793,
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	tbf, ok := qdiscs[0].(*Tbf)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	if tbf.Rate != qdisc.Rate {
		t.Fatal("Rate doesn't match")
	}
	if tbf.Limit != qdisc.Limit {
		t.Fatal("Limit doesn't match")
	}
	if tbf.Buffer != qdisc.Buffer {
		t.Fatal("Buffer doesn't match")
	}
	// Change
	// For change to work, the handle MUST not change
	qdisc.Rate = 23456
	if err := QdiscChange(qdisc); err != nil {
		t.Fatal(err)
	}

	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	tbf, ok = qdiscs[0].(*Tbf)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	if tbf.Rate != qdisc.Rate {
		t.Fatal("Rate doesn't match")
	}
	if tbf.Limit != qdisc.Limit {
		t.Fatal("Limit doesn't match")
	}
	if tbf.Buffer != qdisc.Buffer {
		t.Fatal("Buffer doesn't match")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFqAddChangeDel(t *testing.T) {
	minKernelRequired(t, 3, 11)

	t.Cleanup(setUpNetlinkTest(t))
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	qdisc := &Fq{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(1, 0),
			Parent:    HANDLE_ROOT,
		},
		FlowPacketLimit: 123,
		Pacing:          0,
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	fq, ok := qdiscs[0].(*Fq)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	if fq.FlowPacketLimit != qdisc.FlowPacketLimit {
		t.Fatal("Flow Packet Limit does not match")
	}
	if fq.Pacing != qdisc.Pacing {
		t.Fatal("Pacing does not match")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFqHorizon(t *testing.T) {
	minKernelRequired(t, 5, 7)

	t.Cleanup(setUpNetlinkTest(t))
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	qdisc := &Fq{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(1, 0),
			Parent:    HANDLE_ROOT,
		},
		Horizon:           1000,
		HorizonDropPolicy: HORIZON_DROP_POLICY_CAP,
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	fq, ok := qdiscs[0].(*Fq)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	if fq.Horizon != qdisc.Horizon {
		t.Fatal("Horizon does not match")
	}
	if fq.HorizonDropPolicy != qdisc.HorizonDropPolicy {
		t.Fatal("HorizonDropPolicy does not match")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFqCodelAddChangeDel(t *testing.T) {
	minKernelRequired(t, 3, 4)

	t.Cleanup(setUpNetlinkTest(t))
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	qdisc := &FqCodel{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(1, 0),
			Parent:    HANDLE_ROOT,
		},
		ECN:     1,
		Quantum: 9000,
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	fqcodel, ok := qdiscs[0].(*FqCodel)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	if fqcodel.Quantum != qdisc.Quantum {
		t.Fatal("Quantum does not match")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestIngressAddDel(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	ingressBlock := new(uint32)
	*ingressBlock = 8
	qdisc := &Ingress{
		QdiscAttrs: QdiscAttrs{
			LinkIndex:    link.Attrs().Index,
			Parent:       HANDLE_INGRESS,
			IngressBlock: ingressBlock,
		},
	}
	err = QdiscAdd(qdisc)
	if err != nil {
		t.Fatal("Failed to add qdisc")
	}
	qdiscs, err := SafeQdiscList(link)
	if err != nil {
		t.Fatal("Failed to list qdisc")
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	if *qdiscs[0].Attrs().IngressBlock != *ingressBlock {
		t.Fatal("IngressBlock does not match")
	}
	if qdiscs[0].Attrs().Statistics == nil {
		t.Fatal("Statistics is nil")
	}
	if qdiscs[0].Attrs().Statistics.Basic.Bytes != 0 || qdiscs[0].Attrs().Statistics.Basic.Packets != 0 {
		t.Fatal("Statistics is not zero")
	}
	if err = QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = SafeQdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

// Tests the round-trip conversion of Netem attributes to ensure
// human-readable values are correctly preserved (fixes #480).
func TestNetemQdiscAttrsRoundTrip(t *testing.T) {
	initClockMutex.Lock()
	oldTickInUsec := tickInUsec
	tickInUsec = 15.625
	initClockMutex.Unlock()
	defer func() {
		initClockMutex.Lock()
		tickInUsec = oldTickInUsec
		initClockMutex.Unlock()
	}()

	nattrs := NetemQdiscAttrs{
		Latency:       5000,
		DelayCorr:     12.5,
		Limit:         2048,
		Loss:          5.0,
		LossCorr:      9.5,
		Gap:           3,
		Duplicate:     4.0,
		DuplicateCorr: 7.0,
		Jitter:        1300,
		ReorderProb:   10.0,
		ReorderCorr:   11.0,
		CorruptProb:   3.0,
		CorruptCorr:   2.0,
		Rate64:        123456789,
	}
	netem := NewNetem(QdiscAttrs{}, nattrs)

	if netem.Latency != time2Tick(nattrs.Latency) {
		t.Fatalf("kernel-format latency mismatch: got %d, want %d", netem.Latency, time2Tick(nattrs.Latency))
	}
	if netem.DelayCorr != Percentage2u32(nattrs.DelayCorr) {
		t.Fatalf("kernel-format delayCorr mismatch: got %d, want %d", netem.DelayCorr, Percentage2u32(nattrs.DelayCorr))
	}
	if netem.Limit != nattrs.Limit {
		t.Fatalf("kernel-format limit mismatch: got %d, want %d", netem.Limit, nattrs.Limit)
	}
	if netem.Loss != Percentage2u32(nattrs.Loss) {
		t.Fatalf("kernel-format loss mismatch: got %d, want %d", netem.Loss, Percentage2u32(nattrs.Loss))
	}
	if netem.LossCorr != Percentage2u32(nattrs.LossCorr) {
		t.Fatalf("kernel-format lossCorr mismatch: got %d, want %d", netem.LossCorr, Percentage2u32(nattrs.LossCorr))
	}
	if netem.Gap != nattrs.Gap {
		t.Fatalf("kernel-format gap mismatch: got %d, want %d", netem.Gap, nattrs.Gap)
	}
	if netem.Duplicate != Percentage2u32(nattrs.Duplicate) {
		t.Fatalf("kernel-format duplicate mismatch: got %d, want %d", netem.Duplicate, Percentage2u32(nattrs.Duplicate))
	}
	if netem.DuplicateCorr != Percentage2u32(nattrs.DuplicateCorr) {
		t.Fatalf("kernel-format duplicateCorr mismatch: got %d, want %d", netem.DuplicateCorr, Percentage2u32(nattrs.DuplicateCorr))
	}
	if netem.Jitter != time2Tick(nattrs.Jitter) {
		t.Fatalf("kernel-format jitter mismatch: got %d, want %d", netem.Jitter, time2Tick(nattrs.Jitter))
	}
	if netem.ReorderProb != Percentage2u32(nattrs.ReorderProb) {
		t.Fatalf("kernel-format reorderProb mismatch: got %d, want %d", netem.ReorderProb, Percentage2u32(nattrs.ReorderProb))
	}
	if netem.ReorderCorr != Percentage2u32(nattrs.ReorderCorr) {
		t.Fatalf("kernel-format reorderCorr mismatch: got %d, want %d", netem.ReorderCorr, Percentage2u32(nattrs.ReorderCorr))
	}
	if netem.CorruptProb != Percentage2u32(nattrs.CorruptProb) {
		t.Fatalf("kernel-format corruptProb mismatch: got %d, want %d", netem.CorruptProb, Percentage2u32(nattrs.CorruptProb))
	}
	if netem.CorruptCorr != Percentage2u32(nattrs.CorruptCorr) {
		t.Fatalf("kernel-format corruptCorr mismatch: got %d, want %d", netem.CorruptCorr, Percentage2u32(nattrs.CorruptCorr))
	}
	if netem.Rate64 != nattrs.Rate64 {
		t.Fatalf("kernel-format rate64 mismatch: got %d, want %d", netem.Rate64, nattrs.Rate64)
	}

	human := netem.ToNetemQdiscAttrs()
	if human.Latency != tick2Time(time2Tick(nattrs.Latency)) {
		t.Fatalf("human-readable latency mismatch: got %d, want %d", human.Latency, tick2Time(time2Tick(nattrs.Latency)))
	}
	if math.Abs(float64(human.DelayCorr-nattrs.DelayCorr)) > 0.0001 {
		t.Fatalf("human-readable delayCorr mismatch: got %f, want %f", human.DelayCorr, nattrs.DelayCorr)
	}
	if human.Limit != nattrs.Limit {
		t.Fatalf("human-readable limit mismatch: got %d, want %d", human.Limit, nattrs.Limit)
	}
	if math.Abs(float64(human.Loss-nattrs.Loss)) > 0.0001 {
		t.Fatalf("human-readable loss mismatch: got %f, want %f", human.Loss, nattrs.Loss)
	}
	if math.Abs(float64(human.LossCorr-nattrs.LossCorr)) > 0.0001 {
		t.Fatalf("human-readable lossCorr mismatch: got %f, want %f", human.LossCorr, nattrs.LossCorr)
	}
	if human.Gap != nattrs.Gap {
		t.Fatalf("human-readable gap mismatch: got %d, want %d", human.Gap, nattrs.Gap)
	}
	if math.Abs(float64(human.Duplicate-nattrs.Duplicate)) > 0.0001 {
		t.Fatalf("human-readable duplicate mismatch: got %f, want %f", human.Duplicate, nattrs.Duplicate)
	}
	if math.Abs(float64(human.DuplicateCorr-nattrs.DuplicateCorr)) > 0.0001 {
		t.Fatalf("human-readable duplicateCorr mismatch: got %f, want %f", human.DuplicateCorr, nattrs.DuplicateCorr)
	}
	if human.Jitter != tick2Time(time2Tick(nattrs.Jitter)) {
		t.Fatalf("human-readable jitter mismatch: got %d, want %d", human.Jitter, tick2Time(time2Tick(nattrs.Jitter)))
	}
	if math.Abs(float64(human.ReorderProb-nattrs.ReorderProb)) > 0.0001 {
		t.Fatalf("human-readable reorderProb mismatch: got %f, want %f", human.ReorderProb, nattrs.ReorderProb)
	}
	if math.Abs(float64(human.ReorderCorr-nattrs.ReorderCorr)) > 0.0001 {
		t.Fatalf("human-readable reorderCorr mismatch: got %f, want %f", human.ReorderCorr, nattrs.ReorderCorr)
	}
	if math.Abs(float64(human.CorruptProb-nattrs.CorruptProb)) > 0.0001 {
		t.Fatalf("human-readable corruptProb mismatch: got %f, want %f", human.CorruptProb, nattrs.CorruptProb)
	}
	if math.Abs(float64(human.CorruptCorr-nattrs.CorruptCorr)) > 0.0001 {
		t.Fatalf("human-readable corruptCorr mismatch: got %f, want %f", human.CorruptCorr, nattrs.CorruptCorr)
	}
	if human.Rate64 != nattrs.Rate64 {
		t.Fatalf("human-readable rate64 mismatch: got %d, want %d", human.Rate64, nattrs.Rate64)
	}
}

func TestU32ToPercentagePrecisionNearMax(t *testing.T) {
	almostMax := uint32(math.MaxUint32 - 1)
	got := u32ToPercentage(almostMax)
	if got >= 100 {
		t.Fatalf("u32ToPercentage(%d) must be < 100, got %f", almostMax, got)
	}
}
