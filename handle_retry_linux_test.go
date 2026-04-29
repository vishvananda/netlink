//go:build linux
// +build linux

package netlink

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func TestExecuteIterRetryInterruptedRetriesDumpInterrupted(t *testing.T) {
	t.Cleanup(setUpNetlinkTest(t))

	const linkCount = 1000
	links := make([]Link, 0, linkCount)
	for i := range linkCount {
		link := &Dummy{LinkAttrs{Name: fmt.Sprintf("retry%04d", i)}}
		if err := LinkAdd(link); err != nil {
			t.Fatalf("failed to add link %d: %v", i, err)
		}
		links = append(links, link)
	}
	t.Cleanup(func() {
		for _, link := range links {
			_ = LinkDel(link)
		}
	})

	dumpHandle, err := NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dumpHandle.Close() })

	churnHandle, err := NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { churnHandle.Close() })

	churn := churnLink(churnHandle)
	defer func() {
		if err := churn.stopAndWait(); err != nil {
			t.Error(err)
		}
	}()

	if err := waitForExecuteIterDumpInterrupted(dumpHandle, churn); err != nil {
		t.Fatal(err)
	}

	// RouteListFiltered uses the same ExecuteIter path. Exercise it directly
	// because link dumps trigger NLM_F_DUMP_INTR more reliably in a test netns.
	dumpHandle.RetryInterrupted()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		err := executeIterLinkDump(dumpHandle)
		switch {
		case err == ErrDumpInterrupted:
			t.Fatalf("raw ErrDumpInterrupted escaped; ExecuteIter did not retry")
		case errors.Is(err, ErrDumpInterrupted):
			// OK: retry path was used and exhausted after 10 attempts.
		case err != nil:
			t.Fatal(err)
		default:
			// OK: retry path eventually got a stable dump.
		}

		if err := churn.errValue(); err != nil {
			t.Fatal(err)
		}
	}
}

func executeIterLinkDump(h *Handle) error {
	req := h.newNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_DUMP)
	req.AddData(nl.NewIfInfomsg(FAMILY_ALL))
	req.AddData(nl.NewRtAttr(unix.IFLA_EXT_MASK, nl.Uint32Attr(nl.RTEXT_FILTER_VF)))
	return req.ExecuteIter(unix.NETLINK_ROUTE, unix.RTM_NEWLINK, func([]byte) bool {
		return true
	})
}

type linkChurn struct {
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	errMu sync.Mutex
	err   error
}

func churnLink(h *Handle) *linkChurn {
	churn := &linkChurn{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	link := &Dummy{LinkAttrs{Name: "retry-churn"}}

	go func() {
		defer close(churn.done)
		for {
			select {
			case <-churn.stop:
				_ = h.LinkDel(link)
				return
			default:
			}
			if err := h.LinkAdd(link); err != nil && !errors.Is(err, unix.EEXIST) {
				churn.setErr(fmt.Errorf("failed to add churn link: %w", err))
				return
			}
			if err := h.LinkDel(link); err != nil && !errors.Is(err, unix.ENODEV) {
				churn.setErr(fmt.Errorf("failed to delete churn link: %w", err))
				return
			}
		}
	}()

	return churn
}

func (c *linkChurn) setErr(err error) {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	c.err = err
}

func (c *linkChurn) errValue() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.err
}

func (c *linkChurn) stopAndWait() error {
	c.stopOnce.Do(func() {
		close(c.stop)
	})
	<-c.done
	return c.errValue()
}

func waitForExecuteIterDumpInterrupted(h *Handle, churn *linkChurn) error {
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		err := executeIterLinkDump(h)
		if errors.Is(err, ErrDumpInterrupted) {
			return nil
		}
		if err != nil {
			return err
		}

		if err := churn.errValue(); err != nil {
			return err
		}
	}
	return fmt.Errorf("failed to trigger %v; increase linkCount or churn duration", ErrDumpInterrupted)
}
