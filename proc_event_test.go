package netlink

import (
	"github.com/vishvananda/netns"
	"os"
	"os/exec"
	"runtime"
	"testing"
)

func TestSubscribeProcEvent(t *testing.T) {
	skipUnlessRoot(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pid1ns, err := netns.GetFromPid(1)
	if err != nil {
		panic(err)
	}

	err = netns.Set(pid1ns)
	if err != nil {
		panic(err)
	}

	ch := make(chan ProcEvent)
	done := make(chan struct{})
	defer close(done)

	errChan := make(chan error)

	if err := ProcEventMonitor(ch, done, errChan); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("false")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// first we wait for proc - i.e. childTgid is cmd.Process.Pid
	for {
		e := <-ch
		t.Logf("pid: %+v e: %+v", os.Getpid(), e)
		if e.Msg.Tgid() == uint32(os.Getpid()) {
			if forkEvent, ok := e.Msg.(*ForkProcEvent); ok {
				if forkEvent.ChildTgid == uint32(cmd.Process.Pid) {
					break
				}
			}
		}
	}

	// wait for exec event
	for {
		e := <-ch
		if e.Msg.Tgid() == uint32(cmd.Process.Pid) {
			if _, ok := e.Msg.(*ExecProcEvent); ok {
				break
			}
		}
	}

	cmd.Wait()
	for {
		e := <-ch
		if e.Msg.Tgid() == uint32(cmd.Process.Pid) {
			if exitEvent, ok := e.Msg.(*ExitProcEvent); ok {
				if exitEvent.ExitCode != 256 {
					t.Errorf("Expected error code 256 (-1), but got %+v", exitEvent)
				}
				break
			}
		}
	}

	done <- struct{}{}
}
