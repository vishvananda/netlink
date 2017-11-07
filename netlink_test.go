package netlink

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type tearDownNetlinkTest func()

func skipUnlessRoot(t *testing.T) {
	if os.Getuid() != 0 {
		msg := "Skipped test because it requires root privileges."
		log.Printf(msg)
		t.Skip(msg)
	}
}

func setUpNetlinkTest(t *testing.T) tearDownNetlinkTest {
	skipUnlessRoot(t)

	// new temporary namespace so we don't pollute the host
	// lock thread since the namespace is thread local
	runtime.LockOSThread()
	var err error
	ns, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create newns", ns)
	}

	return func() {
		ns.Close()
		runtime.UnlockOSThread()
	}
}

func setUpMPLSNetlinkTest(t *testing.T) tearDownNetlinkTest {
	if _, err := os.Stat("/proc/sys/net/mpls/platform_labels"); err != nil {
		msg := "Skipped test because it requires MPLS support."
		log.Printf(msg)
		t.Skip(msg)
	}
	f := setUpNetlinkTest(t)
	setUpF := func(path, value string) {
		file, err := os.Create(path)
		defer file.Close()
		if err != nil {
			t.Fatalf("Failed to open %s: %s", path, err)
		}
		file.WriteString(value)
	}
	setUpF("/proc/sys/net/mpls/platform_labels", "1024")
	setUpF("/proc/sys/net/mpls/conf/lo/input", "1")
	return f
}

func setUpNetlinkTestWithKModule(t *testing.T, name string) tearDownNetlinkTest {
	file, err := ioutil.ReadFile("/proc/modules")
	if err != nil {
		t.Fatal("Failed to open /proc/modules", err)
	}
	found := false
	for _, line := range strings.Split(string(file), "\n") {
		n := strings.Split(line, " ")[0]
		if n == name {
			found = true
			break
		}

	}
	if !found {
		msg := fmt.Sprintf("Skipped test because it requres kmodule %s.", name)
		log.Println(msg)
		t.Skip(msg)
	}
	return setUpNetlinkTest(t)
}

func remountSysfs() error {
	if err := unix.Mount("", "/", "none", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return err
	}
	if err := unix.Unmount("/sys", unix.MNT_DETACH); err != nil {
		return err
	}
	return unix.Mount("", "/sys", "sysfs", 0, "")
}

func minKernelRequired(t *testing.T, kernel, major int) {
	k, m, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	if k < kernel || k == kernel && m < major {
		t.Skipf("Host Kernel (%d.%d) does not meet test's minimum required version: (%d.%d)",
			k, m, kernel, major)
	}
}

func KernelVersion() (kernel, major int, err error) {
	uts := unix.Utsname{}
	if err = unix.Uname(&uts); err != nil {
		return
	}

	ba := make([]byte, 0, len(uts.Release))
	for _, b := range uts.Release {
		if b == 0 {
			break
		}
		ba = append(ba, byte(b))
	}
	var rest string
	if n, _ := fmt.Sscanf(string(ba), "%d.%d%s", &kernel, &major, &rest); n < 2 {
		err = fmt.Errorf("can't parse kernel version in %q", string(ba))
	}
	return
}
