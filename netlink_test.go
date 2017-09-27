package netlink

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
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

func setUpSEG6NetlinkTest(t *testing.T) tearDownNetlinkTest {
	// check if SEG6 options are enabled in Kernel Config
	cmd := exec.Command("uname", "-r")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatal("Failed to run: uname -r")
	}
	s := []string{"/boot/config-", strings.TrimRight(out.String(), "\n")}
	filename := strings.Join(s, "")

	grepKey := func(key, fname string) (string, error) {
		cmd := exec.Command("grep", key, filename)
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run() // "err != nil" if no line matched with grep
		return strings.TrimRight(out.String(), "\n"), err
	}
	key := string("CONFIG_IPV6_SEG6_LWTUNNEL=y")
	if _, err := grepKey(key, filename); err != nil {
		msg := "Skipped test because it requires SEG6_LWTUNNEL support."
		log.Printf(msg)
		t.Skip(msg)
	}
	key = string("CONFIG_IPV6_SEG6_INLINE=y")
	if _, err := grepKey(key, filename); err != nil {
		msg := "Skipped test because it requires SEG6_INLINE support."
		log.Printf(msg)
		t.Skip(msg)
	}
	// Add CONFIG_IPV6_SEG6_HMAC to support seg6_hamc
	// key := string("CONFIG_IPV6_SEG6_HMAC=y")

	return setUpNetlinkTest(t)
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
