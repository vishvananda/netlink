// +build linux

package netlink

import (
	"io/ioutil"
	"strings"
	"testing"
)

func setupRdmaKModule(t *testing.T, name string) {
	skipUnlessRoot(t)
	file, err := ioutil.ReadFile("/proc/modules")
	if err != nil {
		t.Fatal("Failed to open /proc/modules", err)
	}
	for _, line := range strings.Split(string(file), "\n") {
		n := strings.Split(line, " ")[0]
		if n == name {
			return
		}

	}
	t.Skipf("Test requires kmodule %q.", name)
}

func TestRdmaGetRdmaLink(t *testing.T) {
	minKernelRequired(t, 4, 16)
	setupRdmaKModule(t, "ib_core")
	_, err := RdmaLinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
}

func TestRdmaSetRdmaLinkName(t *testing.T) {
	minKernelRequired(t, 4, 19)
	setupRdmaKModule(t, "ib_core")
	link, err := RdmaLinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	// Set new name
	err = RdmaLinkSetName(link, "bar")
	if err != nil {
		t.Fatal(err)
	}
	// Revert back to old name
	err = RdmaLinkSetName(link, "foo")
	if err != nil {
		t.Fatal(err)
	}
}

func TestRdmaSystemGetNetnsMode(t *testing.T) {
	minKernelRequired(t, 5, 2)
	setupRdmaKModule(t, "ib_core")

	mode, err := RdmaSystemGetNetnsMode()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("rdma system netns mode =", mode)
}
