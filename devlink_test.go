// +build linux

package netlink

import (
	"testing"
)

func TestDevLinkGetDeviceList(t *testing.T) {
	minKernelRequired(t, 4, 12)
	setUpNetlinkTestWithKModule(t, "devlink")
	_, err := DevLinkGetDeviceList()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDevLinkGetDeviceByName(t *testing.T) {
	minKernelRequired(t, 4, 12)
	setUpNetlinkTestWithKModule(t, "devlink")
	_, err := DevLinkGetDeviceByName("foo", "bar")
	if err != nil {
		t.Fatal(err)
	}
}
