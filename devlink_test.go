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

func TestDevLinkSetEswitchMode(t *testing.T) {
	minKernelRequired(t, 4, 12)
	setUpNetlinkTestWithKModule(t, "devlink")
	dev, err := DevLinkGetDeviceByName("foo", "bar")
	if err != nil {
		t.Fatal(err)
	}
	err = DevLinkSetEswitchMode(dev, "switchdev")
	if err != nil {
		t.Fatal(err)
	}
	err = DevLinkSetEswitchMode(dev, "legacy")
	if err != nil {
		t.Fatal(err)
	}
}

func TestDevLinkGetAllPortList(t *testing.T) {
	minKernelRequired(t, 5, 4)
	ports, err := DevLinkGetAllPortList()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("devlink port count = ", len(ports))
	for _, port := range ports {
		t.Log(*port)
	}
}

func TestDevLinkGetPortByIndex(t *testing.T) {
	minKernelRequired(t, 5, 4)
	ports, err := DevLinkGetAllPortList()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("devlink port count = ", len(ports))
	for _, port := range ports {
		p, err2 := DevLinkGetPortByIndex(port.BusName, port.DeviceName, port.PortIndex)
		if err2 != nil {
			t.Fatal(err)
		}
		t.Log(*p)
	}
}
