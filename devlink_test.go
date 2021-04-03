// +build linux

package netlink

import (
	"testing"
	"flag"
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

func TestDevLinkAddDelSfPort(t *testing.T) {
	var addAttrs DevLinkPortAddAttrs
	minKernelRequired(t, 5, 13)
	if bus == "" || device == "" {
		t.Log("devlink bus and device are empty, skipping test")
		return
	}

	dev, err := DevLinkGetDeviceByName(bus, device)
	if err != nil {
		t.Fatal(err)
		return
	}
	addAttrs.SfNumberValid = true
	addAttrs.SfNumber = uint32(sfnum)
	addAttrs.PfNumber = 0
	port, err2 := DevLinkPortAdd(dev.BusName, dev.DeviceName, 7, addAttrs)
	if err2 != nil {
		t.Fatal(err2)
		return
	}
	t.Log(*port)
	if port.Fn != nil {
		t.Log("function attributes = " , *port.Fn)
	}
	err2 = DevLinkPortDel(dev.BusName, dev.DeviceName, port.PortIndex)
	if err2 != nil {
		t.Fatal(err2)
	}
}

var bus string
var device string
var sfnum uint

func init() {
        flag.StringVar(&bus, "bus", "", "devlink device bus name")
        flag.StringVar(&device, "device", "", "devlink device devicename")
        flag.UintVar(&sfnum, "sfnum", 0, "devlink port sfnumber")
}
