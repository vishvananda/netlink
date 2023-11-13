//go:build linux
// +build linux

package netlink

import (
	"flag"
	"net"
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
		t.Log("function attributes = ", *port.Fn)
	}
	err2 = DevLinkPortDel(dev.BusName, dev.DeviceName, port.PortIndex)
	if err2 != nil {
		t.Fatal(err2)
	}
}

func TestDevLinkSfPortFnSet(t *testing.T) {
	var addAttrs DevLinkPortAddAttrs
	var stateAttr DevlinkPortFnSetAttrs

	minKernelRequired(t, 5, 12)
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
		t.Log("function attributes = ", *port.Fn)
	}
	macAttr := DevlinkPortFnSetAttrs{
		FnAttrs: DevlinkPortFn{
			HwAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
		HwAddrValid: true,
	}
	err2 = DevlinkPortFnSet(dev.BusName, dev.DeviceName, port.PortIndex, macAttr)
	if err2 != nil {
		t.Log("function mac set err = ", err2)
	}
	stateAttr.FnAttrs.State = 1
	stateAttr.StateValid = true
	err2 = DevlinkPortFnSet(dev.BusName, dev.DeviceName, port.PortIndex, stateAttr)
	if err2 != nil {
		t.Log("function state set err = ", err2)
	}

	port, err3 := DevLinkGetPortByIndex(dev.BusName, dev.DeviceName, port.PortIndex)
	if err3 == nil {
		t.Log(*port)
		t.Log(*port.Fn)
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

func TestDevlinkGetDeviceInfoByNameAsMap(t *testing.T) {
	info, err := pkgHandle.DevlinkGetDeviceInfoByNameAsMap("pci", "0000:00:00.0", mockDevlinkInfoGetter)
	if err != nil {
		t.Fatal(err)
	}
	testInfo := devlinkTestInfoParesd()
	for k, v := range info {
		if testInfo[k] != v {
			t.Fatal("Value", v, "retrieved for key", k, "is not equal to", testInfo[k])
		}
	}
}

func TestDevlinkGetDeviceInfoByName(t *testing.T) {
	info, err := pkgHandle.DevlinkGetDeviceInfoByName("pci", "0000:00:00.0", mockDevlinkInfoGetter)
	if err != nil {
		t.Fatal(err)
	}
	testInfo := parseInfoData(devlinkTestInfoParesd())
	if !areInfoStructsEqual(info, testInfo) {
		t.Fatal("Info structures are not equal")
	}
}

func TestDevlinkGetDeviceInfoByNameAsMapFail(t *testing.T) {
	_, err := pkgHandle.DevlinkGetDeviceInfoByNameAsMap("pci", "0000:00:00.0", mockDevlinkInfoGetterEmpty)
	if err == nil {
		t.Fatal()
	}
}

func TestDevlinkGetDeviceInfoByNameFail(t *testing.T) {
	_, err := pkgHandle.DevlinkGetDeviceInfoByName("pci", "0000:00:00.0", mockDevlinkInfoGetterEmpty)
	if err == nil {
		t.Fatal()
	}
}

func mockDevlinkInfoGetter(bus, device string) ([]byte, error) {
	return devlinkInfo(), nil
}

func mockDevlinkInfoGetterEmpty(bus, device string) ([]byte, error) {
	return []byte{}, nil
}

func devlinkInfo() []byte {
	return []byte{51, 1, 0, 0, 8, 0, 1, 0, 112, 99, 105, 0, 17, 0, 2, 0, 48,
		48, 48, 48, 58, 56, 52, 58, 48, 48, 46, 48, 0, 0, 0, 0, 8, 0, 98, 0,
		105, 99, 101, 0, 28, 0, 99, 0, 51, 48, 45, 56, 57, 45, 97, 51, 45,
		102, 102, 45, 102, 102, 45, 99, 97, 45, 48, 53, 45, 54, 56, 0, 36,
		0, 100, 0, 13, 0, 103, 0, 98, 111, 97, 114, 100, 46, 105, 100, 0, 0,
		0, 0, 15, 0, 104, 0, 75, 56, 53, 53, 56, 53, 45, 48, 48, 48, 0, 0,
		28, 0, 101, 0, 12, 0, 103, 0, 102, 119, 46, 109, 103, 109, 116, 0,
		10, 0, 104, 0, 53, 46, 52, 46, 53, 0, 0, 0, 28, 0, 101, 0, 16, 0,
		103, 0, 102, 119, 46, 109, 103, 109, 116, 46, 97, 112, 105, 0, 8, 0,
		104, 0, 49, 46, 55, 0, 40, 0, 101, 0, 18, 0, 103, 0, 102, 119, 46,
		109, 103, 109, 116, 46, 98, 117, 105, 108, 100, 0, 0, 0, 15, 0, 104,
		0, 48, 120, 51, 57, 49, 102, 55, 54, 52, 48, 0, 0, 32, 0, 101, 0,
		12, 0, 103, 0, 102, 119, 46, 117, 110, 100, 105, 0, 13, 0, 104, 0,
		49, 46, 50, 56, 57, 56, 46, 48, 0, 0, 0, 0, 32, 0, 101, 0, 16, 0,
		103, 0, 102, 119, 46, 112, 115, 105, 100, 46, 97, 112, 105, 0, 9, 0,
		104, 0, 50, 46, 52, 50, 0, 0, 0, 0, 40, 0, 101, 0, 17, 0, 103, 0,
		102, 119, 46, 98, 117, 110, 100, 108, 101, 95, 105, 100, 0, 0, 0, 0,
		15, 0, 104, 0, 48, 120, 56, 48, 48, 48, 55, 48, 54, 98, 0, 0, 48, 0,
		101, 0, 16, 0, 103, 0, 102, 119, 46, 97, 112, 112, 46, 110, 97, 109,
		101, 0, 27, 0, 104, 0, 73, 67, 69, 32, 79, 83, 32, 68, 101, 102, 97,
		117, 108, 116, 32, 80, 97, 99, 107, 97, 103, 101, 0, 0, 32, 0, 101,
		0, 11, 0, 103, 0, 102, 119, 46, 97, 112, 112, 0, 0, 13, 0, 104, 0,
		49, 46, 51, 46, 50, 52, 46, 48, 0, 0, 0, 0, 44, 0, 101, 0, 21, 0,
		103, 0, 102, 119, 46, 97, 112, 112, 46, 98, 117, 110, 100, 108,
		101, 95, 105, 100, 0, 0, 0, 0, 15, 0, 104, 0, 48, 120, 99, 48, 48,
		48, 48, 48, 48, 49, 0, 0, 44, 0, 101, 0, 15, 0, 103, 0, 102, 119,
		46, 110, 101, 116, 108, 105, 115, 116, 0, 0, 21, 0, 104, 0, 50, 46,
		52, 48, 46, 50, 48, 48, 48, 45, 51, 46, 49, 54, 46, 48, 0, 0, 0, 0,
		44, 0, 101, 0, 21, 0, 103, 0, 102, 119, 46, 110, 101, 116, 108, 105,
		115, 116, 46, 98, 117, 105, 108, 100, 0, 0, 0, 0, 15, 0, 104, 0, 48,
		120, 54, 55, 54, 97, 52, 56, 57, 100, 0, 0}
}

func devlinkTestInfoParesd() map[string]string {
	return map[string]string{
		"board.id":         "K85585-000",
		"fw.app":           "1.3.24.0",
		"fw.app.bundle_id": "0xc0000001",
		"fw.app.name":      "ICE OS Default Package",
		"fw.bundle_id":     "0x8000706b",
		"fw.mgmt":          "5.4.5",
		"fw.mgmt.api":      "1.7",
		"fw.mgmt.build":    "0x391f7640",
		"fw.netlist":       "2.40.2000-3.16.0",
		"fw.netlist.build": "0x676a489d",
		"fw.psid.api":      "2.42",
		"fw.undi":          "1.2898.0",
		"driver":           "ice",
		"serialNumber":     "30-89-a3-ff-ff-ca-05-68",
	}
}

func areInfoStructsEqual(first *DevlinkDeviceInfo, second *DevlinkDeviceInfo) bool {
	if first.FwApp != second.FwApp || first.FwAppBoundleID != second.FwAppBoundleID ||
		first.FwAppName != second.FwAppName || first.FwBoundleID != second.FwBoundleID ||
		first.FwMgmt != second.FwMgmt || first.FwMgmtAPI != second.FwMgmtAPI ||
		first.FwMgmtBuild != second.FwMgmtBuild || first.FwNetlist != second.FwNetlist ||
		first.FwNetlistBuild != second.FwNetlistBuild || first.FwPsidAPI != second.FwPsidAPI ||
		first.BoardID != second.BoardID || first.FwUndi != second.FwUndi ||
		first.Driver != second.Driver || first.SerialNumber != second.SerialNumber {
		return false
	}
	return true
}

func TestDevlinkGetDeviceResources(t *testing.T) {
	minKernelRequired(t, 5, 11)
	tearDown := setUpNetlinkTestWithKModule(t, "devlink")
	defer tearDown()

	if bus == "" || device == "" {
		//TODO: setup netdevsim device instead of getting device from flags
		t.Log("devlink bus and device are empty, skipping test")
		t.SkipNow()
	}

	res, err := DevlinkGetDeviceResources(bus, device)
	if err != nil {
		t.Fatalf("failed to get device(%s/%s) resources. %s", bus, device, err)
	}

	if res.Bus != bus || res.Device != device {
		t.Fatalf("missmatching bus/device")
	}

	t.Logf("Resources: %+v", res)
}
