package netlink

import (
	"errors"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink/nl"
)

// tests in this package require following modules: vdpa, vdpa_sim, vdpa_sim_net
// The vpda_sim_net module creates virtual VDPA mgmt device with name vdpasim_net.

const (
	vdpaSimMGMTDev     = "vdpasim_net"
	vdpaTestDeviceName = "__nl_test_dev"
)

var (
	vdapTestReqModules = []string{"vdpa", "vdpa_sim", "vdpa_sim_net"}
)

func setupVDPATest(t *testing.T, reqCommands ...int) func() {
	t.Helper()
	skipUnlessRoot(t)
	skipUnlessKModuleLoaded(t, vdapTestReqModules...)
	gFam, err := GenlFamilyGet(nl.VDPA_GENL_NAME)
	if err != nil {
		t.Skip("can't check for supported VDPA commands")
	}
	for _, c := range reqCommands {
		found := false
		for _, supportedOpt := range gFam.Ops {
			if supportedOpt.ID == uint32(c) {
				found = true
			}
		}
		if !found {
			t.Skip("host doesn't support required VDPA command for the test")
		}
	}
	return func() {
		_ = VDPADelDev(vdpaTestDeviceName)
	}
}

func TestVDPAGetMGMTDevList(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_MGMTDEV_GET)()
	mgmtDevs, err := VDPAGetMGMTDevList()
	if err != nil {
		t.Fatalf("Failed to list VDPA mgmt devs: %v", err)
	}
	simMGMTFound := false
	for _, d := range mgmtDevs {
		if d.DevName != vdpaSimMGMTDev || d.BusName != "" {
			continue
		}
		simMGMTFound = true
		checkVDPAMGMTDev(t, d)
	}
	if !simMGMTFound {
		t.Fatal("VDPA vdpasim_net MGMT device not found")
	}
}

func TestVDPAGetMGMTDevByBusAndName(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_MGMTDEV_GET)()
	mgmtDev, err := VDPAGetMGMTDevByBusAndName("", vdpaSimMGMTDev)
	if err != nil {
		t.Fatalf("Failed to get VDPA sim mgmt dev: %v", err)
	}
	checkVDPAMGMTDev(t, mgmtDev)
	if mgmtDev.DevName != vdpaSimMGMTDev || mgmtDev.BusName != "" {
		t.Fatalf("Invalid device received for Get call, expected: %s, actual: %s", vdpaSimMGMTDev, mgmtDev.DevName)
	}
}

func TestVDPAGetMGMTDevByBusAndName_Unknown_Device(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_MGMTDEV_GET)()
	_, err := VDPAGetMGMTDevByBusAndName("pci", "__should_not_exist")
	if !errors.Is(err, syscall.ENODEV) {
		t.Fatal("VDPAGetMGMTDevByBusAndName returns unexpected error for unknown device")
	}
}

func TestVDPANewDev(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_DEV_GET, nl.VDPA_CMD_DEV_NEW)()
	if err := createVDPATestDev(); err != nil {
		t.Fatalf("failed to create VDPA device: %v", err)
	}
	_, err := VDPAGetDevByName(vdpaTestDeviceName)
	if err != nil {
		t.Fatalf("failed to get created VDPA devvice: %v", err)
	}
}

func TestVDPANewDev_Already_Exist(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_DEV_GET, nl.VDPA_CMD_DEV_NEW)()
	if err := createVDPATestDev(); err != nil {
		t.Fatalf("failed to create VDPA device: %v", err)
	}
	err := createVDPATestDev()
	if !errors.Is(err, syscall.EEXIST) {
		t.Fatal("VDPANewDev returns unexpected error for device which is already exist")
	}
}

func TestVDPANewDev_Unknown_MGMT_DEV(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_DEV_GET, nl.VDPA_CMD_DEV_NEW)()
	err := VDPANewDev(vdpaTestDeviceName, "", "__should_not_exist", VDPANewDevParams{})
	if !errors.Is(err, syscall.ENODEV) {
		t.Fatal("VDPANewDev returns unexpected error for unknown mgmt device")
	}
}

func TestVDPADelDev(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_DEV_DEL, nl.VDPA_CMD_DEV_NEW)()
	defer setupVDPATest(t)()
	if err := createVDPATestDev(); err != nil {
		t.Fatalf("failed to create VDPA device: %v", err)
	}
	if err := VDPADelDev(vdpaTestDeviceName); err != nil {
		t.Fatalf("VDPADelDev failed: %v", err)
	}
}

func TestVDPADelDev_Unknown_Device(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_DEV_DEL)()
	err := VDPADelDev("__should_not_exist")
	if !errors.Is(err, syscall.ENODEV) {
		t.Fatal("VDPADelDev returns unexpected error for unknown device")
	}
}

func TestVDPAGetDevList(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_DEV_GET, nl.VDPA_CMD_DEV_NEW)()
	if err := createVDPATestDev(); err != nil {
		t.Fatalf("failed to create VDPA device: %v", err)
	}
	devs, err := VDPAGetDevList()
	if err != nil {
		t.Fatalf("VDPAGetDevList failed: %v", err)
	}
	testDevFound := false
	for _, d := range devs {
		if d.Name != vdpaTestDeviceName {
			continue
		}
		testDevFound = true
		checkVDPADev(t, d)
	}
	if !testDevFound {
		t.Fatal("VDPA test device not found")
	}
}

func TestVDPAGetDevByName(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_DEV_GET, nl.VDPA_CMD_DEV_NEW)()
	if err := createVDPATestDev(); err != nil {
		t.Fatalf("failed to create VDPA device: %v", err)
	}
	dev, err := VDPAGetDevByName(vdpaTestDeviceName)
	if err != nil {
		t.Fatalf("VDPAGetDevByName failed: %v", err)
	}
	checkVDPADev(t, dev)
	if dev.Name != vdpaTestDeviceName {
		t.Fatalf("Invalid device received for Get call, expected: %s, actual: %s", vdpaTestDeviceName, dev.Name)
	}
}

func TestVDPAGetDevByName_Unknown(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_DEV_GET)()
	_, err := VDPAGetDevByName("__should_not_exist")
	if !errors.Is(err, syscall.ENODEV) {
		t.Fatal("VDPAGetDevByName returns unexpected error for unknown device")
	}
}

func TestVDPAGetDevConfigList(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_DEV_GET, nl.VDPA_CMD_DEV_CONFIG_GET)()
	if err := createVDPATestDev(); err != nil {
		t.Fatalf("failed to create VDPA device: %v", err)
	}
	devConfs, err := VDPAGetDevConfigList()
	if err != nil {
		t.Fatalf("VDPAGetDevConfigList failed: %v", err)
	}
	testDevConfFound := false
	for _, d := range devConfs {
		if d.Name != vdpaTestDeviceName {
			continue
		}
		testDevConfFound = true
		checkVDPADevConf(t, d)
	}
	if !testDevConfFound {
		t.Fatal("VDPA test device config not found")
	}
}

func TestVDPAGetDevConfigByName(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_DEV_GET, nl.VDPA_CMD_DEV_CONFIG_GET)()
	if err := createVDPATestDev(); err != nil {
		t.Fatalf("failed to create VDPA device: %v", err)
	}
	dev, err := VDPAGetDevConfigByName(vdpaTestDeviceName)
	if err != nil {
		t.Fatalf("VDPAGetDevConfigByName failed: %v", err)
	}
	checkVDPADevConf(t, dev)
	if dev.Name != vdpaTestDeviceName {
		t.Fatalf("Invalid device received for Get call, expected: %s, actual: %s", vdpaTestDeviceName, dev.Name)
	}
}

func TestVDPAGetDevConfigByName_Unknowm(t *testing.T) {
	defer setupVDPATest(t, nl.VDPA_CMD_DEV_GET, nl.VDPA_CMD_DEV_CONFIG_GET)()
	_, err := VDPAGetDevConfigByName("__should_not_exist")
	if !errors.Is(err, syscall.ENODEV) {
		t.Fatal("VDPAGetDevConfigByName returns unexpected error for unknown device")
	}
}

func TestSetGetBits(t *testing.T) {
	features := SetBits(0, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_MQ)
	if !IsBitSet(features, VIRTIO_NET_F_CSUM) || !IsBitSet(features, VIRTIO_NET_F_MQ) {
		t.Fatal("BitSet test failed")
	}
	if IsBitSet(features, VIRTIO_NET_F_STATUS) {
		t.Fatal("unexpected bit is set")
	}
}

func createVDPATestDev() error {
	return VDPANewDev(vdpaTestDeviceName, "", vdpaSimMGMTDev, VDPANewDevParams{})
}

func checkVDPAMGMTDev(t *testing.T, d *VDPAMGMTDev) {
	if d == nil {
		t.Fatal("VDPA MGMT dev is nil")
	}
	if d.DevName == "" {
		t.Fatal("VDPA MGMT dev name is not set")
	}
}

func checkVDPADev(t *testing.T, d *VDPADev) {
	if d == nil {
		t.Fatal("VDPA dev is nil")
	}
	if d.Name == "" {
		t.Fatal("VDPA dev name is not set")
	}
	if d.ID == 0 {
		t.Fatal("VDPA dev ID is not set")
	}
}

func checkVDPADevConf(t *testing.T, d *VDPADevConfig) {
	if d == nil {
		t.Fatal("VDPA dev config is nil")
	}
	if d.Name == "" {
		t.Fatal("VDPA dev name is not set")
	}
	if d.ID == 0 {
		t.Fatal("VDPA dev ID is not set")
	}
}
