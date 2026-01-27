package netlink

import (
	"fmt"
	"io/ioutil"
	"testing"
)

func TestBridgeVlan(t *testing.T) {
	minKernelRequired(t, 3, 10)

	t.Cleanup(setUpNetlinkTest(t))
	if err := remountSysfs(); err != nil {
		t.Fatal(err)
	}
	bridgeName := "foo"
	bridge := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeName}}
	if err := LinkAdd(bridge); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(fmt.Sprintf("/sys/devices/virtual/net/%s/bridge/vlan_filtering", bridgeName), []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	if vlanMap, err := BridgeVlanList(); err != nil {
		t.Fatal(err)
	} else {
		if len(vlanMap) != 1 {
			t.Fatal()
		}
		if vInfo, ok := vlanMap[int32(bridge.Index)]; !ok {
			t.Fatal("vlanMap should include foo port vlan info")
		} else {
			if len(vInfo) != 1 {
				t.Fatal()
			} else {
				if !vInfo[0].EngressUntag() || !vInfo[0].PortVID() || vInfo[0].Vid != 1 {
					t.Fatalf("bridge vlan show get wrong return %s", vInfo[0].String())
				}
			}
		}
	}
	dummy := &Dummy{LinkAttrs: LinkAttrs{Name: "dum1"}}
	if err := LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	if err := LinkSetMaster(dummy, bridge); err != nil {
		t.Fatal(err)
	}
	if err := BridgeVlanAdd(dummy, 2, false, false, false, false); err != nil {
		t.Fatal(err)
	}
	if err := BridgeVlanAdd(dummy, 3, true, true, false, false); err != nil {
		t.Fatal(err)
	}
	if err := BridgeVlanAddRange(dummy, 4, 6, false, false, false, false); err != nil {
		t.Fatal(err)
	}
	if vlanMap, err := BridgeVlanList(); err != nil {
		t.Fatal(err)
	} else {
		if len(vlanMap) != 2 {
			t.Fatal()
		}
		if vInfo, ok := vlanMap[int32(bridge.Index)]; !ok {
			t.Fatal("vlanMap should include foo port vlan info")
		} else {
			if fmt.Sprintf("%v", vInfo) != "[{Flags:6 Vid:1}]" {
				t.Fatalf("unexpected result %v", vInfo)
			}
		}
		if vInfo, ok := vlanMap[int32(dummy.Index)]; !ok {
			t.Fatal("vlanMap should include dum1 port vlan info")
		} else {
			if fmt.Sprintf("%v", vInfo) != "[{Flags:4 Vid:1} {Flags:0 Vid:2} {Flags:6 Vid:3} {Flags:0 Vid:4} {Flags:0 Vid:5} {Flags:0 Vid:6}]" {
				t.Fatalf("unexpected result %v", vInfo)
			}
		}
	}
}

func TestBridgeVlanTunnelInfo(t *testing.T) {
	minKernelRequired(t, 4, 11)
	t.Cleanup(setUpNetlinkTest(t))

	if err := remountSysfs(); err != nil {
		t.Fatal(err)
	}
	bridgeName := "br0"
	vxlanName := "vxlan0"

	// ip link add br0 type bridge
	bridge := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeName}}
	if err := LinkAdd(bridge); err != nil {
		t.Fatal(err)
	}

	// ip link add vxlan0 type vxlan dstport 4789 nolearning external local 10.0.1.1
	vxlan := &Vxlan{
		// local
		SrcAddr:  []byte("10.0.1.1"),
		Learning: false,
		// external
		FlowBased: true,
		// dstport
		Port:      4789,
		LinkAttrs: LinkAttrs{Name: vxlanName},
	}
	if err := LinkAdd(vxlan); err != nil {
		t.Fatal(err)
	}

	// ip link set dev vxlan0 master br0
	if err := LinkSetMaster(vxlan, bridge); err != nil {
		t.Fatal(err)
	}

	// ip link set br0 type bridge vlan_filtering 1
	if err := BridgeSetVlanFiltering(bridge, true); err != nil {
		t.Fatal(err)
	}

	// bridge link set dev vxlan0 vlan_tunnel on
	if err := LinkSetVlanTunnel(vxlan, true); err != nil {
		t.Fatal(err)
	}

	p, err := LinkGetProtinfo(vxlan)
	if err != nil {
		t.Fatal(err)
	}
	if !p.VlanTunnel {
		t.Fatal("vlan tunnel should be enabled on vxlan device")
	}

	// bridge vlan add vid 10 dev vxlan0
	if err := BridgeVlanAdd(vxlan, 10, false, false, false, false); err != nil {
		t.Fatal(err)
	}

	// bridge vlan add vid 11 dev vxlan0
	if err := BridgeVlanAdd(vxlan, 11, false, false, false, false); err != nil {
		t.Fatal(err)
	}

	// bridge vlan add dev vxlan0 vid 10 tunnel_info id 20
	if err := BridgeVlanAddTunnelInfo(vxlan, 10, 20, false, false); err != nil {
		t.Fatal(err)
	}

	tis, err := BridgeVlanTunnelShow()
	if err != nil {
		t.Fatal(err)
	}

	if len(tis) != 1 {
		t.Fatal("only one tunnel info")
	}
	ti := tis[0]
	if ti.TunId != 20 || ti.Vid != 10 {
		t.Fatal("unexpected result")
	}

	// bridge vlan del dev vxlan0 vid 10 tunnel_info id 20
	if err := BridgeVlanDelTunnelInfo(vxlan, 10, 20, false, false); err != nil {
		t.Fatal(err)
	}

	tis, err = BridgeVlanTunnelShow()
	if err != nil {
		t.Fatal(err)
	}

	if len(tis) != 0 {
		t.Fatal("tunnel info should have been deleted")
	}

	// bridge vlan add dev vxlan0 vid 10-11 tunnel_info id 20-21
	if err := BridgeVlanAddRangeTunnelInfoRange(vxlan, 10, 11, 20, 21, false, false); err != nil {
		t.Fatal(err)
	}

	tis, err = BridgeVlanTunnelShow()
	if err != nil {
		t.Fatal(err)
	}
	if len(tis) != 2 {
		t.Fatal("two tunnel info")
	}

	// bridge vlan del dev vxlan0 vid 10-11 tunnel_info id 20-21
	if err := BridgeVlanDelRangeTunnelInfoRange(vxlan, 10, 11, 20, 21, false, false); err != nil {
		t.Fatal(err)
	}

	tis, err = BridgeVlanTunnelShow()
	if err != nil {
		t.Fatal(err)
	}

	if len(tis) != 0 {
		t.Fatal("tunnel info should have been deleted")
	}
}

func TestBridgeVni(t *testing.T) {
	minKernelRequired(t, 5, 18)
	t.Cleanup(setUpNetlinkTest(t))

	vxlanName := "vxlan0"

	// ip link add vxlan0 type vxlan dstport 4789 nolearning external vnifilter
	vxlan := &Vxlan{
		LinkAttrs: LinkAttrs{Name: vxlanName},
		Learning:  false,
		FlowBased: true,
		VniFilter: true,
	}
	if err := LinkAdd(vxlan); err != nil {
		t.Fatal(err)
	}

	link, err := LinkByName(vxlanName)
	if err != nil {
		t.Fatal(err)
	}

	// bridge vni add dev vxlan0 vni 100
	if err := BridgeVniAdd(link, 100); err != nil {
		t.Fatal(err)
	}

	// bridge vni show
	vniMap, err := BridgeVniList()
	if err != nil {
		t.Fatal(err)
	}
	vnis := vniMap[int32(link.Attrs().Index)]
	if len(vnis) != 1 {
		t.Fatalf("expected 1 VNI, got %d", len(vnis))
	}
	if vnis[0].Vni != 100 {
		t.Fatalf("expected VNI 100, got %d", vnis[0].Vni)
	}
	if vnis[0].VniEnd != 0 {
		t.Fatalf("expected VniEnd 0 for single VNI, got %d", vnis[0].VniEnd)
	}

	// bridge vni del dev vxlan0 vni 100
	if err := BridgeVniDel(link, 100); err != nil {
		t.Fatal(err)
	}

	vniMap, err = BridgeVniList()
	if err != nil {
		t.Fatal(err)
	}
	vnis = vniMap[int32(link.Attrs().Index)]
	if len(vnis) != 0 {
		t.Fatalf("expected 0 VNI entries after delete, got %d", len(vnis))
	}

	// bridge vni add dev vxlan0 vni 200-210
	if err := BridgeVniAddRange(link, 200, 210); err != nil {
		t.Fatal(err)
	}

	// bridge vni show
	vniMap, err = BridgeVniList()
	if err != nil {
		t.Fatal(err)
	}
	vnis = vniMap[int32(link.Attrs().Index)]
	if len(vnis) != 1 {
		t.Fatalf("expected 1 VNI range entry, got %d", len(vnis))
	}
	if vnis[0].Vni != 200 {
		t.Fatalf("expected VNI start 200, got %d", vnis[0].Vni)
	}
	if vnis[0].VniEnd != 210 {
		t.Fatalf("expected VNI end 210, got %d", vnis[0].VniEnd)
	}

	// bridge vni del dev vxlan0 vni 200-210
	if err := BridgeVniDelRange(link, 200, 210); err != nil {
		t.Fatal(err)
	}

	vniMap, err = BridgeVniList()
	if err != nil {
		t.Fatal(err)
	}
	vnis = vniMap[int32(link.Attrs().Index)]
	if len(vnis) != 0 {
		t.Fatalf("expected 0 VNI entries after range delete, got %d", len(vnis))
	}
}

func TestBridgeGroupFwdMask(t *testing.T) {
	minKernelRequired(t, 4, 15) //minimal release for per-port group_fwd_mask
	t.Cleanup(setUpNetlinkTest(t))
	if err := remountSysfs(); err != nil {
		t.Fatal(err)
	}
	bridgeName := "foo"
	var mask uint16 = 0xfff0
	bridge := &Bridge{LinkAttrs: LinkAttrs{Name: bridgeName}, GroupFwdMask: &mask}
	if err := LinkAdd(bridge); err != nil {
		t.Fatal(err)
	}
	brlink, err := LinkByName(bridgeName)
	if err != nil {
		t.Fatal(err)
	}
	if *(brlink.(*Bridge).GroupFwdMask) != mask {
		t.Fatalf("created bridge has group_fwd_mask value %x, different from expected %x",
			*(brlink.(*Bridge).GroupFwdMask), mask)
	}
	dummyName := "dm1"
	dummy := &Dummy{LinkAttrs: LinkAttrs{Name: dummyName, MasterIndex: brlink.Attrs().Index}}
	if err := LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	dmLink, err := LinkByName(dummyName)
	if err != nil {
		t.Fatal(err)
	}
	if err = LinkSetBRSlaveGroupFwdMask(dmLink, mask); err != nil {
		t.Fatal(err)
	}
}
