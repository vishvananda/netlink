package netlink

import (
	"bytes"
	"io/ioutil"
	"net"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func TestParseIpsetProtocolResult(t *testing.T) {
	msgBytes, err := ioutil.ReadFile("testdata/ipset_protocol_result")
	if err != nil {
		t.Fatalf("reading test fixture failed: %v", err)
	}

	msg := ipsetUnserialize([][]byte{msgBytes})
	if msg.Protocol != 6 {
		t.Errorf("expected msg.Protocol to equal 6, got %d", msg.Protocol)
	}
}

func TestParseIpsetListResult(t *testing.T) {
	msgBytes, err := ioutil.ReadFile("testdata/ipset_list_result")
	if err != nil {
		t.Fatalf("reading test fixture failed: %v", err)
	}

	msg := ipsetUnserialize([][]byte{msgBytes})
	if msg.SetName != "clients" {
		t.Errorf(`expected SetName to equal "clients", got %q`, msg.SetName)
	}
	if msg.TypeName != "hash:mac" {
		t.Errorf(`expected TypeName to equal "hash:mac", got %q`, msg.TypeName)
	}
	if msg.Protocol != 6 {
		t.Errorf("expected Protocol to equal 6, got %d", msg.Protocol)
	}
	if msg.References != 0 {
		t.Errorf("expected References to equal 0, got %d", msg.References)
	}
	if msg.NumEntries != 2 {
		t.Errorf("expected NumEntries to equal 2, got %d", msg.NumEntries)
	}
	if msg.HashSize != 1024 {
		t.Errorf("expected HashSize to equal 1024, got %d", msg.HashSize)
	}
	if *msg.Timeout != 3600 {
		t.Errorf("expected Timeout to equal 3600, got %d", *msg.Timeout)
	}
	if msg.MaxElements != 65536 {
		t.Errorf("expected MaxElements to equal 65536, got %d", msg.MaxElements)
	}
	if msg.CadtFlags != nl.IPSET_FLAG_WITH_COMMENT|nl.IPSET_FLAG_WITH_COUNTERS {
		t.Error("expected CadtFlags to be IPSET_FLAG_WITH_COMMENT and IPSET_FLAG_WITH_COUNTERS")
	}
	if len(msg.Entries) != 2 {
		t.Fatalf("expected 2 Entries, got %d", len(msg.Entries))
	}

	// first entry
	ent := msg.Entries[0]
	if int(*ent.Timeout) != 3577 {
		t.Errorf("expected Timeout for first entry to equal 3577, got %d", *ent.Timeout)
	}
	if int(*ent.Bytes) != 4121 {
		t.Errorf("expected Bytes for first entry to equal 4121, got %d", *ent.Bytes)
	}
	if int(*ent.Packets) != 42 {
		t.Errorf("expected Packets for first entry to equal 42, got %d", *ent.Packets)
	}
	if ent.Comment != "foo bar" {
		t.Errorf("unexpected Comment for first entry: %q", ent.Comment)
	}
	expectedMAC := net.HardwareAddr{0xde, 0xad, 0x0, 0x0, 0xbe, 0xef}
	if !bytes.Equal(ent.MAC, expectedMAC) {
		t.Errorf("expected MAC for first entry to be %s, got %s", expectedMAC.String(), ent.MAC.String())
	}

	// second entry
	ent = msg.Entries[1]
	expectedMAC = net.HardwareAddr{0x1, 0x2, 0x3, 0x0, 0x1, 0x2}
	if !bytes.Equal(ent.MAC, expectedMAC) {
		t.Errorf("expected MAC for second entry to be %s, got %s", expectedMAC.String(), ent.MAC.String())
	}
}

func TestIpsetCreateListAddDelDestroy(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	timeout := uint32(3)
	err := IpsetCreate("my-test-ipset-1", "hash:ip", IpsetCreateOptions{
		Replace:  true,
		Timeout:  &timeout,
		Counters: true,
		Comments: true,
		Skbinfo:  false,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = IpsetCreate("my-test-ipset-2", "hash:net", IpsetCreateOptions{
		Replace:  true,
		Timeout:  &timeout,
		Counters: false,
		Comments: true,
		Skbinfo:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	results, err := IpsetListAll()

	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 IPSets to be created, got %d", len(results))
	}

	if results[0].SetName != "my-test-ipset-1" {
		t.Errorf("expected name to be 'my-test-ipset-1', but got '%s'", results[0].SetName)
	}

	if results[1].SetName != "my-test-ipset-2" {
		t.Errorf("expected name to be 'my-test-ipset-2', but got '%s'", results[1].SetName)
	}

	if results[0].TypeName != "hash:ip" {
		t.Errorf("expected type to be 'hash:ip', but got '%s'", results[0].TypeName)
	}

	if results[1].TypeName != "hash:net" {
		t.Errorf("expected type to be 'hash:net', but got '%s'", results[1].TypeName)
	}

	if *results[0].Timeout != 3 {
		t.Errorf("expected timeout to be 3, but got '%d'", *results[0].Timeout)
	}

	ip := net.ParseIP("10.99.99.99")
	exist, err := IpsetTest("my-test-ipset-1", &IPSetEntry{
		IP: ip,
	})
	if err != nil {
		t.Fatal(err)
	}
	if exist {
		t.Errorf("entry should not exist before being added: %s", ip.String())
	}

	err = IpsetAdd("my-test-ipset-1", &IPSetEntry{
		Comment: "test comment",
		IP:      ip,
		Replace: false,
	})

	if err != nil {
		t.Fatal(err)
	}

	exist, err = IpsetTest("my-test-ipset-1", &IPSetEntry{
		IP: ip,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !exist {
		t.Errorf("entry should exist after being added: %s", ip.String())
	}

	result, err := IpsetList("my-test-ipset-1")

	if err != nil {
		t.Fatal(err)
	}

	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry be created, got '%d'", len(result.Entries))
	}
	if result.Entries[0].IP.String() != "10.99.99.99" {
		t.Fatalf("expected entry to be '10.99.99.99', got '%s'", result.Entries[0].IP.String())
	}

	if result.Entries[0].Comment != "test comment" {
		// This is only supported in the kernel module from revision 2 or 4, so comments may be ignored.
		t.Logf("expected comment to be 'test comment', got '%s'", result.Entries[0].Comment)
	}

	err = IpsetDel("my-test-ipset-1", &IPSetEntry{
		Comment: "test comment",
		IP:      net.ParseIP("10.99.99.99"),
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err = IpsetList("my-test-ipset-1")
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Entries) != 0 {
		t.Fatalf("expected 0 entries to exist, got %d", len(result.Entries))
	}

	err = IpsetDestroy("my-test-ipset-1")
	if err != nil {
		t.Fatal(err)
	}

	err = IpsetDestroy("my-test-ipset-2")
	if err != nil {
		t.Fatal(err)
	}
}

func TestIpsetCreateListAddDelDestroyWithTestCases(t *testing.T) {
	timeout := uint32(3)
	protocalTCP := uint8(unix.IPPROTO_TCP)
	port := uint16(80)

	testCases := []struct {
		desc     string
		setname  string
		typename string
		options  IpsetCreateOptions
		entry    *IPSetEntry
	}{
		{
			desc:     "Type-hash:ip",
			setname:  "my-test-ipset-1",
			typename: "hash:ip",
			options: IpsetCreateOptions{
				Replace:  true,
				Timeout:  &timeout,
				Counters: true,
				Comments: true,
				Skbinfo:  false,
			},
			entry: &IPSetEntry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.99"),
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:net",
			setname:  "my-test-ipset-2",
			typename: "hash:net",
			options: IpsetCreateOptions{
				Replace:  true,
				Timeout:  &timeout,
				Counters: false,
				Comments: true,
				Skbinfo:  true,
			},
			entry: &IPSetEntry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0"),
				CIDR:    24,
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:net,net",
			setname:  "my-test-ipset-4",
			typename: "hash:net,net",
			options: IpsetCreateOptions{
				Replace:  true,
				Timeout:  &timeout,
				Counters: false,
				Comments: true,
				Skbinfo:  true,
			},
			entry: &IPSetEntry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0"),
				CIDR:    24,
				IP2:     net.ParseIP("10.99.0.0"),
				CIDR2:   24,
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:ip,ip",
			setname:  "my-test-ipset-5",
			typename: "hash:net,net",
			options: IpsetCreateOptions{
				Replace:  true,
				Timeout:  &timeout,
				Counters: false,
				Comments: true,
				Skbinfo:  true,
			},
			entry: &IPSetEntry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0"),
				IP2:     net.ParseIP("10.99.0.0"),
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:ip,port",
			setname:  "my-test-ipset-6",
			typename: "hash:ip,port",
			options: IpsetCreateOptions{
				Replace:  true,
				Timeout:  &timeout,
				Counters: false,
				Comments: true,
				Skbinfo:  true,
			},
			entry: &IPSetEntry{
				Comment:  "test comment",
				IP:       net.ParseIP("10.99.99.1"),
				Protocol: &protocalTCP,
				Port:     &port,
				Replace:  false,
			},
		},
		{
			desc:     "Type-hash:net,port,net",
			setname:  "my-test-ipset-7",
			typename: "hash:net,port,net",
			options: IpsetCreateOptions{
				Replace:  true,
				Timeout:  &timeout,
				Counters: false,
				Comments: true,
				Skbinfo:  true,
			},
			entry: &IPSetEntry{
				Comment:  "test comment",
				IP:       net.ParseIP("10.99.99.0"),
				CIDR:     24,
				IP2:      net.ParseIP("10.99.0.0"),
				CIDR2:    24,
				Protocol: &protocalTCP,
				Port:     &port,
				Replace:  false,
			},
		},
		{
			desc:     "Type-hash:mac",
			setname:  "my-test-ipset-8",
			typename: "hash:mac",
			options: IpsetCreateOptions{
				Replace:  true,
				Timeout:  &timeout,
				Counters: true,
				Comments: true,
				Skbinfo:  false,
			},
			entry: &IPSetEntry{
				Comment: "test comment",
				MAC:     net.HardwareAddr{0x26, 0x6f, 0x0d, 0x5b, 0xc1, 0x9d},
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:net,iface",
			setname:  "my-test-ipset-9",
			typename: "hash:net,iface",
			options: IpsetCreateOptions{
				Replace:  true,
				Timeout:  &timeout,
				Counters: true,
				Comments: true,
				Skbinfo:  false,
			},
			entry: &IPSetEntry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0"),
				CIDR:    24,
				IFace:   "eth0",
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:ip,mark",
			setname:  "my-test-ipset-10",
			typename: "hash:ip,mark",
			options: IpsetCreateOptions{
				Replace:  true,
				Timeout:  &timeout,
				Counters: true,
				Comments: true,
				Skbinfo:  false,
			},
			entry: &IPSetEntry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0"),
				Mark:    &timeout,
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:net6",
			setname:  "my-test-ipset-11",
			typename: "hash:net",
			options: IpsetCreateOptions{
				Replace:  true,
				Timeout:  &timeout,
				Counters: false,
				Comments: true,
				Skbinfo:  true,
				Family:   unix.AF_INET6,
			},
			entry: &IPSetEntry{
				Comment: "test comment",
				IP:      net.ParseIP("::1"),
				CIDR:    128,
				Replace: false,
			},
		},
		{
			desc:     "Type-hash:net6:net6",
			setname:  "my-test-ipset-11",
			typename: "hash:net,net",
			options: IpsetCreateOptions{
				Replace:  true,
				Timeout:  &timeout,
				Counters: false,
				Comments: true,
				Skbinfo:  true,
				Family:   unix.AF_INET6,
			},
			entry: &IPSetEntry{
				Comment: "test comment",
				IP:      net.ParseIP("::1"),
				CIDR:    128,
				IP2:     net.ParseIP("::2"),
				CIDR2:   128,
				Replace: false,
			},
		},
	}

	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			tearDown := setUpNetlinkTest(t)
			defer tearDown()

			err := IpsetCreate(tC.setname, tC.typename, tC.options)
			if err != nil {
				t.Fatal(err)
			}

			result, err := IpsetList(tC.setname)
			if err != nil {
				t.Fatal(err)
			}

			if result.SetName != tC.setname {
				t.Errorf("expected name to be '%s', but got '%s'", tC.setname, result.SetName)
			}

			if result.TypeName != tC.typename {
				t.Errorf("expected type to be '%s', but got '%s'", tC.typename, result.TypeName)
			}

			if *result.Timeout != timeout {
				t.Errorf("expected timeout to be %d, but got '%d'", timeout, *result.Timeout)
			}

			err = IpsetAdd(tC.setname, tC.entry)

			if err != nil {
				t.Error(result.Protocol, result.Family)
				t.Fatal(err)
			}

			exist, err := IpsetTest(tC.setname, tC.entry)
			if err != nil {
				t.Fatal(err)
			}
			if !exist {
				t.Errorf("entry should exist, but 'test' got false, case: %s", tC.desc)
			}

			result, err = IpsetList(tC.setname)

			if err != nil {
				t.Fatal(err)
			}

			if len(result.Entries) != 1 {
				t.Fatalf("expected 1 entry be created, got '%d'", len(result.Entries))
			}

			if tC.entry.IP != nil {
				if !tC.entry.IP.Equal(result.Entries[0].IP) {
					t.Fatalf("expected entry to be '%v', got '%v'", tC.entry.IP, result.Entries[0].IP)
				}
			}

			if tC.entry.CIDR > 0 {
				if result.Entries[0].CIDR != tC.entry.CIDR {
					t.Fatalf("expected cidr to be '%d', got '%d'", tC.entry.CIDR, result.Entries[0].CIDR)
				}
			}

			if tC.entry.IP2 != nil {
				if !tC.entry.IP2.Equal(result.Entries[0].IP2) {
					t.Fatalf("expected entry.ip2 to be '%v', got '%v'", tC.entry.IP2, result.Entries[0].IP2)
				}
			}

			if tC.entry.CIDR2 > 0 {
				if result.Entries[0].CIDR2 != tC.entry.CIDR2 {
					t.Fatalf("expected cidr2 to be '%d', got '%d'", tC.entry.CIDR2, result.Entries[0].CIDR2)
				}
			}

			if tC.entry.Port != nil {
				if *result.Entries[0].Protocol != *tC.entry.Protocol {
					t.Fatalf("expected protocol to be '%d', got '%d'", *tC.entry.Protocol, *result.Entries[0].Protocol)
				}
				if *result.Entries[0].Port != *tC.entry.Port {
					t.Fatalf("expected port to be '%d', got '%d'", *tC.entry.Port, *result.Entries[0].Port)
				}
			}

			if tC.entry.MAC != nil {
				if result.Entries[0].MAC.String() != tC.entry.MAC.String() {
					t.Fatalf("expected mac to be '%v', got '%v'", tC.entry.MAC, result.Entries[0].MAC)
				}
			}

			if tC.entry.IFace != "" {
				if result.Entries[0].IFace != tC.entry.IFace {
					t.Fatalf("expected iface to be '%v', got '%v'", tC.entry.IFace, result.Entries[0].IFace)
				}
			}

			if tC.entry.Mark != nil {
				if *result.Entries[0].Mark != *tC.entry.Mark {
					t.Fatalf("expected mark to be '%v', got '%v'", *tC.entry.Mark, *result.Entries[0].Mark)
				}
			}

			if result.Entries[0].Comment != tC.entry.Comment {
				// This is only supported in the kernel module from revision 2 or 4, so comments may be ignored.
				t.Logf("expected comment to be '%s', got '%s'", tC.entry.Comment, result.Entries[0].Comment)
			}

			err = IpsetDel(tC.setname, tC.entry)
			if err != nil {
				t.Fatal(err)
			}

			exist, err = IpsetTest(tC.setname, tC.entry)
			if err != nil {
				t.Fatal(err)
			}
			if exist {
				t.Errorf("entry should be deleted, but 'test' got true, case: %s", tC.desc)
			}

			result, err = IpsetList(tC.setname)
			if err != nil {
				t.Fatal(err)
			}

			if len(result.Entries) != 0 {
				t.Fatalf("expected 0 entries to exist, got %d", len(result.Entries))
			}

			err = IpsetDestroy(tC.setname)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIpsetBitmapCreateListWithTestCases(t *testing.T) {
	timeout := uint32(3)

	testCases := []struct {
		desc     string
		setname  string
		typename string
		options  IpsetCreateOptions
		entry    *IPSetEntry
	}{
		{
			desc:     "Type-bitmap:port",
			setname:  "my-test-ipset-11",
			typename: "bitmap:port",
			options: IpsetCreateOptions{
				Replace:  true,
				Timeout:  &timeout,
				Counters: true,
				Comments: false,
				Skbinfo:  false,
				PortFrom: 100,
				PortTo:   600,
			},
			entry: &IPSetEntry{
				Comment: "test comment",
				IP:      net.ParseIP("10.99.99.0"),
				CIDR:    26,
				Mark:    &timeout,
				Replace: false,
			},
		},
	}

	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			tearDown := setUpNetlinkTest(t)
			defer tearDown()

			err := IpsetCreate(tC.setname, tC.typename, tC.options)
			if err != nil {
				t.Fatal(err)
			}

			result, err := IpsetList(tC.setname)
			if err != nil {
				t.Fatal(err)
			}

			if tC.typename == "bitmap:port" {
				if result.PortFrom != tC.options.PortFrom || result.PortTo != tC.options.PortTo {
					t.Fatalf("expected port range %d-%d, got %d-%d", tC.options.PortFrom, tC.options.PortTo, result.PortFrom, result.PortTo)
				}
			} else if tC.typename == "bitmap:ip" {
				if result.IPFrom == nil || result.IPTo == nil || result.IPFrom.Equal(tC.options.IPFrom) || result.IPTo.Equal(tC.options.IPTo) {
					t.Fatalf("expected ip range %v-%v, got %v-%v", tC.options.IPFrom, tC.options.IPTo, result.IPFrom, result.IPTo)
				}
			}

		})
	}
}

func TestIpsetSwap(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ipset1 := "my-test-ipset-swap-1"
	ipset2 := "my-test-ipset-swap-2"

	err := IpsetCreate(ipset1, "hash:ip", IpsetCreateOptions{
		Replace: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = IpsetDestroy(ipset1)
	}()

	err = IpsetCreate(ipset2, "hash:ip", IpsetCreateOptions{
		Replace: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = IpsetDestroy(ipset2)
	}()

	err = IpsetAdd(ipset1, &IPSetEntry{
		IP: net.ParseIP("10.99.99.99"),
	})
	if err != nil {
		t.Fatal(err)
	}

	assertHasOneEntry := func(name string) {
		result, err := IpsetList(name)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Entries) != 1 {
			t.Fatalf("expected 1 entry be created, got '%d'", len(result.Entries))
		}
		if result.Entries[0].IP.String() != "10.99.99.99" {
			t.Fatalf("expected entry to be '10.99.99.99', got '%s'", result.Entries[0].IP.String())
		}
	}

	assertIsEmpty := func(name string) {
		result, err := IpsetList(name)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Entries) != 0 {
			t.Fatalf("expected 0 entry be created, got '%d'", len(result.Entries))
		}
	}

	assertHasOneEntry(ipset1)
	assertIsEmpty(ipset2)

	err = IpsetSwap(ipset1, ipset2)
	if err != nil {
		t.Fatal(err)
	}

	assertIsEmpty(ipset1)
	assertHasOneEntry(ipset2)
}

func nextIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// TestIpsetMaxElements tests that we can create an ipset containing
// 128k elements, which is double the default size (64k elements).
func TestIpsetMaxElements(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()

	ipsetName := "my-test-ipset-max"
	maxElements := uint32(128 << 10)

	err := IpsetCreate(ipsetName, "hash:ip", IpsetCreateOptions{
		Replace:     true,
		MaxElements: maxElements,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = IpsetDestroy(ipsetName)
	}()

	ip := net.ParseIP("10.0.0.0")
	for i := uint32(0); i < maxElements; i++ {
		err = IpsetAdd(ipsetName, &IPSetEntry{
			IP: ip,
		})
		if err != nil {
			t.Fatal(err)
		}
		nextIP(ip)
	}

	result, err := IpsetList(ipsetName)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != int(maxElements) {
		t.Fatalf("expected '%d' entry be created, got '%d'", maxElements, len(result.Entries))
	}
}
