package netlink

import (
	"reflect"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func featureBitsetAttr(t *testing.T, attrType int, values map[string]bool, noMask bool) syscall.NetlinkRouteAttr {
	t.Helper()
	bitset := nl.NewRtAttr(unix.NLA_F_NESTED|attrType, nil)
	if noMask {
		bitset.AddRtAttr(nl.ETHTOOL_A_BITSET_NOMASK, nil)
	}
	bits := bitset.AddRtAttr(unix.NLA_F_NESTED|nl.ETHTOOL_A_BITSET_BITS, nil)
	index := uint32(0)
	for name, value := range values {
		bit := bits.AddRtAttr(unix.NLA_F_NESTED|nl.ETHTOOL_A_BITSET_BITS_BIT, nil)
		bit.AddRtAttr(nl.ETHTOOL_A_BITSET_BIT_INDEX, nl.Uint32Attr(index))
		bit.AddRtAttr(nl.ETHTOOL_A_BITSET_BIT_NAME, nl.ZeroTerminated(name))
		if value {
			bit.AddRtAttr(nl.ETHTOOL_A_BITSET_BIT_VALUE, nil)
		}
		index++
	}
	return parseSerializedAttrs(t, []*nl.RtAttr{bitset})[0]
}

func TestParseNetDevFeatures(t *testing.T) {
	attrs := []syscall.NetlinkRouteAttr{
		featureBitsetAttr(t, nl.ETHTOOL_A_FEATURES_HW, map[string]bool{
			"rx-gro-hw":               true,
			"tx-generic-segmentation": true,
		}, true),
		featureBitsetAttr(t, nl.ETHTOOL_A_FEATURES_WANTED, map[string]bool{
			"rx-gro-hw":               false,
			"tx-generic-segmentation": true,
		}, false),
		featureBitsetAttr(t, nl.ETHTOOL_A_FEATURES_ACTIVE, map[string]bool{
			"rx-gro-hw":               false,
			"tx-generic-segmentation": true,
		}, false),
		featureBitsetAttr(t, nl.ETHTOOL_A_FEATURES_NOCHANGE, map[string]bool{
			"tx-generic-segmentation": true,
		}, true),
	}

	got, err := parseNetDevFeatures(attrs)
	if err != nil {
		t.Fatalf("parseNetDevFeatures failed: %v", err)
	}
	want := map[string]NetDevFeature{
		"rx-gro-hw": {
			Hardware: true,
		},
		"tx-generic-segmentation": {
			Hardware: true,
			Wanted:   true,
			Active:   true,
			NoChange: true,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("features = %#v, want %#v", got, want)
	}
}

func TestParseNetDevFeaturesSetReply(t *testing.T) {
	attrs := []syscall.NetlinkRouteAttr{
		featureBitsetAttr(t, nl.ETHTOOL_A_FEATURES_WANTED, nil, false),
		featureBitsetAttr(t, nl.ETHTOOL_A_FEATURES_ACTIVE, map[string]bool{
			"rx-gro-hw": true,
		}, false),
	}
	if err := parseNetDevFeaturesSetReply(attrs); err != nil {
		t.Fatalf("parseNetDevFeaturesSetReply failed: %v", err)
	}

	attrs = []syscall.NetlinkRouteAttr{
		featureBitsetAttr(t, nl.ETHTOOL_A_FEATURES_WANTED, map[string]bool{
			"tx-checksum-ipv4": false,
			"rx-gro-hw":        true,
		}, false),
		featureBitsetAttr(t, nl.ETHTOOL_A_FEATURES_ACTIVE, nil, false),
	}
	err := parseNetDevFeaturesSetReply(attrs)
	const want = "netlink: ethtool did not apply requested feature changes: rx-gro-hw=on, tx-checksum-ipv4=off"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestVerifyNetDevFeatureStates(t *testing.T) {
	features := map[string]NetDevFeature{
		"rx-gro-hw": {Active: true},
	}
	if err := verifyNetDevFeatureStates(map[string]bool{"rx-gro-hw": true}, features); err != nil {
		t.Fatalf("verifyNetDevFeatureStates failed: %v", err)
	}

	err := verifyNetDevFeatureStates(map[string]bool{
		"tx-checksum-ipv4": false,
		"rx-gro-hw":        false,
	}, features)
	const want = "netlink: ethtool did not apply requested feature changes: rx-gro-hw=off, tx-checksum-ipv4=off"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestParseNetDevFeaturesSetReplyRejectsMalformedData(t *testing.T) {
	tests := []struct {
		name  string
		attrs []syscall.NetlinkRouteAttr
	}{
		{
			name: "missing wanted bitset",
			attrs: []syscall.NetlinkRouteAttr{
				featureBitsetAttr(t, nl.ETHTOOL_A_FEATURES_ACTIVE, nil, false),
			},
		},
		{
			name: "missing active bitset",
			attrs: []syscall.NetlinkRouteAttr{
				featureBitsetAttr(t, nl.ETHTOOL_A_FEATURES_WANTED, nil, false),
			},
		},
		{
			name: "malformed active bitset",
			attrs: []syscall.NetlinkRouteAttr{
				featureBitsetAttr(t, nl.ETHTOOL_A_FEATURES_WANTED, nil, false),
				routeAttr(nl.ETHTOOL_A_FEATURES_ACTIVE, nil),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := parseNetDevFeaturesSetReply(test.attrs); err == nil {
				t.Fatal("accepted a malformed features set reply")
			}
		})
	}
}

func TestParseNetDevFeatureBitsetAcceptsNonTerminatedName(t *testing.T) {
	bitset := nl.NewRtAttr(unix.NLA_F_NESTED|nl.ETHTOOL_A_FEATURES_ACTIVE, nil)
	bits := bitset.AddRtAttr(unix.NLA_F_NESTED|nl.ETHTOOL_A_BITSET_BITS, nil)
	bit := bits.AddRtAttr(unix.NLA_F_NESTED|nl.ETHTOOL_A_BITSET_BITS_BIT, nil)
	bit.AddRtAttr(nl.ETHTOOL_A_BITSET_BIT_NAME, []byte("rx-gro-hw"))
	bit.AddRtAttr(nl.ETHTOOL_A_BITSET_BIT_VALUE, nil)

	attr := parseSerializedAttrs(t, []*nl.RtAttr{bitset})[0]
	got, err := parseNetDevFeatureBitset(attr)
	if err != nil {
		t.Fatalf("parseNetDevFeatureBitset failed: %v", err)
	}
	want := map[string]bool{"rx-gro-hw": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("features = %v, want %v", got, want)
	}
}

func TestParseNetDevFeatureBitsetSkipsUnnamedBits(t *testing.T) {
	attr := featureBitsetAttr(t, nl.ETHTOOL_A_FEATURES_ACTIVE, map[string]bool{"": true}, true)
	got, err := parseNetDevFeatureBitset(attr)
	if err != nil {
		t.Fatalf("parseNetDevFeatureBitset failed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("features = %v, want empty", got)
	}
}

func TestParseNetDevFeatureBitsetRejectsMalformedData(t *testing.T) {
	compact := nl.NewRtAttr(unix.NLA_F_NESTED|nl.ETHTOOL_A_FEATURES_ACTIVE, nil)
	compact.AddRtAttr(nl.ETHTOOL_A_BITSET_VALUE, []byte{1, 0, 0, 0})
	tests := []struct {
		name string
		attr syscall.NetlinkRouteAttr
	}{
		{
			name: "compact",
			attr: parseSerializedAttrs(t, []*nl.RtAttr{compact})[0],
		},
		{
			name: "missing bits",
			attr: routeAttr(nl.ETHTOOL_A_FEATURES_ACTIVE, nil),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseNetDevFeatureBitset(test.attr); err == nil {
				t.Fatal("accepted malformed feature bitset")
			}
		})
	}
}

func TestNewNetDevFeaturesSetAttrs(t *testing.T) {
	attrs, err := newNetDevFeaturesSetAttrs(7, map[string]bool{
		"tx-checksum-ipv4": false,
		"rx-gro-hw":        true,
	})
	if err != nil {
		t.Fatalf("newNetDevFeaturesSetAttrs failed: %v", err)
	}
	top := attrsByType(parseSerializedAttrs(t, attrs))
	wanted := top[nl.ETHTOOL_A_FEATURES_WANTED]
	wantedAttrs, err := nl.ParseRouteAttr(wanted.Value)
	if err != nil {
		t.Fatal(err)
	}
	bits := attrsByType(wantedAttrs)[nl.ETHTOOL_A_BITSET_BITS]
	entries, err := nl.ParseRouteAttr(bits.Value)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("encoded %d feature entries, want 2", len(entries))
	}

	names := make([]string, 0, 2)
	values := make(map[string]bool)
	for _, entry := range entries {
		fields, err := nl.ParseRouteAttr(entry.Value)
		if err != nil {
			t.Fatal(err)
		}
		byType := attrsByType(fields)
		nameValue := byType[nl.ETHTOOL_A_BITSET_BIT_NAME].Value
		name := string(nameValue[:len(nameValue)-1])
		names = append(names, name)
		_, values[name] = byType[nl.ETHTOOL_A_BITSET_BIT_VALUE]
	}
	if !reflect.DeepEqual(names, []string{"rx-gro-hw", "tx-checksum-ipv4"}) {
		t.Fatalf("feature order = %v", names)
	}
	if !values["rx-gro-hw"] || values["tx-checksum-ipv4"] {
		t.Fatalf("feature values = %v", values)
	}
}

func TestNewNetDevFeaturesSetAttrsRejectsInvalidConfig(t *testing.T) {
	tests := []map[string]bool{
		nil,
		{"": true},
		{"bad\x00name": true},
	}
	for _, config := range tests {
		if _, err := newNetDevFeaturesSetAttrs(1, config); err == nil {
			t.Fatalf("accepted invalid feature config %#v", config)
		}
	}
}
