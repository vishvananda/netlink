//go:build linux
// +build linux

// Resilient nexthop group creates a resilient group of nexthops.
// The library provides the equivalent feature like commandline below:
//
// ip nexthop add id 1 via 10.0.0.1 dev eth0
// ip nexthop add id 2 via 10.0.0.2 dev eth0
// ip nexthop add id 100 group 1/2 type res buckets 8 idle_timer 60 unbalanced_timer 300

// Usage
// sudo resilient-nexthop-group -dev eth0 -gw 10.0.0.1,10.0.0.2
// sudo resilient-nexthop-group -dev eth0 -gw 10.0.0.1 -cleanup

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
)

var (
	dev             = flag.String("dev", "", "interface the members of nexthop points to")
	gateways        = flag.String("gw", "", "comma separated list of gateways for the nexthop group")
	groupID         = flag.Uint("group-id", 100, "nexthop group ID")
	memberBaseID    = flag.Uint("members-base-id", 1, "base ID for the members of the nexthop group")
	buckets         = flag.Uint("buckets", 8, "number of buckets for the resilient nexthop group")
	idleTimer       = flag.Uint("idle-timer", 60, "idle timer for the resilient nexthop group in seconds")
	unbalancedTimer = flag.Uint("unbalanced-timer", 60, "unbalanced timer for the resilient nexthop group in seconds")
	cleanup         = flag.Bool("cleanup", false, "cleanup the nexthop group and its members")
)

func main() {
	log.SetFlags(0)
	flag.Parse()

	if *dev == "" || *gateways == "" {
		flag.Usage()
		log.Fatal("device and gateways must be specified")
	}

	link, err := netlink.LinkByName(*dev)
	if err != nil {
		log.Fatalf("failed to get link by name %s: %v", *dev, err)
	}

	members, err := parseGateways(*gateways)
	if err != nil {
		log.Fatalf("failed to parse gateways: %v", err)
	}

	if *groupID >= *memberBaseID && *groupID < *memberBaseID+uint(len(members)) {
		log.Fatalf("group ID %d overlaps with member nexthop IDs [%d, %d); pick a distinct ID",
			*groupID, *memberBaseID, *memberBaseID+uint(len(members)))
	}

	if *cleanup {
		cleanupNexthops(members)
		return
	}

	group := make([]netlink.NexthopGroupMember, 0, len(members))

	for i, m := range members {
		id := uint32(*memberBaseID) + uint32(i)
		nh := &netlink.Nexthop{
			ID:      id,
			OIF:     uint32(link.Attrs().Index),
			Gateway: m.gateway,
		}
		if err := netlink.NexthopReplace(nh); err != nil {
			log.Fatalf("failed to add nexthop %v: %v", nh, err)
		}
		log.Printf("created member nexthop %d via %s: %v", id, m.gateway, *dev)

		group = append(group, netlink.NexthopGroupMember{
			ID:     id,
			Weight: m.weight,
		})
	}

	nhg := &netlink.Nexthop{
		ID:        uint32(*groupID),
		Group:     group,
		GroupType: netlink.NEXTHOP_GRP_TYPE_RES,
		ResilientGroup: &netlink.NexthopResilientGroup{
			Buckets:         uint16(*buckets),
			IdleTimer:       uint32(*idleTimer),
			UnbalancedTimer: uint32(*unbalancedTimer),
		},
	}
	if err := netlink.NexthopReplace(nhg); err != nil {
		log.Fatalf("failed to add resilient nexthop group: %v", err)
	}
	log.Println(describeGroup(nhg))
}

func cleanupNexthops(members []member) {
	group := &netlink.Nexthop{ID: uint32(*groupID)}
	if err := netlink.NexthopDel(group); err != nil {
		log.Fatalf("failed to delete resilient nexthop group %d: %v", *groupID, err)
	}
	log.Printf("deleted resilient nexthop group %d", *groupID)

	for i := range members {
		id := uint32(*memberBaseID) + uint32(i)
		member := &netlink.Nexthop{ID: id}
		if err := netlink.NexthopDel(member); err != nil {
			log.Fatalf("failed to delete member nexthop %d: %v", id, err)
		}
		log.Printf("deleted member nexthop %d", id)
	}
}

type member struct {
	gateway net.IP
	weight  uint16
}

func parseGateways(gateways string) ([]member, error) {
	var members []member
	for _, field := range strings.Split(gateways, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		addr, weight := field, uint16(1)
		if at := strings.Index(field, ":"); at != -1 {
			addr = field[:at]
			w, err := strconv.Atoi(field[at+1:])
			if err != nil {
				return nil, fmt.Errorf("invalid weight for gateway %s: %v", field, err)
			}
			if w < 1 || w > 256 {
				return nil, fmt.Errorf("weight for gateway %s must be between 1 and 256", field)
			}
			weight = uint16(w)
		}
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("invalid gateway IP: %s", addr)
		}
		members = append(members, member{
			gateway: ip,
			weight:  weight,
		})
	}
	return members, nil
}

func describeGroup(nh *netlink.Nexthop) string {
	entries := make([]string, 0, len(nh.Group))
	for _, entry := range nh.Group {
		entries = append(entries, fmt.Sprintf("%d", entry.ID))
	}

	desc := fmt.Sprintf("Nexthop group ID: %d, Members: [%s]", nh.ID, strings.Join(entries, ", "))
	if nh.ResilientGroup != nil {
		desc += fmt.Sprintf(", Buckets: %d, IdleTimer: %d, UnbalancedTimer: %d, UnbalancedTime: %d",
			nh.ResilientGroup.Buckets, nh.ResilientGroup.IdleTimer, nh.ResilientGroup.UnbalancedTimer, nh.ResilientGroup.UnbalancedTime)
	}
	return desc
}
