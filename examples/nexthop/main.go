//go:build linux
// +build linux

// Basic nexthop creates a nexthop object
// The library provides the equivalent feature like commandline below:
//
// ip nexthop add id 1 via 10.0.0.1 dev eth0
// ip nexthop del id 1
// ip nexthop show

// Usage
// sudo nexthop -dev eth0 -gw 10.0.0.1
// sudo nexthop -dev eth0 -gw 10.0.0.1 -id 2
// sudo nexthop -dev eth0 -gw 10.0.0.1 -cleanup

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
	dev       = flag.String("dev", "", "interface the nexthop points to")
	gateway   = flag.String("gw", "", "gateway IP for the nexthop")
	id        = flag.Uint("id", 1, "nexthop ID")
	blackhole = flag.Bool("blackhole", false, "create a blackhole nexthop")
	cleanup   = flag.Bool("cleanup", false, "cleanup the nexthop")
)

func main() {
	log.SetFlags(0)
	flag.Parse()

	if *dev == "" {
		flag.Usage()
		log.Fatal("device must be specified")
	}

	link, err := netlink.LinkByName(*dev)
	if err != nil {
		log.Fatalf("failed to get link by name %s: %v", *dev, err)
	}

	nh, err := buildNexthop(link)
	if err != nil {
		log.Fatalf("failed to build nexthop: %v", err)
	}

	if *cleanup {
		cleanupNexthop(nh)
		return
	}

	if err := netlink.NexthopReplace(nh); err != nil {
		log.Fatalf("failed to add nexthop %v: %v", nh, err)
	}
	log.Printf("created nexthop %d via %s dev %s", nh.ID, nh.Gateway, *dev)

	listNexthops()
}

func buildNexthop(link netlink.Link) (*netlink.Nexthop, error) {
	nh := &netlink.Nexthop{
		ID: uint32(*id),
	}

	if *blackhole {
		nh.Blackhole = true
		return nh, nil
	}

	nh.OIF = uint32(link.Attrs().Index)
	if *gateway == "" {
		return nil, fmt.Errorf("gateway (-gw) is required unless -blackhole is set")
	}
	ip := net.ParseIP(*gateway)
	if ip == nil {
		return nil, fmt.Errorf("invalid gateway IP: %s", *gateway)
	}
	nh.Gateway = ip
	return nh, nil
}

func cleanupNexthop(nh *netlink.Nexthop) {
	del := &netlink.Nexthop{ID: nh.ID}
	if err := netlink.NexthopDel(del); err != nil {
		log.Fatalf("failed to delete nexthop %d: %v", nh.ID, err)
	}
	log.Printf("deleted nexthop %d", nh.ID)
}

func listNexthops() {
	nhs, err := netlink.NexthopList()
	if err != nil {
		log.Fatalf("failed to list nexthops: %v", err)
	}
	if len(nhs) == 0 {
		log.Println("no nexthops present")
		return
	}
	rows := make([]string, 0, len(nhs))
	for _, nh := range nhs {
		rows = append(rows, describeNexthop(&nh))
	}
	log.Printf("nexthops:\n%s", strings.Join(rows, "\n"))
}

func describeNexthop(nh *netlink.Nexthop) string {
	var parts []string
	if nh.Blackhole {
		parts = append(parts, "blackhole")
	}
	if nh.OIF > 0 {
		parts = append(parts, "dev "+strconv.FormatUint(uint64(nh.OIF), 10))
	}
	if nh.Gateway != nil {
		parts = append(parts, "via "+nh.Gateway.String())
	}
	parts = append(parts, "protocol "+nh.Protocol.String())
	return fmt.Sprintf("id %d %s", nh.ID, strings.Join(parts, " "))
}
