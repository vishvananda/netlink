module github.com/vishvananda/netlink/examples/resilient-nexthop-group

go 1.26.3

require github.com/vishvananda/netlink v1.3.1

require (
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/sys v0.10.0 // indirect
)

replace github.com/vishvananda/netlink => ../..
