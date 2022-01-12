#!/usr/bin/env bash
sudo modprobe ip_gre
sudo modprobe nf_conntrack
sudo modprobe nf_conntrack_netlink
# these modules not available
# sudo modprobe nf_conntrack_ipv4
# sudo modprobe nf_conntrack_ipv6
sudo modprobe sch_hfsc
sudo modprobe sch_sfq
