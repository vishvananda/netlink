//go:build !linux
// +build !linux

package netlink

type (
	XfrmPolicy struct{}
	XfrmState  struct{}
)
