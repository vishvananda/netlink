//go:build !linux
// +build !linux

package netlink

import "fmt"

func (p Proto) String() string {
	return fmt.Sprintf("%d", p)
}
