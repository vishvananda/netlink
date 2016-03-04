// +build !ppc64,!ppc64le

package netlink

const (
	syscall_TUNSETIFF     = 0x400454ca
	syscall_TUNSETPERSIST = 0x400454ca
)
