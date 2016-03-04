// +build linux
// +build ppc64 ppc64le

package netlink

const (
	syscall_TUNSETIFF     = 0x800454ca
	syscall_TUNSETPERSIST = 0x800454ca
)
