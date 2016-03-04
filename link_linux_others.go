// +build linux
// +build x86_64 arm64 s390x

package netlink

const (
	syscall_TUNSETIFF     = 0x400454ca
	syscall_TUNSETPERSIST = 0x400454ca
)
