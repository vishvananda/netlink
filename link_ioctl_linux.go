package netlink

import (
	"syscall"
	"unsafe"
)

// LinkSetBondSlave add slave to bond link via ioctl interface.
func LinkSetBondSlave(link Link, master *Bond) error {
	// TODO: implement bond ABI_VER < 2 if needed - look ifenslave sources
	fd, err := getIfSocket()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	ifreq := &IfreqSlave{}
	copy(ifreq.Name[:syscall.IFNAMSIZ-1], master.Attrs().Name)
	copy(ifreq.Slave[:syscall.IFNAMSIZ-1], link.Attrs().Name)

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		SIOCBONDENSLAVE, uintptr(unsafe.Pointer(ifreq))); errno != 0 {
		return errno
	}
	return nil
}
