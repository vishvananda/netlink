package netlink

import "syscall"

// ioctl bonding calls.
const (
	SIOCBONDENSLAVE        = 0x8990 /* enslave a device to the bond */
	SIOCBONDRELEASE        = 0x8991 /* release a slave from the bond*/
	SIOCBONDSETHWADDR      = 0x8992 /* set the hw addr of the bond  */
	SIOCBONDSLAVEINFOQUERY = 0x8993 /* rtn info about slave state   */
	SIOCBONDINFOQUERY      = 0x8994 /* rtn info about bond state    */
	SIOCBONDCHANGEACTIVE   = 0x8995 /* update to a new active slave */
)

// IfreqSlave struct for ioctl syscall.
type IfreqSlave struct {
	Name  [syscall.IFNAMSIZ]byte
	Slave [syscall.IFNAMSIZ]byte
}

// getIfScoket create UDP socket. This socket can be used to make ioctl call.
func getIfSocket() (fd int, err error) {
	for _, socket := range []int{
		syscall.AF_INET,
		syscall.AF_PACKET,
		syscall.AF_INET6,
	} {
		if fd, err = syscall.Socket(socket, syscall.SOCK_DGRAM, 0); err == nil {
			break
		}
	}
	if err == nil {
		return fd, nil
	}
	return -1, err
}
