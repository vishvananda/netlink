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

// ioctl for statistics.
const (
	SIOCETHTOOL = 0x8946

	ETHTOOL_GSTRINGS   = 0x0000001b /* get specified string set */
	ETHTOOL_GSTATS     = 0x0000001d /* get NIC-specific statistics */
	ETHTOOL_GSSET_INFO = 0x00000037 /* Get string set info */
)

// string set id.
const (
	ETH_SS_TEST            = iota // self-test result names, for use with %ETHTOOL_TEST
	ETH_SS_STATS                  // statistic names, for use with %ETHTOOL_GSTATS
	ETH_SS_PRIV_FLAGS             // driver private flag names, for use with
	_ETH_SS_NTUPLE_FILTERS        // deprecated
	ETH_SS_FEATURES               // device feature names
	ETH_SS_RSS_HASH_FUNCS         // RSS hush function names
)

// IfreqSlave struct for ioctl syscall.
type IfreqSlave struct {
	Name  [syscall.IFNAMSIZ]byte
	Slave [syscall.IFNAMSIZ]byte
}

// IfreqData struct for ioctl syscall.
type IfreqData struct {
	Name [syscall.IFNAMSIZ]byte
	Data uintptr
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

func ioctl(fd int, ifreq uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), SIOCETHTOOL, ifreq)
	if errno != 0 {
		return errno
	}
	return nil
}

type sset struct {
	cmd      uint32
	reserved uint32
	mask     uint64
	data     [1]uint32
}

type gstrings struct {
	cmd        uint32
	string_set uint32
	lenght     uint32
	data       [32]byte
}

type stats struct {
	cmd     uint32
	n_stats uint32
	data    [1]uint64
}
