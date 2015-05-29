package netlink

import (
	"errors"
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

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), SIOCBONDENSLAVE, uintptr(unsafe.Pointer(ifreq)))
	if errno != 0 {
		return errno
	}
	return nil
}

// LinkStatistics get link stats - equivalent to ethtool --statistics
func LinkStatistics(link Link) error {
	// TODO: implement
	return errors.New("unimplemented")
}

// LinkPeerIndex get veth peer index.
func LinkPeerIndex(link *Veth) (int, error) {
	// TODO write generic functions for LinkStatistics
	fd, err := getIfSocket()
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	e := &sset{cmd: ETHTOOL_GSSET_INFO, mask: 1 << ETH_SS_STATS}

	ifreq := &IfreqData{Data: uintptr(unsafe.Pointer(e))}
	copy(ifreq.Name[:syscall.IFNAMSIZ-1], link.Name)
	if err := ioctl(fd, uintptr(unsafe.Pointer(ifreq))); err != nil {
		return 0, err
	}

	strings := &gstrings{cmd: ETHTOOL_GSTRINGS, string_set: ETH_SS_STATS, lenght: e.data[0]}
	ifreq.Data = uintptr(unsafe.Pointer(strings))
	if err := ioctl(fd, uintptr(unsafe.Pointer(ifreq))); err != nil {
		return 0, err
	}

	stats := &stats{cmd: ETHTOOL_GSTATS, n_stats: strings.lenght}
	ifreq.Data = uintptr(unsafe.Pointer(stats))
	if err := ioctl(fd, uintptr(unsafe.Pointer(ifreq))); err != nil {
		return 0, err
	}
	return int(stats.data[0]), nil
}
