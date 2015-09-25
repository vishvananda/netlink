package netlink

/*
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define IFREQ_SIZE sizeof(struct ifreq)
*/
import "C"

type ifReq struct {
	Name [C.IFNAMSIZ]byte
	Flags uint16
	pad [C.IFREQ_SIZE-C.IFNAMSIZ-2]byte
}
