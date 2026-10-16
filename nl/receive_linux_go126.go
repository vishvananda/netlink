//go:build linux && go1.26

package nl

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func receiveNetlinkMessages(rawConn syscall.RawConn) ([]syscall.NetlinkMessage, unix.Sockaddr, error) {
	var (
		rb       [RECEIVE_BUFFER_SIZE]byte
		nr       int
		from     unix.Sockaddr
		innerErr error
	)
	err := rawConn.Read(func(fd uintptr) (done bool) {
		nr, from, innerErr = unix.Recvfrom(int(fd), rb[:], 0)
		return innerErr != unix.EWOULDBLOCK
	})
	if innerErr != nil {
		return nil, nil, innerErr
	}
	if err != nil {
		return nil, nil, err
	}
	nl, err := parseNetlinkMessage(rb[:], nr)
	return nl, from, err
}
