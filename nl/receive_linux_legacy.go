//go:build linux && !go1.26

package nl

import (
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var receiveBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, RECEIVE_BUFFER_SIZE)
		return &buf
	},
}

func receiveNetlinkMessages(rawConn syscall.RawConn) ([]syscall.NetlinkMessage, unix.Sockaddr, error) {
	bufp := receiveBufferPool.Get().(*[]byte)
	rb := *bufp
	defer receiveBufferPool.Put(bufp)

	var (
		nr       int
		from     unix.Sockaddr
		innerErr error
	)
	err := rawConn.Read(func(fd uintptr) (done bool) {
		nr, from, innerErr = unix.Recvfrom(int(fd), rb, 0)
		return innerErr != unix.EWOULDBLOCK
	})
	if innerErr != nil {
		return nil, nil, innerErr
	}
	if err != nil {
		return nil, nil, err
	}
	nl, err := parseNetlinkMessage(rb, nr)
	return nl, from, err
}
