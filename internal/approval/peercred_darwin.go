//go:build darwin

package approval

import (
	"net"

	"golang.org/x/sys/unix"
)

func getPeerPID(conn net.Conn) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, nil
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var peerPID int
	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		peerPID, sockErr = unix.GetsockoptInt(int(fd), 0 /* SOL_LOCAL */, unix.LOCAL_PEERPID)
	})
	if err != nil {
		return 0, err
	}
	return peerPID, sockErr
}
