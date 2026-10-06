//go:build linux

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
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			sockErr = err
			return
		}
		peerPID = int(ucred.Pid)
	})
	if err != nil {
		return 0, err
	}
	return peerPID, sockErr
}
