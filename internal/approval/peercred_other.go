//go:build !darwin && !linux

package approval

import "net"

func getPeerPID(conn net.Conn) (int, error) {
	return 0, nil
}
