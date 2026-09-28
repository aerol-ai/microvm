//go:build linux

package service

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// platformOriginalDstPort reads SO_ORIGINAL_DST (the pre-NAT destination) of
// a REDIRECTed TCP connection.
func platformOriginalDstPort(conn net.Conn) (int, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, errors.New("not a TCP connection")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return 0, err
	}
	var port int
	var opErr error
	ctlErr := raw.Control(func(fd uintptr) {
		// struct sockaddr_in: family(2) port(2, network order) addr(4) pad(8).
		addr, err := unix.GetsockoptIPv6Mreq(int(fd), syscall.SOL_IP, unix.SO_ORIGINAL_DST)
		if err != nil {
			opErr = err
			return
		}
		port = int(binary.BigEndian.Uint16(addr.Multiaddr[2:4]))
	})
	if ctlErr != nil {
		return 0, ctlErr
	}
	if opErr != nil {
		return 0, opErr
	}
	return port, nil
}
