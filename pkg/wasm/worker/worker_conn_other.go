//go:build !linux

package worker

import (
	"net"
	"os"
)

// wrapWorkerConn: off Linux no worker drops its privileges, and none
// answers guest_listener with a socket (hostDialSupported), so sandboxd's
// connections to workers are used as they are.
func wrapWorkerConn(c net.Conn, _ string) (net.Conn, error) { return c, nil }

// readGuestListenerReply reads a guest_listener reply, which off Linux
// carries no socket.
func readGuestListenerReply(conn net.Conn) (Envelope, *os.File, error) {
	env, err := readFrame(conn)
	return env, nil, err
}
