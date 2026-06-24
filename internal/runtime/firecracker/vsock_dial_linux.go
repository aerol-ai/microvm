//go:build linux

package firecracker

// vsock_dial_linux.go is the production VsockDialer. Firecracker exposes
// host-initiated vsock through the AF_UNIX socket configured in PutVsock:
// connect to the UDS, write "CONNECT <port>\n", read "OK <host-port>\n",
// then use that same connection for the guest protocol.

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// linuxVsockDialer is the production VsockDialer. Zero value is usable.
type linuxVsockDialer struct{}

// NewLinuxVsockDialer returns the production VsockDialer for use from
// cmd/sandboxd/main.go.
func NewLinuxVsockDialer() VsockDialer { return &linuxVsockDialer{} }

// Dial opens Firecracker's host-side vsock UDS and connects to the guest port.
// The CID is included for logging/debugging; Firecracker already knows the
// guest CID from the PutVsock / snapshot state that created the UDS.
func (d *linuxVsockDialer) Dial(ctx context.Context, socketPath string, cid, port uint32) (io.ReadWriteCloser, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("vsock dial cid=%d port=%d: socket path is empty", cid, port)
	}

	var nd net.Dialer
	conn, err := nd.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("vsock dial socket=%s cid=%d port=%d: %w", socketPath, cid, port, err)
	}

	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("vsock dial socket=%s cid=%d port=%d: set deadline: %w", socketPath, cid, port, err)
		}
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("vsock dial socket=%s cid=%d port=%d: connect command: %w", socketPath, cid, port, err)
	}
	ack, err := readFirecrackerVsockAck(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("vsock dial socket=%s cid=%d port=%d: read connect ack: %w", socketPath, cid, port, err)
	}
	fields := strings.Fields(ack)
	if len(fields) != 2 || fields[0] != "OK" {
		_ = conn.Close()
		return nil, fmt.Errorf("vsock dial socket=%s cid=%d port=%d: unexpected connect ack %q", socketPath, cid, port, strings.TrimSpace(ack))
	}
	if _, err := strconv.ParseUint(fields[1], 10, 32); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("vsock dial socket=%s cid=%d port=%d: unexpected connect ack %q", socketPath, cid, port, strings.TrimSpace(ack))
	}

	return conn, nil
}

func readFirecrackerVsockAck(conn net.Conn) (string, error) {
	const maxAckLine = 128
	buf := make([]byte, 0, 32)
	one := make([]byte, 1)
	for len(buf) < maxAckLine {
		n, err := conn.Read(one)
		if n > 0 {
			buf = append(buf, one[0])
			if one[0] == '\n' {
				return string(buf), nil
			}
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("ack line exceeded %d bytes", maxAckLine)
}
