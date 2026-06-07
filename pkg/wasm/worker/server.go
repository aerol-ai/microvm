package worker

import (
	"net"
	"os"
)

// Serve accepts framed control messages on conn until EOF or an unrecoverable error.
// TriggerPanic is test-only: it deliberately panics inside a host function path
// so supervisors can prove worker crashes do not take down the parent daemon.
func Serve(conn net.Conn) error {
	defer conn.Close()
	for {
		env, err := readFrame(conn)
		if err != nil {
			return err
		}
		switch env.Type {
		case MsgHealthPing:
			if err := writeFrame(conn, Envelope{Type: MsgPong, SandboxID: env.SandboxID}); err != nil {
				return err
			}
		case MsgTriggerPanic:
			panic("wasm worker test panic")
		default:
			if err := writeFrame(conn, Envelope{
				Type:      MsgInvokeResult,
				SandboxID: env.SandboxID,
			}); err != nil {
				return err
			}
		}
	}
}

// ServeSocketPath listens on a Unix domain socket and serves one connection at a time.
// Used by worker subprocess entrypoints and integration tests.
func ServeSocketPath(socketPath string) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		if err := Serve(conn); err != nil {
			return err
		}
	}
}
