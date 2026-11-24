package worker

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

// Lent folders (privilege mode split, plans/security-gaps-m1-m4.md, M1 PR
// 15). In single mode sandboxd opens each folder a message names, a WASM
// sandbox's mount points among them, and passes it with the message
// (openGrants). In split the root helper keeps those mount points and
// sandboxd cannot reach them, so they are lent instead:
//
//   - sandboxd marks them (wasmengine.Preopen.Lent), sends the message
//     without them, and has the helper lend them (lend_client.go): right
//     after an instantiate or a restore, which is when a worker comes to
//     hold the sandbox, and before every other message that names them,
//     as single mode passes them with each one;
//   - the helper connects to the worker on the socket it serves the worker
//     on, asks whether it holds the sandbox, and only then passes the open
//     folders under the sandbox's name (LendFolders). The worker records
//     them as it records every grant (readGrantedFrame).
//
// The helper is root and the worker is not trusted: each reply is read
// with the caller's deadline, at most lendReplyMax bytes, and with read(2),
// so a descriptor the worker sends back is dropped, never kept.

// ErrLendForeign: the worker says it holds another sandbox.
var ErrLendForeign = errors.New("the WASM host holds another sandbox")

// ErrLendNotHeld: the worker does not say it holds the sandbox.
var ErrLendNotHeld = errors.New("the WASM host does not hold the sandbox")

// lendReplyMax bounds a worker's reply to the helper: a status or a pong
// is a few dozen bytes.
const lendReplyMax = 64 << 10

// LendFolders passes files, open folders named by paths, to the worker on
// conn for sandboxID, once the worker says it holds sandboxID. The caller
// sets conn's deadline.
func LendFolders(conn *net.UnixConn, sandboxID string, paths []string, files []*os.File) error {
	if len(files) == 0 || len(files) != len(paths) || len(files) > maxFrameFiles {
		return fmt.Errorf("lend %d folders named %d times", len(files), len(paths))
	}
	if err := writeFrame(conn, Envelope{Type: MsgInstanceStatus, SandboxID: sandboxID}); err != nil {
		return err
	}
	reply, err := readSmallFrame(conn)
	if err != nil {
		return err
	}
	var st instanceStatusPayload
	if reply.Type != MsgOK || decodePayload(reply.Payload, &st) != nil {
		return fmt.Errorf("the WASM host answered the status question with %q", reply.Type)
	}
	switch {
	case st.Loaded && st.SandboxID == sandboxID:
	case st.SandboxID != "" && st.SandboxID != sandboxID:
		return ErrLendForeign
	default:
		return ErrLendNotHeld
	}
	if err := writeFrameFiles(conn, Envelope{Type: MsgHealthPing, SandboxID: sandboxID, FDPaths: paths}, files); err != nil {
		return err
	}
	if reply, err = readSmallFrame(conn); err != nil {
		return err
	}
	if reply.Type != MsgPong {
		return fmt.Errorf("the WASM host answered the loan with %q", reply.Type)
	}
	return nil
}

// readSmallFrame reads one frame of at most lendReplyMax bytes with r's
// Read.
func readSmallFrame(r io.Reader) (Envelope, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Envelope{}, err
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size == 0 || size > lendReplyMax {
		return Envelope{}, fmt.Errorf("a WASM host's reply of %d bytes", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return Envelope{}, err
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return Envelope{}, err
	}
	return env, nil
}
