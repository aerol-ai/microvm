package worker

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

const maxFrameSize = 16 << 20 // 16 MiB — generous for Phase 1 control messages

// maxFrameFiles caps the descriptors one frame carries: a module, a
// sandbox's /work, its mount folders and four snapshot files fit with room
// to spare. The reader's control buffer is sized for it, so a frame never
// arrives with some of its descriptors cut off.
const maxFrameFiles = 32

func encodeFrame(env Envelope) ([]byte, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	if len(body) > maxFrameSize {
		return nil, fmt.Errorf("frame too large: %d bytes", len(body))
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	return frame, nil
}

func writeFrame(w io.Writer, env Envelope) error {
	frame, err := encodeFrame(env)
	if err != nil {
		return err
	}
	if _, err := w.Write(frame[:4]); err != nil {
		return err
	}
	_, err = w.Write(frame[4:])
	return err
}

// writeFrameFiles writes env with files' descriptors attached, which the
// kernel delivers with the frame's first byte. env.FDPaths must name the
// files in order. A connection that cannot carry descriptors (not a Unix
// socket) gets the frame without them, and the worker opens the paths.
func writeFrameFiles(w io.Writer, env Envelope, files []*os.File) error {
	uc, ok := w.(*net.UnixConn)
	if len(files) == 0 || !ok {
		env.FDPaths = nil
		return writeFrame(w, env)
	}
	if len(files) != len(env.FDPaths) || len(files) > maxFrameFiles {
		return fmt.Errorf("frame names %d paths for %d descriptors", len(env.FDPaths), len(files))
	}
	frame, err := encodeFrame(env)
	if err != nil {
		return err
	}
	fds := make([]int, len(files))
	for i, f := range files {
		fd, err := rawFD(f)
		if err != nil {
			return err
		}
		fds[i] = fd
	}
	// The descriptors ride the 4-byte header (sendmsg); the body goes with
	// a plain write. The reader takes the header with recvmsg and the body
	// with read (readFrameFiles): Go's race detector counts a write and a
	// read on a descriptor as ordering the two goroutines, and does not
	// count sendmsg or recvmsg, so a frame sent and read whole with those
	// would leave the ordering the socket gives invisible to it.
	n, _, err := uc.WriteMsgUnix(frame[:4], syscall.UnixRights(fds...), nil)
	if err != nil {
		return err
	}
	_, err = uc.Write(frame[n:])
	return err
}

// readFrame reads a frame that carries no descriptors. It reads with
// read(2) only: descriptors a sender attached anyway are dropped by the
// kernel, never held here (a worker's reply is untrusted input).
func readFrame(r io.Reader) (Envelope, error) {
	env, _, err := readFrameFrom(r.Read, r.Read, nil)
	return env, err
}

// errTooManyFDs fails a frame that carried more descriptors than any
// message needs (maxFrameFiles).
var errTooManyFDs = fmt.Errorf("frame carries more than %d descriptors", maxFrameFiles)

// readFrameFiles reads one frame and the descriptors that came with it,
// named by env.FDPaths. Descriptors that do not match the names one for
// one (a truncated control message, a sender bug) are all closed: the
// worker then opens the paths itself, as it would for an older sandboxd.
func readFrameFiles(r io.Reader) (Envelope, []*os.File, error) {
	uc, ok := r.(*net.UnixConn)
	if !ok {
		return readFrameFrom(r.Read, r.Read, nil)
	}
	var fds []int
	truncated := false
	oob := make([]byte, syscall.CmsgSpace(maxFrameFiles*4))
	tooMany := false
	read := func(b []byte) (int, error) {
		n, oobn, flags, _, err := uc.ReadMsgUnix(b, oob)
		if oobn > 0 {
			got, perr := parseRights(oob[:oobn])
			if len(fds)+len(got) > maxFrameFiles {
				// The header may take a few reads, each with its own
				// descriptors: never hold more than one message's worth.
				for _, fd := range got {
					_ = syscall.Close(fd)
				}
				tooMany = true
			} else {
				fds = append(fds, got...)
			}
			truncated = truncated || perr != nil
		}
		truncated = truncated || flags&syscall.MSG_CTRUNC != 0
		if tooMany && err == nil {
			err = errTooManyFDs
		}
		return n, err
	}
	// Descriptors arrive with the header (writeFrameFiles); the body is
	// read with read(2), which the race detector sees (see there), and
	// which drops any descriptor sent with it.
	env, files, err := readFrameFrom(read, uc.Read, func() []int { return fds })
	if err == nil && tooMany {
		err = errTooManyFDs
	}
	if err != nil {
		closeFiles(files)
		return env, nil, err
	}
	if truncated || len(files) != len(env.FDPaths) {
		closeFiles(files)
		return env, nil, nil
	}
	return env, files, nil
}

// readFrameFrom reads the 4-byte header with readHdr and the body with
// readBody; received lists the descriptors read so far.
func readFrameFrom(readHdr, readBody func([]byte) (int, error), received func() []int) (Envelope, []*os.File, error) {
	var files []*os.File
	collect := func() {
		if received == nil {
			return
		}
		for _, fd := range received()[len(files):] {
			files = append(files, os.NewFile(uintptr(fd), "granted"))
		}
	}
	readFull := func(read func([]byte) (int, error), buf []byte, first bool) error {
		got := 0
		for got < len(buf) {
			n, err := read(buf[got:])
			got += n
			collect()
			if err == nil && n == 0 {
				err = io.EOF
			}
			if err != nil {
				if got >= len(buf) {
					return nil
				}
				// As io.ReadFull reports it: EOF before a frame, a short
				// frame after its start.
				if errors.Is(err, io.EOF) {
					if got > 0 || !first {
						return io.ErrUnexpectedEOF
					}
					return io.EOF
				}
				return err
			}
		}
		return nil
	}
	var hdr [4]byte
	if err := readFull(readHdr, hdr[:], true); err != nil {
		return Envelope{}, files, err
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size == 0 || size > maxFrameSize {
		return Envelope{}, files, fmt.Errorf("invalid frame size %d", size)
	}
	body := make([]byte, size)
	if err := readFull(readBody, body, false); err != nil {
		return Envelope{}, files, err
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return Envelope{}, files, err
	}
	return env, files, nil
}

// parseRights takes the descriptors out of a control message.
func parseRights(oob []byte) ([]int, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	var fds []int
	for i := range msgs {
		got, err := syscall.ParseUnixRights(&msgs[i])
		if err != nil {
			return fds, err
		}
		fds = append(fds, got...)
	}
	return fds, nil
}

func closeFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}

// readGrantedFrame reads a frame and records the descriptors it carries
// as grants (wasmengine.GrantHostPath), so the engine reaches those paths
// through them. A module belongs to the worker; everything else to the
// sandbox the message names, whose stop releases it in a resident host.
// A proxy_http carries none: any sent with one are closed.
func readGrantedFrame(conn net.Conn) (Envelope, error) {
	env, files, err := readFrameFiles(conn)
	if err != nil {
		return env, err
	}
	if env.Type == MsgProxyHTTP {
		closeFiles(files)
		return env, nil
	}
	scope := env.SandboxID
	if env.Type == MsgLoadModule {
		scope = ""
	}
	for i, f := range files {
		wasmengine.GrantHostPath(scope, env.FDPaths[i], f)
	}
	return env, nil
}
