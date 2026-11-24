package worker

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedWorker answers each frame on its socket with the next of
// replies (the last again once they run out), and records each frame's
// type, sandbox, named paths and descriptors.
type scriptedWorker struct {
	mu      sync.Mutex
	replies []Envelope
	frames  []string
	fds     int
	// note, when set, hears each frame as it arrives. Set before serving.
	note func(string)
}

func (w *scriptedWorker) serve(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "lw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "w.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			go w.handle(conn)
		}
	}()
	return sock
}

func (w *scriptedWorker) handle(conn *net.UnixConn) {
	defer conn.Close()
	for {
		env, files, err := readFrameFiles(conn)
		if err != nil {
			return
		}
		w.mu.Lock()
		line := string(env.Type) + " " + env.SandboxID + " " + strings.Join(env.FDPaths, ",")
		w.frames = append(w.frames, line)
		w.fds += len(files)
		reply := w.replies[0]
		if len(w.replies) > 1 {
			w.replies = w.replies[1:]
		}
		w.mu.Unlock()
		if w.note != nil {
			w.note("frame " + line)
		}
		closeFiles(files)
		if err := writeFrame(conn, reply); err != nil {
			return
		}
	}
}

func (w *scriptedWorker) seen() ([]string, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.frames), w.fds
}

func statusReply(t *testing.T, loaded bool, holder string) Envelope {
	t.Helper()
	body, err := encodePayload(instanceStatusPayload{Loaded: loaded, SandboxID: holder, Checked: true})
	if err != nil {
		t.Fatal(err)
	}
	return Envelope{Type: MsgOK, Payload: body}
}

func dialUnix(t *testing.T, sock string) *net.UnixConn {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

// TestLendFolders: the helper's loan asks the worker first, and passes the
// folders only to a worker that says it holds the sandbox.
func TestLendFolders(t *testing.T) {
	dir := t.TempDir()
	open := func() []*os.File {
		f, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return []*os.File{f}
	}
	paths := []string{"/var/lib/aerolvm-rootd/mounts/sb-1/0"}
	for _, tc := range []struct {
		name    string
		replies []Envelope
		want    error
		fds     int
	}{
		{"it holds the sandbox", []Envelope{statusReply(t, true, "sb-1"), {Type: MsgPong}}, nil, 1},
		{"a resident host that holds it", []Envelope{statusReply(t, true, "sb-1"), {Type: MsgPong}}, nil, 1},
		{"it holds another sandbox", []Envelope{statusReply(t, false, "sb-2")}, ErrLendForeign, 0},
		{"it holds none yet", []Envelope{statusReply(t, false, "")}, ErrLendNotHeld, 0},
		{"loaded, but no holder named", []Envelope{statusReply(t, true, "")}, ErrLendNotHeld, 0},
		{"an error for a status", []Envelope{{Type: MsgError}}, errAny, 0},
		{"a status it cannot read", []Envelope{{Type: MsgOK, Payload: []byte("{")}}, errAny, 0},
		{"the loan not taken", []Envelope{statusReply(t, true, "sb-1"), {Type: MsgError}}, errAny, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &scriptedWorker{replies: tc.replies}
			conn := dialUnix(t, w.serve(t))
			err := LendFolders(conn, "sb-1", paths, open())
			if tc.want == errAny {
				if err == nil || errors.Is(err, ErrLendForeign) || errors.Is(err, ErrLendNotHeld) {
					t.Fatalf("lend = %v", err)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("lend = %v, want %v", err, tc.want)
			}
			frames, fds := w.seen()
			if fds != tc.fds || frames[0] != string(MsgInstanceStatus)+" sb-1 " {
				t.Fatalf("frames %v, %d descriptors", frames, fds)
			}
			if tc.fds > 0 && frames[1] != string(MsgHealthPing)+" sb-1 "+paths[0] {
				t.Fatalf("loan frame %v", frames)
			}
		})
	}
	// Names and folders that do not match are never sent.
	w := &scriptedWorker{replies: []Envelope{statusReply(t, true, "sb-1")}}
	conn := dialUnix(t, w.serve(t))
	if err := LendFolders(conn, "sb-1", append(paths, "/x"), open()); err == nil {
		t.Fatal("lent two names for one folder")
	}
	if err := LendFolders(conn, "sb-1", nil, nil); err == nil {
		t.Fatal("lent nothing")
	}
	if frames, _ := w.seen(); len(frames) != 0 {
		t.Fatalf("sent %v", frames)
	}
}

// errAny stands for any error that is neither of the named ones.
var errAny = errors.New("any")

// TestReadSmallFrame: a worker's reply to the helper is bounded.
func TestReadSmallFrame(t *testing.T) {
	// A whole, valid frame one byte past the bound.
	body := []byte(`{"type":"pong"}`)
	body = append(body, []byte(strings.Repeat(" ", lendReplyMax+1-len(body)))...)
	big := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	big = append(big, body...)
	for name, raw := range map[string][]byte{
		"too large":    big,
		"empty":        {0, 0, 0, 0},
		"short header": {0, 0},
		"short body":   {0, 0, 0, 9, '{'},
		"not JSON":     {0, 0, 0, 1, '{'},
	} {
		if _, err := readSmallFrame(strings.NewReader(string(raw))); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	frame, err := encodeFrame(Envelope{Type: MsgPong})
	if err != nil {
		t.Fatal(err)
	}
	if env, err := readSmallFrame(strings.NewReader(string(frame))); err != nil || env.Type != MsgPong {
		t.Fatalf("pong = %v, %v", env, err)
	}
}
