package worker

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

var errCov96Write = errors.New("cov96: peer gone")

// cov96ScriptConn replays pre-framed requests and accepts only the first
// okFrames replies, so each Serve arm can be driven into its "reply write
// failed" return without racing a pipe close.
type cov96ScriptConn struct {
	r        *bytes.Reader
	okWrites int
	writes   int
	out      bytes.Buffer
}

func newCov96ScriptConn(t *testing.T, okFrames int, envs ...Envelope) *cov96ScriptConn {
	t.Helper()
	var buf bytes.Buffer
	for _, env := range envs {
		if err := writeFrame(&buf, env); err != nil {
			t.Fatal(err)
		}
	}
	// writeFrame issues a header write and a body write per frame.
	return &cov96ScriptConn{r: bytes.NewReader(buf.Bytes()), okWrites: 2 * okFrames}
}

func (c *cov96ScriptConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *cov96ScriptConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes > c.okWrites {
		return 0, errCov96Write
	}
	return c.out.Write(p)
}

func (c *cov96ScriptConn) Close() error                     { return nil }
func (c *cov96ScriptConn) LocalAddr() net.Addr              { return &net.UnixAddr{Name: "cov96", Net: "unix"} }
func (c *cov96ScriptConn) RemoteAddr() net.Addr             { return &net.UnixAddr{Name: "cov96", Net: "unix"} }
func (c *cov96ScriptConn) SetDeadline(time.Time) error      { return nil }
func (c *cov96ScriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *cov96ScriptConn) SetWriteDeadline(time.Time) error { return nil }

func (c *cov96ScriptConn) replies(t *testing.T) []Envelope {
	t.Helper()
	var out []Envelope
	r := bytes.NewReader(c.out.Bytes())
	for r.Len() > 0 {
		env, err := readFrame(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, env)
	}
	return out
}

func cov96Payload(t *testing.T, v any) []byte {
	t.Helper()
	b, err := encodePayload(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cov96SnapshotDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "mem.snap")
	if err := wasmengine.WriteSnapshotDir(dir, wasmengine.SnapshotCapture{Memory: []byte("memory")}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCov96ServerServeTriggerPanic(t *testing.T) {
	conn := newCov96ScriptConn(t, 0, Envelope{Type: MsgTriggerPanic, SandboxID: "sb"})
	defer func() {
		if r := recover(); r != "wasm worker test panic" {
			t.Fatalf("recover = %v, want the test panic", r)
		}
	}()
	_ = (&Server{}).Serve(conn)
	t.Fatal("Serve returned instead of panicking")
}

func TestCov96ServerServeUnknownEngineReplyFails(t *testing.T) {
	t.Setenv("AEROL_WASM_ENGINE", "no-such-engine")
	conn := newCov96ScriptConn(t, 0, Envelope{
		Type: MsgLoadModule, SandboxID: "sb",
		Payload: cov96Payload(t, loadModulePayload{Path: "unused.wasm", MemoryMB: 16}),
	})
	if err := (&Server{}).Serve(conn); err == nil {
		t.Fatal("Serve = nil, want the engine selection error")
	}
}

func TestCov96ServerServeLoadModuleSuccessReplyFails(t *testing.T) {
	mod := wasmmod.WriteMinimalWasm(t, t.TempDir(), "demo.wasm")
	load := Envelope{Type: MsgLoadModule, SandboxID: "sb", Payload: cov96Payload(t, loadModulePayload{Path: mod, MemoryMB: 16})}

	t.Run("write fails", func(t *testing.T) {
		s := &Server{}
		conn := newCov96ScriptConn(t, 0, load)
		if err := s.Serve(conn); !errors.Is(err, errCov96Write) {
			t.Fatalf("Serve = %v, want write failure", err)
		}
		if s.eng == nil {
			t.Fatal("module load did not leave an engine behind")
		}
	})

	t.Run("encode fails", func(t *testing.T) {
		orig := encodePayload
		t.Cleanup(func() { encodePayload = orig })
		encodeErr := errors.New("cov96 encode")
		encodePayload = func(any) ([]byte, error) { return nil, encodeErr }
		conn := newCov96ScriptConn(t, 1, load)
		if err := (&Server{}).Serve(conn); !errors.Is(err, encodeErr) {
			t.Fatalf("Serve = %v, want encode failure", err)
		}
	})
}

// Each case fails the reply write of one Serve arm. Serve must stop right
// there: one attempted (failed) header write and nothing delivered. The arms
// return the handler's own error rather than the write error, so only
// termination is asserted.
func TestCov96ServerServeReplyWriteFailures(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := cov96SnapshotDir(t)
	engErr := errors.New("cov96 engine")

	cases := []struct {
		name string
		eng  wasmengine.Engine
		env  Envelope
	}{
		{name: "exec result", eng: &mockEngine{}, env: Envelope{Type: MsgExec, SandboxID: "sb", Payload: cov96Payload(t, execPayload{})}},
		{name: "invoke ok", eng: &mockEngine{}, env: Envelope{Type: MsgInvoke, SandboxID: "sb", Payload: cov96Payload(t, invokePayload{})}},
		{name: "stop error", eng: &mockEngine{err: engErr}, env: Envelope{Type: MsgStopInstance, SandboxID: "sb"}},
		{name: "checkpoint write error", eng: &mockEngine{}, env: Envelope{Type: MsgCheckpoint, SandboxID: "sb", Payload: cov96Payload(t, checkpointPayload{OutDir: filepath.Join(blocker, "snap")})}},
		{name: "checkpoint ok", eng: &mockEngine{}, env: Envelope{Type: MsgCheckpoint, SandboxID: "sb", Payload: cov96Payload(t, checkpointPayload{OutDir: filepath.Join(t.TempDir(), "snap")})}},
		{name: "restore no engine", eng: nil, env: Envelope{Type: MsgRestore, SandboxID: "sb", Payload: cov96Payload(t, restorePayload{Dir: snap})}},
		{name: "restore engine error", eng: &mockEngine{err: engErr}, env: Envelope{Type: MsgRestore, SandboxID: "sb", Payload: cov96Payload(t, restorePayload{Dir: snap})}},
		{name: "restore ok", eng: &mockEngine{}, env: Envelope{Type: MsgRestore, SandboxID: "sb", Payload: cov96Payload(t, restorePayload{Dir: snap})}},
		{name: "set capability ok", eng: &mockEngine{}, env: Envelope{Type: MsgSetCapability, SandboxID: "sb", Payload: cov96Payload(t, setCapabilityPayload{})}},
		{name: "set listen port ok", eng: &mockEngine{}, env: Envelope{Type: MsgSetListenPort, SandboxID: "sb", Payload: cov96Payload(t, setListenPortPayload{Port: 8080})}},
		{name: "proxy request error", eng: &mockEngine{}, env: Envelope{Type: MsgProxyHTTP, SandboxID: "sb", Payload: cov96Payload(t, proxyHTTPPayload{Method: " \x00 "})}},
		{name: "netstats", eng: nil, env: Envelope{Type: MsgNetstatsTick, SandboxID: "sb"}},
		{name: "unknown type", eng: nil, env: Envelope{Type: MessageType("cov96-unknown"), SandboxID: "sb"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{eng: tc.eng}
			conn := newCov96ScriptConn(t, 0, tc.env, Envelope{Type: MsgHealthPing, SandboxID: "sb"})
			_ = s.Serve(conn)
			if conn.writes != 1 || conn.out.Len() != 0 || conn.r.Len() == 0 {
				t.Fatalf("writes=%d delivered=%d unread=%d; want Serve to stop at the failed reply",
					conn.writes, conn.out.Len(), conn.r.Len())
			}
		})
	}
}

// Restore failures reply with an error frame and keep serving.
func TestCov96ServerServeRestoreErrorsContinue(t *testing.T) {
	snap := cov96SnapshotDir(t)
	restore := Envelope{Type: MsgRestore, SandboxID: "sb", Payload: cov96Payload(t, restorePayload{Dir: snap})}
	for _, tc := range []struct {
		name string
		eng  wasmengine.Engine
	}{
		{name: "no engine", eng: nil},
		{name: "engine error", eng: &mockEngine{err: errors.New("cov96 restore")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{eng: tc.eng}
			conn := newCov96ScriptConn(t, 2, restore, Envelope{Type: MsgHealthPing, SandboxID: "sb"})
			_ = s.Serve(conn)
			got := conn.replies(t)
			if len(got) != 2 || got[0].Type != MsgError || got[1].Type != MsgPong {
				t.Fatalf("replies = %+v, want error then pong", got)
			}
		})
	}
}
