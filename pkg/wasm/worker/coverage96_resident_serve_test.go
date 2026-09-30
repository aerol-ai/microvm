package worker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestCov96ResidentServeTriggerPanic(t *testing.T) {
	conn := newCov96ScriptConn(t, 0, Envelope{Type: MsgTriggerPanic, SandboxID: "sb"})
	defer func() {
		if r := recover(); r != "wasm resident worker test panic" {
			t.Fatalf("recover = %v, want the resident test panic", r)
		}
	}()
	_ = (&ResidentServer{}).Serve(conn)
	t.Fatal("Serve returned instead of panicking")
}

func cov96LoadedResident(t *testing.T) *ResidentServer {
	t.Helper()
	mod := wasmmod.WriteMinimalWasm(t, t.TempDir(), "demo.wasm")
	s := &ResidentServer{}
	conn := newCov96ScriptConn(t, 1, Envelope{
		Type: MsgLoadModule, SandboxID: "host",
		Payload: cov96Payload(t, loadModulePayload{Path: mod, MemoryMB: 16}),
	})
	_ = s.Serve(conn)
	if got := conn.replies(t); len(got) != 1 || got[0].Type != MsgOK {
		t.Fatalf("load replies = %+v, want one OK", got)
	}
	return s
}

// The resident host refuses to build its runtime when the compile cache path
// is unusable, and reports that per request instead of dying.
func TestCov96ResidentServeEngineInitFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "cache-file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", blocker)
	load := Envelope{Type: MsgLoadModule, SandboxID: "host", Payload: cov96Payload(t, loadModulePayload{Path: "unused.wasm", MemoryMB: 16})}
	ping := Envelope{Type: MsgHealthPing, SandboxID: "host"}

	t.Run("error reply delivered", func(t *testing.T) {
		s := &ResidentServer{}
		conn := newCov96ScriptConn(t, 2, load, ping)
		_ = s.Serve(conn)
		got := conn.replies(t)
		if len(got) != 2 || got[0].Type != MsgError || got[1].Type != MsgPong {
			t.Fatalf("replies = %+v, want error then pong", got)
		}
		if s.engine() != nil {
			t.Fatal("failed init left an engine installed")
		}
	})
	t.Run("error reply write fails", func(t *testing.T) {
		conn := newCov96ScriptConn(t, 0, load, ping)
		_ = (&ResidentServer{}).Serve(conn)
		if conn.writes != 1 || conn.r.Len() == 0 {
			t.Fatalf("writes=%d unread=%d; want Serve to stop at the failed reply", conn.writes, conn.r.Len())
		}
	})
}

// Each case fails the reply write of one resident Serve arm; Serve must stop
// there rather than keep reading.
func TestCov96ResidentServeReplyWriteFailures(t *testing.T) {
	loaded := cov96LoadedResident(t)
	bad := []byte("not json")
	missing := filepath.Join(t.TempDir(), "missing.wasm")

	cases := []struct {
		name     string
		srv      *ResidentServer
		okFrames int
		envs     []Envelope
	}{
		{name: "load decode", srv: &ResidentServer{}, envs: []Envelope{{Type: MsgLoadModule, SandboxID: "host", Payload: bad}}},
		{name: "load missing module", srv: &ResidentServer{}, envs: []Envelope{{Type: MsgLoadModule, SandboxID: "host", Payload: cov96Payload(t, loadModulePayload{Path: missing, MemoryMB: 16})}}},
		{name: "duplicate instantiate", srv: loaded, okFrames: 1, envs: []Envelope{
			{Type: MsgInstantiate, SandboxID: "sb-dup", Payload: cov96Payload(t, instantiatePayload{Caps: nonListenCaps("wasm")})},
			{Type: MsgInstantiate, SandboxID: "sb-dup", Payload: cov96Payload(t, instantiatePayload{Caps: nonListenCaps("wasm")})},
		}},
		{name: "exec decode", srv: &ResidentServer{}, envs: []Envelope{{Type: MsgExec, SandboxID: "sb", Payload: bad}}},
		{name: "exec no engine", srv: &ResidentServer{}, envs: []Envelope{{Type: MsgExec, SandboxID: "sb", Payload: cov96Payload(t, execPayload{Caps: nonListenCaps("wasm")})}}},
		{name: "exec run error", srv: loaded, envs: []Envelope{{Type: MsgExec, SandboxID: "", Payload: cov96Payload(t, execPayload{Caps: nonListenCaps("wasm")})}}},
		{name: "invoke decode", srv: &ResidentServer{}, envs: []Envelope{{Type: MsgInvoke, SandboxID: "sb", Payload: bad}}},
		{name: "invoke no engine", srv: &ResidentServer{}, envs: []Envelope{{Type: MsgInvoke, SandboxID: "sb", Payload: cov96Payload(t, invokePayload{})}}},
		{name: "invoke unknown instance", srv: loaded, envs: []Envelope{{Type: MsgInvoke, SandboxID: "sb-none", Payload: cov96Payload(t, invokePayload{Export: "_start"})}}},
		{name: "network blocks", srv: &ResidentServer{}, envs: []Envelope{{Type: MsgSetNetworkBlocks, SandboxID: "sb", Payload: cov96Payload(t, setNetworkBlocksPayload{BlockEgress: true})}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envs := append(tc.envs, Envelope{Type: MsgHealthPing, SandboxID: "sb"})
			conn := newCov96ScriptConn(t, tc.okFrames, envs...)
			_ = tc.srv.Serve(conn)
			if want := 2*tc.okFrames + 1; conn.writes != want || conn.r.Len() == 0 {
				t.Fatalf("writes=%d (want %d) unread=%d; want Serve to stop at the failed reply",
					conn.writes, want, conn.r.Len())
			}
		})
	}
}
