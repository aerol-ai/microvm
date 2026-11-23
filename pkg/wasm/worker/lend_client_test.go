package worker

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// TestClientLendsWhatItDoesNotOpen: a message whose caps name a lent
// folder goes without it, and the helper is asked to lend it: right after
// an instantiate or a restore, and before an exec, a capability change or
// a streamed run. Single mode, which lends nothing, never asks.
func TestClientLendsWhatItDoesNotOpen(t *testing.T) {
	work := t.TempDir()
	// A folder sandboxd could open: it is still never passed.
	lent := t.TempDir()
	caps := wasmengine.Capabilities{Preopens: []wasmengine.Preopen{{GuestPath: "/work", HostPath: work}, {GuestPath: "/data", HostPath: lent, Lent: true}}}
	var events []string
	var mu sync.Mutex
	note := func(s string) {
		mu.Lock()
		events = append(events, s)
		mu.Unlock()
	}
	var lendErr error
	withGrantPolicy(t, GrantPolicy{Lend: func(_ context.Context, sandboxID, socket string) error {
		note("lend " + sandboxID + " " + filepath.Base(socket))
		return lendErr
	}})
	w := &scriptedWorker{replies: []Envelope{{Type: MsgOK}}, note: note}
	sock := w.serve(t)
	c := NewClient(sock)
	snapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := events
		events = nil
		return out
	}
	if err := c.Instantiate("sb-1", caps); err != nil {
		t.Fatal(err)
	}
	// The frame first (the worker holds the sandbox from it), then the loan.
	if got := snapshot(); !slices.Equal(got, []string{"frame " + string(MsgInstantiate) + " sb-1 " + work, "lend sb-1 w.sock"}) {
		t.Fatalf("instantiate: %v", got)
	}
	if err := c.SetCapability("sb-1", caps); err != nil {
		t.Fatal(err)
	}
	if got := snapshot(); !slices.Equal(got, []string{"lend sb-1 w.sock", "frame " + string(MsgSetCapability) + " sb-1 " + work}) {
		t.Fatalf("set capability: %v", got)
	}
	result, err := encodePayload(execResultPayload{})
	if err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	w.replies = []Envelope{{Type: MsgInvokeResult, Payload: result}}
	w.mu.Unlock()
	if _, err := c.Exec("sb-1", caps, "_start"); err != nil {
		t.Fatal(err)
	}
	if got := snapshot(); !slices.Equal(got, []string{"lend sb-1 w.sock", "frame " + string(MsgExec) + " sb-1 " + work}) {
		t.Fatalf("exec: %v", got)
	}
	// A loan that fails fails the message: before an exec, nothing is sent.
	lendErr = errors.New("helper down")
	if _, err := c.Exec("sb-1", caps, "_start"); err == nil || !strings.Contains(err.Error(), "helper down") {
		t.Fatalf("exec with a failed loan = %v", err)
	}
	if got := snapshot(); !slices.Equal(got, []string{"lend sb-1 w.sock"}) {
		t.Fatalf("a failed loan sent %v", got)
	}
	w.mu.Lock()
	w.replies = []Envelope{{Type: MsgOK}}
	w.mu.Unlock()
	if err := c.Instantiate("sb-1", caps); err == nil {
		t.Fatal("instantiate with a failed loan")
	}
	if err := c.SetCapability("sb-1", caps); err == nil {
		t.Fatal("set capability with a failed loan")
	}
	if _, err := c.StartExec(context.Background(), "sb-1", ExecStartPayload{Caps: caps}); err == nil {
		t.Fatal("a streamed run with a failed loan")
	}
	_ = snapshot()
	// No lender: a lent folder cannot be reached, and nothing is sent.
	withGrantPolicy(t, GrantPolicy{})
	if _, err := c.Exec("sb-1", caps, "_start"); !errors.Is(err, errNoLender) {
		t.Fatalf("no lender: %v", err)
	}
	if got := snapshot(); len(got) != 0 {
		t.Fatalf("sent with no lender: %v", got)
	}
	// Caps that name no lent folder never ask (single mode).
	if err := c.Instantiate("sb-1", wasmengine.Capabilities{Preopens: caps.Preopens[:1]}); err != nil {
		t.Fatal(err)
	}
	if got := snapshot(); !slices.Equal(got, []string{"frame " + string(MsgInstantiate) + " sb-1 " + work}) {
		t.Fatalf("single mode: %v", got)
	}
}

// TestRestoreLendsAfter: a restore is the other message that makes a
// worker hold a sandbox; the loan follows it.
func TestRestoreLendsAfter(t *testing.T) {
	snap := t.TempDir()
	if err := wasmengine.WriteSnapshotDir(filepath.Join(snap, "mem.snap"), wasmengine.SnapshotCapture{Memory: []byte("m")}); err != nil {
		t.Fatal(err)
	}
	var lends []string
	withGrantPolicy(t, GrantPolicy{Lend: func(_ context.Context, id, _ string) error { lends = append(lends, id); return nil }})
	w := &scriptedWorker{replies: []Envelope{{Type: MsgOK}}}
	c := NewClient(w.serve(t))
	caps := wasmengine.Capabilities{Preopens: []wasmengine.Preopen{{GuestPath: "/data", HostPath: "/m/sb-1/0", Lent: true}}}
	if err := c.Restore("sb-1", filepath.Join(snap, "mem.snap"), caps); err != nil {
		t.Fatal(err)
	}
	frames, fds := w.seen()
	if !slices.Equal(lends, []string{"sb-1"}) || len(frames) != 1 || strings.Contains(frames[0], "/m/sb-1/0") || fds != 4 {
		t.Fatalf("lends %v frames %v fds %d", lends, frames, fds)
	}
	w.mu.Lock()
	w.replies = []Envelope{{Type: MsgError}}
	w.mu.Unlock()
	if err := c.Restore("sb-1", filepath.Join(snap, "mem.snap"), caps); err == nil || len(lends) != 1 {
		t.Fatalf("a refused restore lent: %v %v", err, lends)
	}
}
