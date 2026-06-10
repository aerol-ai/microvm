package toolhost

import (
	"testing"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
)

// ─── daytonaCommandStream unit tests ─────────────────────────────────────────

func TestDaytonaCommandStreamBroadcastAndSubscribe(t *testing.T) {
	s := newDaytonaCommandStream()

	// broadcast some stdout before subscribe
	s.broadcast(sessions.StreamStdout, []byte("hello"))
	s.broadcast(sessions.StreamStderr, []byte("err"))

	// subscriber should get replay of existing bytes
	initial, ch, finished := s.subscribe()
	if finished {
		t.Fatal("stream should not be finished yet")
	}
	if len(initial) == 0 {
		t.Fatal("expected initial replay bytes")
	}

	// broadcast after subscribe
	s.broadcast(sessions.StreamStdout, []byte("world"))
	select {
	case frame := <-ch:
		if frame == nil {
			t.Fatal("expected non-nil frame")
		}
	case <-time.After(time.Second):
		t.Fatal("expected frame on subscriber channel")
	}
}

func TestDaytonaCommandStreamBroadcastNilChunk(t *testing.T) {
	s := newDaytonaCommandStream()
	// nil/empty chunk should be ignored
	s.broadcast(sessions.StreamStdout, nil)
	s.broadcast(sessions.StreamStdout, []byte{})
	initial, _, finished := s.subscribe()
	if finished {
		t.Fatal("should not be finished")
	}
	if len(initial) != 0 {
		t.Fatalf("expected no replay for nil chunks, got %d bytes", len(initial))
	}
}

func TestDaytonaCommandStreamFinishIdempotent(t *testing.T) {
	s := newDaytonaCommandStream()
	_, ch, _ := s.subscribe()
	s.finish()
	// closed channel should drain without blocking
	_, ok := <-ch
	if ok {
		t.Fatal("channel should be closed after finish")
	}
	// calling finish again should not panic
	s.finish()
}

func TestDaytonaCommandStreamSubscribeAfterFinish(t *testing.T) {
	s := newDaytonaCommandStream()
	s.broadcast(sessions.StreamStdout, []byte("data"))
	s.finish()

	initial, ch, finished := s.subscribe()
	if !finished {
		t.Fatal("should report finished")
	}
	_ = initial // replay bytes
	// channel should be immediately closed
	_, ok := <-ch
	if ok {
		t.Fatal("channel should be closed after finish")
	}
}

func TestDaytonaCommandStreamNilBroadcast(t *testing.T) {
	var s *daytonaCommandStream
	// should not panic on nil stream
	s.broadcast(sessions.StreamStdout, []byte("x"))
}

func TestDaytonaCommandStreamNilFinish(t *testing.T) {
	var s *daytonaCommandStream
	s.finish() // must not panic
}

func TestDaytonaCommandStreamNilSubscribe(t *testing.T) {
	var s *daytonaCommandStream
	initial, ch, finished := s.subscribe()
	if !finished {
		t.Fatal("nil stream should report finished")
	}
	if initial != nil {
		t.Fatal("nil stream should return no initial bytes")
	}
	_, ok := <-ch
	if ok {
		t.Fatal("nil stream channel should be closed")
	}
}

// ─── daytonaCompat unit tests ─────────────────────────────────────────────────

func TestDaytonaCompatEnsureAndSession(t *testing.T) {
	dc := newDaytonaCompat()

	// ensure creates session
	s1 := dc.ensureSession("my-session")
	if s1 == nil {
		t.Fatal("ensureSession should return non-nil")
	}
	// second ensure returns same state
	s2 := dc.ensureSession("my-session")
	if s1 != s2 {
		t.Fatal("ensureSession should return same state")
	}

	// session retrieves it
	state, ok := dc.session("my-session")
	if !ok || state == nil {
		t.Fatalf("session not found: ok=%v state=%v", ok, state)
	}
}

func TestDaytonaCompatTrimSpace(t *testing.T) {
	dc := newDaytonaCompat()
	dc.ensureSession("  spaced  ")
	_, ok := dc.session("spaced")
	if !ok {
		t.Fatal("ensureSession should trim spaces")
	}
}

func TestDaytonaCompatDeleteSession(t *testing.T) {
	dc := newDaytonaCompat()
	dc.ensureSession("del-sess")
	dc.deleteSession("del-sess")
	_, ok := dc.session("del-sess")
	if ok {
		t.Fatal("deleted session should not be found")
	}
}

func TestDaytonaCompatListSessionIDs(t *testing.T) {
	dc := newDaytonaCompat()
	dc.ensureSession("z-session")
	dc.ensureSession("a-session")
	ids := dc.listSessionIDs()
	if len(ids) != 2 {
		t.Fatalf("expected 2 session IDs, got %d", len(ids))
	}
	if ids[0] != "a-session" || ids[1] != "z-session" {
		t.Fatalf("expected sorted IDs: %v", ids)
	}
}

// ─── daytonaSessionState unit tests ───────────────────────────────────────────

func TestDaytonaSessionStateAddAndGetCommand(t *testing.T) {
	state := &daytonaSessionState{commands: map[string]*daytonaCommandState{}}
	cmd := &daytonaCommandState{
		id:        "cmd1",
		command:   "echo hello",
		createdAt: time.Now(),
		stream:    newDaytonaCommandStream(),
	}
	state.addCommand(cmd)

	got, ok := state.command("cmd1")
	if !ok {
		t.Fatal("command not found")
	}
	if got.command != "echo hello" {
		t.Fatalf("command text = %q", got.command)
	}

	// commandPtr returns live pointer
	ptr, ok := state.commandPtr("cmd1")
	if !ok || ptr == nil {
		t.Fatal("commandPtr not found")
	}
	if ptr != cmd {
		t.Fatal("commandPtr should return live pointer")
	}
}

func TestDaytonaSessionStateSetActiveAndAcceptsInput(t *testing.T) {
	state := &daytonaSessionState{commands: map[string]*daytonaCommandState{}}
	cmd := &daytonaCommandState{
		id:      "cmd2",
		command: "read x",
		stream:  newDaytonaCommandStream(),
	}
	state.addCommand(cmd)
	state.setActive("cmd2")

	if !state.acceptsInput("cmd2") {
		t.Fatal("should accept input after setActive")
	}
	if state.acceptsInput("nonexistent") {
		t.Fatal("nonexistent command should not accept input")
	}
}

func TestDaytonaSessionStateFinishCommand(t *testing.T) {
	state := &daytonaSessionState{commands: map[string]*daytonaCommandState{}}
	cmd := &daytonaCommandState{
		id:      "cmd3",
		command: "ls",
		running: true,
		stream:  newDaytonaCommandStream(),
	}
	state.addCommand(cmd)
	state.setActive("cmd3")
	state.finishCommand("cmd3", "output", "stderr", 0)

	got, ok := state.command("cmd3")
	if !ok {
		t.Fatal("command not found after finish")
	}
	if got.exitCode == nil || *got.exitCode != 0 {
		t.Fatalf("exitCode = %v", got.exitCode)
	}
	if got.stdout != "output" || got.stderr != "stderr" {
		t.Fatalf("stdout=%q stderr=%q", got.stdout, got.stderr)
	}
	if state.acceptsInput("cmd3") {
		t.Fatal("finished command should not accept input")
	}
}

func TestDaytonaSessionStateFinishCommandNotFound(t *testing.T) {
	state := &daytonaSessionState{commands: map[string]*daytonaCommandState{}}
	// should not panic
	state.finishCommand("nonexistent", "", "", 0)
}

func TestDaytonaSessionStateCommandsSnapshot(t *testing.T) {
	state := &daytonaSessionState{commands: map[string]*daytonaCommandState{}}
	t1 := time.Now()
	t2 := t1.Add(time.Second)
	cmd1 := &daytonaCommandState{id: "a", command: "first", createdAt: t1, stream: newDaytonaCommandStream()}
	cmd2 := &daytonaCommandState{id: "b", command: "second", createdAt: t2, stream: newDaytonaCommandStream()}
	state.addCommand(cmd2)
	state.addCommand(cmd1)

	snap := state.commandsSnapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(snap))
	}
	if snap[0].id != "a" {
		t.Fatalf("expected sorted by createdAt, got %q first", snap[0].id)
	}
}

// ─── Helper function unit tests ────────────────────────────────────────────────

func TestInt32PtrAndClone(t *testing.T) {
	p := int32Ptr(42)
	if p == nil || *p != 42 {
		t.Fatalf("int32Ptr = %v", p)
	}
	c := cloneInt32Ptr(p)
	if c == nil || *c != 42 || c == p {
		t.Fatalf("cloneInt32Ptr = %v", c)
	}
	if cloneInt32Ptr(nil) != nil {
		t.Fatal("cloneInt32Ptr(nil) should return nil")
	}
}

func TestStringOrNil(t *testing.T) {
	if stringOrNil("") != nil {
		t.Fatal("empty string should return nil")
	}
	p := stringOrNil("hello")
	if p == nil || *p != "hello" {
		t.Fatalf("stringOrNil = %v", p)
	}
}

func TestShellSingleQuote(t *testing.T) {
	// simple string
	if got := shellSingleQuote("hello"); got != "'hello'" {
		t.Fatalf("simple = %q", got)
	}
	// string with single quote
	if got := shellSingleQuote("it's"); got != "'it'\\''s'" {
		t.Fatalf("with quote = %q", got)
	}
}

func TestLongestEndMarkerPrefixSuffix(t *testing.T) {
	pattern := "__END__:123"
	// no overlap
	if got := longestEndMarkerPrefixSuffix("hello world", pattern); got != 0 {
		t.Fatalf("no overlap = %d", got)
	}
	// partial overlap at end
	captured := "some output__"
	got := longestEndMarkerPrefixSuffix(captured, pattern)
	if got != 2 {
		t.Fatalf("partial overlap = %d (expected 2 for \"__\")", got)
	}
	// captured shorter than pattern
	if got := longestEndMarkerPrefixSuffix("_", pattern); got == 0 {
		// _ is prefix of pattern "__END__:123"
		t.Fatalf("single underscore should have partial overlap, got %d", got)
	}
}

func TestNewDaytonaCommandID(t *testing.T) {
	id1, err := newDaytonaCommandID()
	if err != nil {
		t.Fatalf("newDaytonaCommandID: %v", err)
	}
	if len(id1) != 16 { // 8 bytes hex-encoded = 16 chars
		t.Fatalf("id length = %d, want 16", len(id1))
	}
	id2, _ := newDaytonaCommandID()
	if id1 == id2 {
		t.Fatal("IDs should be random")
	}
}

func TestBuildDaytonaSessionResponse(t *testing.T) {
	state := &daytonaSessionState{commands: map[string]*daytonaCommandState{}}
	cmd := &daytonaCommandState{
		id:        "c1",
		command:   "echo",
		exitCode:  int32Ptr(0),
		createdAt: time.Now(),
		stream:    newDaytonaCommandStream(),
	}
	state.addCommand(cmd)

	resp := buildDaytonaSessionResponse("my-session", state)
	if resp.SessionID != "my-session" {
		t.Fatalf("sessionID = %q", resp.SessionID)
	}
	if len(resp.Commands) != 1 {
		t.Fatalf("commands = %d", len(resp.Commands))
	}
	if resp.Commands[0].ID != "c1" {
		t.Fatalf("command id = %q", resp.Commands[0].ID)
	}
}
