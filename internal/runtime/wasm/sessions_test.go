package wasm

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/internal/toolboxwire"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// sessionEnv is a driver whose one sandbox streams through a fake worker,
// so a test decides what every run writes and when it ends.
type sessionEnv struct {
	d    *Driver
	fake *fakeStreamingClient
	set  *sessionSet
}

func newSessionEnv(t *testing.T, cfg Config) *sessionEnv {
	t.Helper()
	d := New(cfg, nil)
	d.byID["sb"] = &sandboxInstance{sandboxID: "sb", status: models.SandboxStatusStarted, socketPath: "/tmp/x.sock", workDir: t.TempDir()}
	fake := &fakeStreamingClient{}
	d.SetWorkerClientFactory(func(string) WorkerClient { return fake })
	set, err := d.sessionsFor("sb")
	if err != nil {
		t.Fatal(err)
	}
	env := &sessionEnv{d: d, fake: fake, set: set}
	t.Cleanup(func() {
		set.close()
		fake.mu.Lock()
		defer fake.mu.Unlock()
		for _, st := range fake.streams {
			_ = st.Close()
		}
	})
	return env
}

// stream waits for the i-th run to start.
func (e *sessionEnv) stream(t *testing.T, i int) *fakeExecStream {
	t.Helper()
	var st *fakeExecStream
	waitFor(t, "run to start", func() bool {
		e.fake.mu.Lock()
		defer e.fake.mu.Unlock()
		if len(e.fake.streams) > i {
			st = e.fake.streams[i]
			return true
		}
		return false
	})
	return st
}

func (e *sessionEnv) starts() int {
	e.fake.mu.Lock()
	defer e.fake.mu.Unlock()
	return len(e.fake.starts)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (e *sessionEnv) exec(t *testing.T, session, text string, async bool) toolhost.CommandResult {
	t.Helper()
	res, err := e.set.exec(context.Background(), session, toolhost.SessionCommand{Text: text, Argv: strings.Fields(text)}, async)
	if err != nil {
		t.Fatalf("exec %q: %v", text, err)
	}
	return res
}

type execOutcome struct {
	toolhost.CommandResult
	err error
}

// execInBackground runs a sync exec on its own goroutine; a test reads the
// outcome once it has let the command end.
func (e *sessionEnv) execInBackground(session, text string) <-chan execOutcome {
	out := make(chan execOutcome, 1)
	go func() {
		res, err := e.set.exec(context.Background(), session, toolhost.SessionCommand{Text: text, Argv: strings.Fields(text)}, false)
		out <- execOutcome{res, err}
	}()
	return out
}

func (e *sessionEnv) info(t *testing.T, session, cmd string) toolhost.CommandInfo {
	t.Helper()
	info, err := e.set.command(session, cmd)
	if err != nil {
		t.Fatalf("command %s: %v", cmd, err)
	}
	return info
}

func (e *sessionEnv) waitExit(t *testing.T, session, cmd string) int32 {
	t.Helper()
	var code int32
	waitFor(t, "command "+cmd+" to end", func() bool {
		info, err := e.set.command(session, cmd)
		if err != nil || info.ExitCode == nil {
			return false
		}
		code = *info.ExitCode
		return true
	})
	return code
}

func exitEvent(code int) worker.ExecEvent {
	return worker.ExecEvent{Exit: &worker.ExecExit{ExitCode: code}}
}

func outEvent(stderr bool, s string) worker.ExecEvent {
	if stderr {
		return worker.ExecEvent{Stream: worker.StreamStderr, Data: []byte(s)}
	}
	return worker.ExecEvent{Stream: worker.StreamStdout, Data: []byte(s)}
}

func TestSessionCreateListGetDelete(t *testing.T) {
	e := newSessionEnv(t, Config{})
	if created, err := e.set.create("b"); !created || err != nil {
		t.Fatalf("create = %v %v", created, err)
	}
	if created, err := e.set.create("b"); created || err != nil {
		t.Fatalf("second create = %v %v, want an existing session", created, err)
	}
	if _, err := e.set.create("a"); err != nil {
		t.Fatal(err)
	}
	if got := e.set.list(); len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" || len(got[0].Commands) != 0 {
		t.Fatalf("list = %+v", got)
	}
	if _, err := e.set.get("missing"); !errors.Is(err, toolhost.ErrSessionNotFound) {
		t.Fatalf("get missing = %v", err)
	}
	if err := e.set.delete("a"); err != nil {
		t.Fatal(err)
	}
	if err := e.set.delete("a"); !errors.Is(err, toolhost.ErrSessionNotFound) {
		t.Fatalf("second delete = %v", err)
	}
	if _, err := e.set.command("b", "nope"); !errors.Is(err, toolhost.ErrCommandNotFound) {
		t.Fatalf("missing command = %v", err)
	}
	if _, err := e.set.command("nope", "nope"); !errors.Is(err, toolhost.ErrSessionNotFound) {
		t.Fatalf("missing session's command = %v", err)
	}
	// The driver keeps one set per sandbox, whichever request asks.
	if again, _ := e.d.sessionsFor("sb"); again != e.set {
		t.Fatal("a second request got another session set")
	}
	if _, err := e.d.sessionsFor("other"); err == nil {
		t.Fatal("sessions for an unknown sandbox")
	}
}

// Commands of one session run strictly one after another, like toolboxd's
// execMu: an async command queued behind a running one does not start
// until it ends, and a sync exec waits its turn too.
func TestSessionCommandsRunOneAtATime(t *testing.T) {
	e := newSessionEnv(t, Config{})
	if _, err := e.set.create("s"); err != nil {
		t.Fatal(err)
	}
	first := e.exec(t, "s", "mod first", true)
	second := e.exec(t, "s", "mod second", true)
	if first.ID == "" || second.ID == "" || first.ID == second.ID {
		t.Fatalf("ids %q %q", first.ID, second.ID)
	}
	run1 := e.stream(t, 0)
	if info := e.info(t, "s", first.ID); !info.Running || info.ExitCode != nil {
		t.Fatalf("first = %+v, want running", info)
	}
	if info := e.info(t, "s", second.ID); info.Running || info.ExitCode != nil {
		t.Fatalf("second = %+v, want waiting", info)
	}
	time.Sleep(20 * time.Millisecond)
	if n := e.starts(); n != 1 {
		t.Fatalf("%d runs started while the first still runs", n)
	}

	syncDone := e.execInBackground("s", "mod third")

	run1.events <- exitEvent(3)
	if code := e.waitExit(t, "s", first.ID); code != 3 {
		t.Fatalf("first exit = %d", code)
	}
	run2 := e.stream(t, 1)
	if e.fake.starts[1].Caps.Args[1] != "second" {
		t.Fatalf("second run args = %v", e.fake.starts[1].Caps.Args)
	}
	select {
	case <-syncDone:
		t.Fatal("sync exec ran before the command ahead of it ended")
	case <-time.After(20 * time.Millisecond):
	}
	run2.events <- exitEvent(0)
	run3 := e.stream(t, 2)
	run3.events <- outEvent(false, "out")
	run3.events <- outEvent(true, "err")
	run3.events <- exitEvent(7)
	res := (<-syncDone).CommandResult
	if res.ExitCode != 7 || res.Stdout != "out" || res.Stderr != "err" || res.ID == "" {
		t.Fatalf("sync result = %+v", res)
	}

	// The session lists its commands oldest first, with their exit codes.
	info, err := e.set.get("s")
	if err != nil || len(info.Commands) != 3 || info.Commands[0].ID != first.ID || info.Commands[2].Command != "mod third" ||
		*info.Commands[0].ExitCode != 3 || *info.Commands[1].ExitCode != 0 {
		t.Fatalf("session = %+v %v", info, err)
	}
	// Every run was a session command: stdin open, no deadline.
	for i, p := range e.fake.starts {
		if !p.Stdin || !p.NoDeadline || p.ModulePath != "" {
			t.Fatalf("run %d payload = %+v", i, p)
		}
	}
}

// An async command's input reaches its run, its logs can be read in
// windows while it runs, and input is refused (409) once it ended.
func TestSessionInputAndLogs(t *testing.T) {
	e := newSessionEnv(t, Config{})
	_, _ = e.set.create("s")
	cmd := e.exec(t, "s", "mod echo", true).ID
	run := e.stream(t, 0)

	if err := e.set.input(context.Background(), "s", cmd, []byte("hi\n")); err != nil {
		t.Fatal(err)
	}
	run.mu.Lock()
	stdin := string(run.stdin)
	run.mu.Unlock()
	if stdin != "hi\n" {
		t.Fatalf("stdin = %q", stdin)
	}
	run.events <- outEvent(false, "ready\n")
	run.events <- outEvent(true, "warn")
	waitFor(t, "output", func() bool {
		out, errOut, _ := e.set.logs("s", cmd, toolboxwire.LogQuery{})
		return out.Text == "ready\n" && errOut.Text == "warn"
	})
	out, errOut, err := e.set.logs("s", cmd, toolboxwire.LogQuery{StdoutOffset: 2, StderrOffset: 9, Limit: 3})
	if err != nil || out.Text != "ady" || out.End != 5 || out.Length != 6 || errOut.Text != "" || errOut.End != 4 || errOut.Length != 4 {
		t.Fatalf("windowed logs = %+v %+v %v", out, errOut, err)
	}
	// A character still being written waits while the command runs.
	run.events <- outEvent(false, "\xc3")
	waitFor(t, "partial character", func() bool {
		out, _, _ := e.set.logs("s", cmd, toolboxwire.LogQuery{StdoutOffset: 6})
		return out.Length == 7
	})
	if out, _, _ := e.set.logs("s", cmd, toolboxwire.LogQuery{StdoutOffset: 6}); out.Text != "" || out.End != 6 {
		t.Fatalf("partial character = %+v", out)
	}
	run.events <- exitEvent(0)
	e.waitExit(t, "s", cmd)
	if out, _, _ := e.set.logs("s", cmd, toolboxwire.LogQuery{StdoutOffset: 6}); out.Text != "?" || out.End != 7 {
		t.Fatalf("finished partial character = %+v", out)
	}
	if err := e.set.input(context.Background(), "s", cmd, []byte("late\n")); !errors.Is(err, toolhost.ErrCommandNotRunning) {
		t.Fatalf("input after the end = %v", err)
	}
	if _, _, err := e.set.logs("s", "nope", toolboxwire.LogQuery{}); !errors.Is(err, toolhost.ErrCommandNotFound) {
		t.Fatalf("logs of a missing command = %v", err)
	}
	if err := e.set.input(context.Background(), "nope", cmd, nil); !errors.Is(err, toolhost.ErrSessionNotFound) {
		t.Fatalf("input to a missing session = %v", err)
	}

	// A command waiting for its turn takes no input either.
	blocker := e.exec(t, "s", "mod block", true).ID
	waiting := e.exec(t, "s", "mod next", true).ID
	if err := e.set.input(context.Background(), "s", waiting, []byte("x")); !errors.Is(err, toolhost.ErrCommandNotRunning) {
		t.Fatalf("input to a waiting command = %v", err)
	}
	e.stream(t, 1).events <- exitEvent(0)
	e.waitExit(t, "s", blocker)
	e.stream(t, 2).events <- exitEvent(0)
	e.waitExit(t, "s", waiting)
}

// A failed stdin write to a command that ended meanwhile reads as "not
// running", not as a server error.
func TestSessionInputRacingTheEnd(t *testing.T) {
	e := newSessionEnv(t, Config{})
	_, _ = e.set.create("s")
	cmd := e.exec(t, "s", "mod", true).ID
	run := e.stream(t, 0)
	run.mu.Lock()
	run.stdinErr = errors.New("connection closed")
	run.mu.Unlock()
	if err := e.set.input(context.Background(), "s", cmd, []byte("x")); err == nil || errors.Is(err, toolhost.ErrCommandNotRunning) {
		t.Fatalf("write error on a running command = %v, want it passed on", err)
	}
	run.events <- exitEvent(0)
	e.waitExit(t, "s", cmd)
	// Swap the state under the write: running at the check, ended at the
	// error.
	e.set.mu.Lock()
	c := e.set.sessions["s"].commands[cmd]
	c.state, c.run = commandRunning, &Stream{ws: run, set: &streamSet{}}
	e.set.mu.Unlock()
	run.mu.Lock()
	run.stdinErr = nil
	run.onStdin = func() {
		e.set.mu.Lock()
		c.state = commandFinished
		e.set.mu.Unlock()
	}
	run.mu.Unlock()
	if err := e.set.input(context.Background(), "s", cmd, []byte("x")); !errors.Is(err, toolhost.ErrCommandNotRunning) {
		t.Fatalf("write racing the end = %v", err)
	}
}

// Output past the per-stream cap keeps the newest bytes, and the offsets a
// reader gets stay the stream's own.
func TestSessionLogsKeepTheNewestBytes(t *testing.T) {
	e := newSessionEnv(t, Config{SessionLogBytes: 8})
	_, _ = e.set.create("s")
	done := e.execInBackground("s", "mod flood")
	run := e.stream(t, 0)
	run.events <- outEvent(false, "0123456789")
	run.events <- outEvent(false, "abcdefghij")
	run.events <- exitEvent(0)
	res := (<-done).CommandResult
	if res.Stdout != "cdefghij" {
		t.Fatalf("sync stdout = %q, want the newest 8 bytes", res.Stdout)
	}
	for _, tc := range []struct {
		from, limit int64
		want        string
		end         int64
	}{
		{0, 0, "cdefghij", 20},
		{14, 0, "efghij", 20},
		{3, 2, "cd", 14},
		{20, 0, "", 20},
	} {
		out, _, err := e.set.logs("s", res.ID, toolboxwire.LogQuery{StdoutOffset: tc.from, Limit: tc.limit})
		if err != nil || out.Text != tc.want || out.End != tc.end || out.Length != 20 {
			t.Errorf("logs from %d limit %d = %+v %v, want %q end %d", tc.from, tc.limit, out, err, tc.want, tc.end)
		}
	}
}

// The sandbox's log budget drops finished commands' logs, oldest first, to
// make room; their lengths stay, so a reader is told it is at the end.
func TestSessionLogBudgetDropsOldestFinishedLogs(t *testing.T) {
	e := newSessionEnv(t, Config{SessionLogBytes: 4 << 10, SessionLogBudget: 8 << 10})
	_, _ = e.set.create("s")
	big := strings.Repeat("x", 4<<10)
	var ids []string
	for i := 0; i < 3; i++ {
		done := e.execInBackground("s", "mod")
		run := e.stream(t, i)
		run.events <- outEvent(false, big)
		run.events <- exitEvent(0)
		res := (<-done).CommandResult
		if res.Stdout != big {
			t.Fatalf("command %d result lost bytes: %d", i, len(res.Stdout))
		}
		ids = append(ids, res.ID)
	}
	out, _, err := e.set.logs("s", ids[0], toolboxwire.LogQuery{})
	if err != nil || out.Text != "" || out.End != 4<<10 || out.Length != 4<<10 {
		t.Fatalf("oldest logs = %d bytes end %d length %d %v, want dropped", len(out.Text), out.End, out.Length, err)
	}
	for _, id := range ids[1:] {
		if out, _, _ := e.set.logs("s", id, toolboxwire.LogQuery{}); out.Text != big {
			t.Fatalf("newer logs dropped: %d bytes", len(out.Text))
		}
	}
	e.set.mu.Lock()
	used := e.set.used
	e.set.mu.Unlock()
	if used > 8<<10 {
		t.Fatalf("log storage %d past the budget", used)
	}

	// With nothing finished left to drop, a running command keeps what fits
	// and still counts every byte.
	e2 := newSessionEnv(t, Config{SessionLogBytes: 8 << 10, SessionLogBudget: 4 << 10})
	_, _ = e2.set.create("s")
	cmd := e2.exec(t, "s", "mod", true).ID
	run := e2.stream(t, 0)
	run.events <- outEvent(false, strings.Repeat("y", 6<<10))
	waitFor(t, "output", func() bool {
		out, _, _ := e2.set.logs("s", cmd, toolboxwire.LogQuery{})
		return out.Length == 6<<10
	})
	if out, _, _ := e2.set.logs("s", cmd, toolboxwire.LogQuery{}); len(out.Text) != 4<<10 || out.End != 6<<10 {
		t.Fatalf("budget-capped running logs = %d bytes end %d", len(out.Text), out.End)
	}
	run.events <- exitEvent(0)
	e2.waitExit(t, "s", cmd)
}

// A session keeps its newest finished commands; the oldest are forgotten.
func TestSessionKeepsNewestFinishedCommands(t *testing.T) {
	e := newSessionEnv(t, Config{SessionCommandsKept: 2})
	_, _ = e.set.create("s")
	var ids []string
	for i := 0; i < 3; i++ {
		done := e.execInBackground("s", "mod")
		run := e.stream(t, i)
		run.events <- outEvent(false, "o")
		run.events <- exitEvent(i)
		ids = append(ids, (<-done).ID)
	}
	if _, err := e.set.command("s", ids[0]); !errors.Is(err, toolhost.ErrCommandNotFound) {
		t.Fatalf("oldest command = %v, want forgotten", err)
	}
	info, _ := e.set.get("s")
	if len(info.Commands) != 2 || info.Commands[0].ID != ids[1] || info.Commands[1].ID != ids[2] {
		t.Fatalf("kept = %+v", info.Commands)
	}
}

func TestSessionCaps(t *testing.T) {
	e := newSessionEnv(t, Config{MaxSessionsPerSandbox: 1, SessionCommandsKept: 2})
	if _, err := e.set.create("one"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.set.create("two"); !errors.Is(err, toolhost.ErrTooManySessions) {
		t.Fatalf("second session = %v", err)
	}
	// One running plus one waiting fills the session.
	running := e.exec(t, "one", "mod a", true).ID
	waiting := e.exec(t, "one", "mod b", true).ID
	if _, err := e.set.exec(context.Background(), "one", toolhost.SessionCommand{Text: "mod c", Argv: []string{"mod", "c"}}, true); !errors.Is(err, toolhost.ErrTooManyCommands) {
		t.Fatalf("third waiting command = %v", err)
	}
	// Followers per command are capped.
	var follows []*toolhost.LogFollow
	for i := 0; i < maxFollowersPerCommand; i++ {
		f, err := e.set.follow("one", running)
		if err != nil {
			t.Fatal(err)
		}
		follows = append(follows, f)
	}
	if _, err := e.set.follow("one", running); !errors.Is(err, toolhost.ErrTooManyFollowers) {
		t.Fatalf("follower past the cap = %v", err)
	}
	follows[0].Close()
	if f, err := e.set.follow("one", running); err != nil {
		t.Fatalf("a follower that left still counts: %v", err)
	} else {
		follows = append(follows, f)
	}
	for _, f := range follows {
		f.Close()
	}
	e.stream(t, 0).events <- exitEvent(0)
	e.waitExit(t, "one", running)
	e.stream(t, 1).events <- exitEvent(0)
	e.waitExit(t, "one", waiting)
	if _, err := e.set.exec(context.Background(), "missing", toolhost.SessionCommand{Argv: []string{"x"}}, true); !errors.Is(err, toolhost.ErrSessionNotFound) {
		t.Fatalf("exec in a missing session = %v", err)
	}
}

// Deleting a session kills its running command and makes its waiting ones
// give up.
func TestSessionDeleteKillsItsCommands(t *testing.T) {
	e := newSessionEnv(t, Config{})
	_, _ = e.set.create("s")
	_ = e.exec(t, "s", "mod block", true)
	run := e.stream(t, 0)
	syncErr := make(chan error, 1)
	go func() {
		_, err := e.set.exec(context.Background(), "s", toolhost.SessionCommand{Text: "mod next", Argv: []string{"mod", "next"}}, false)
		syncErr <- err
	}()
	waitFor(t, "second command to queue", func() bool {
		info, _ := e.set.get("s")
		return len(info.Commands) == 2
	})
	if err := e.set.delete("s"); err != nil {
		t.Fatal(err)
	}
	run.mu.Lock()
	kills := run.kills
	run.mu.Unlock()
	if kills != 1 {
		t.Fatalf("running command killed %d times", kills)
	}
	select {
	case <-run.closed:
	default:
		t.Fatal("running command's stream left open")
	}
	if err := <-syncErr; !errors.Is(err, toolhost.ErrSessionNotFound) {
		t.Fatalf("waiting sync exec = %v, want the session gone", err)
	}
	if n := e.starts(); n != 1 {
		t.Fatalf("%d runs started; the waiting one must not", n)
	}
	waitFor(t, "slot to free", func() bool { return e.d.byID["sb"].streams.count() == 0 })
}

// A start the worker refuses is the request's error when the command could
// start at once, and leaves no record; an async command queued behind
// another reports it as its result instead.
func TestSessionStartRefused(t *testing.T) {
	e := newSessionEnv(t, Config{MaxStreamsPerSandbox: 1})
	_, _ = e.set.create("s")
	// Another run holds the sandbox's only slot.
	other, err := e.d.StartStream(context.Background(), "sb", StreamSpec{})
	if err != nil {
		t.Fatal(err)
	}
	for _, async := range []bool{false, true} {
		_, err := e.set.exec(context.Background(), "s", toolhost.SessionCommand{Argv: []string{"mod"}}, async)
		if !errors.Is(err, toolhost.ErrTooManyProcesses) {
			t.Fatalf("async=%v refused start = %v", async, err)
		}
	}
	if info, _ := e.set.get("s"); len(info.Commands) != 0 {
		t.Fatalf("refused commands kept: %+v", info.Commands)
	}
	_ = other.Close()

	first := e.exec(t, "s", "mod", true).ID
	queued := e.exec(t, "s", "mod", true).ID
	run := e.stream(t, 1)
	e.fake.mu.Lock()
	e.fake.startErr = worker.ErrStreamingUnsupported
	e.fake.mu.Unlock()
	run.events <- exitEvent(0)
	e.waitExit(t, "s", first)
	if code := e.waitExit(t, "s", queued); code != -1 {
		t.Fatalf("refused queued command exit = %d", code)
	}
	if _, errOut, _ := e.set.logs("s", queued, toolboxwire.LogQuery{}); !strings.Contains(errOut.Text, "not supported") {
		t.Fatalf("refused queued command stderr = %q", errOut.Text)
	}
}

// A run that ends killed, or whose connection drops, ends its command with
// -1; a trap's message lands on stderr.
func TestSessionCommandEnds(t *testing.T) {
	e := newSessionEnv(t, Config{})
	_, _ = e.set.create("s")
	for i, tc := range []struct {
		ev       *worker.ExecEvent
		want     int32
		wantErr  string
		dropConn bool
	}{
		{ev: &worker.ExecEvent{Exit: &worker.ExecExit{ExitCode: -1, Killed: true}}, want: -1},
		{ev: &worker.ExecEvent{Exit: &worker.ExecExit{ExitCode: 1, Error: "out of memory"}}, want: 1, wantErr: "out of memory\n"},
		{dropConn: true, want: -1},
	} {
		done := e.execInBackground("s", "mod")
		run := e.stream(t, i)
		if tc.dropConn {
			_ = run.Close()
		} else {
			run.events <- *tc.ev
		}
		res := (<-done).CommandResult
		if res.ExitCode != tc.want || res.Stderr != tc.wantErr {
			t.Fatalf("case %d: %+v", i, res)
		}
	}
}

// Follow replays what is kept, then streams live frames, and ends when the
// command does. A follower that does not read has frames dropped instead of
// holding up the command.
func TestSessionFollow(t *testing.T) {
	e := newSessionEnv(t, Config{})
	_, _ = e.set.create("s")
	cmd := e.exec(t, "s", "mod", true).ID
	run := e.stream(t, 0)
	run.events <- outEvent(false, "early")
	waitFor(t, "early output", func() bool {
		out, _, _ := e.set.logs("s", cmd, toolboxwire.LogQuery{})
		return out.Text == "early"
	})
	f, err := e.set.follow("s", cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !bytes.Equal(f.Replay, toolboxwire.LogReplay([]byte("early"), nil)) {
		t.Fatalf("replay = %q", f.Replay)
	}
	stalled, err := e.set.follow("s", cmd)
	if err != nil {
		t.Fatal(err)
	}
	run.events <- outEvent(true, "live")
	if got := <-f.Frames; !bytes.Equal(got, toolboxwire.FrameLog(true, []byte("live"))) {
		t.Fatalf("live frame = %q", got)
	}
	// The stalled follower never reads; a flood past its queue is dropped
	// for it and the command still finishes.
	chunk := strings.Repeat("z", 64<<10)
	for i := 0; i < 8; i++ {
		run.events <- outEvent(false, chunk)
		<-f.Frames
	}
	run.events <- exitEvent(0)
	e.waitExit(t, "s", cmd)
	if _, ok := <-f.Frames; ok {
		t.Fatal("frames still open after the command ended")
	}
	var got int
	for frame := range stalled.Frames {
		got += len(frame)
	}
	if got == 0 || got > followerQueueBytes+len(chunk)+3 {
		t.Fatalf("stalled follower got %d bytes, want a bounded part", got)
	}
	stalled.Close()

	// Following a finished command is its replay and an end.
	done, err := e.set.follow("s", cmd)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := <-done.Frames; ok || len(done.Replay) == 0 {
		t.Fatalf("finished follow: replay %d bytes", len(done.Replay))
	}
	done.Close()
	if _, err := e.set.follow("s", "nope"); !errors.Is(err, toolhost.ErrCommandNotFound) {
		t.Fatalf("follow a missing command = %v", err)
	}
}

// Stop, destroy, passivate and migrate end the sandbox's sessions; a
// restarted sandbox starts with none.
func TestSandboxEndEndsSessions(t *testing.T) {
	for _, op := range []string{"stop", "destroy", "passivate"} {
		t.Run(op, func(t *testing.T) {
			e := newSessionEnv(t, Config{ModulesDir: t.TempDir()})
			e.d.SetWorkerSupervisor(&fakeSupervisor{})
			_, _ = e.set.create("s")
			cmd := e.exec(t, "s", "mod", true).ID
			run := e.stream(t, 0)
			f, err := e.set.follow("s", cmd)
			if err != nil {
				t.Fatal(err)
			}
			switch op {
			case "stop":
				err = e.d.Stop(context.Background(), "sb")
			case "destroy":
				err = e.d.Destroy(context.Background(), &models.Sandbox{ID: "sb"})
			case "passivate":
				_, _, err = e.d.CheckpointSandbox(context.Background(), &models.Sandbox{ID: "sb"})
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-run.closed:
			case <-time.After(5 * time.Second):
				t.Fatal("running command not ended")
			}
			for range f.Frames {
			}
			f.Close()
			if _, err := e.set.create("x"); !errors.Is(err, toolhost.ErrSessionStopped) {
				t.Fatalf("create on an ended set = %v", err)
			}
			if _, err := e.set.exec(context.Background(), "s", toolhost.SessionCommand{Argv: []string{"x"}}, true); !errors.Is(err, toolhost.ErrSessionStopped) {
				t.Fatalf("exec on an ended set = %v", err)
			}
			e.set.close() // twice is fine
			if op != "stop" {
				// Destroy and passivate take the instance away.
				return
			}
			// A stopped sandbox has no sessions; a restarted one starts
			// with none.
			if _, err := e.d.sessionsFor("sb"); !errors.Is(err, toolhost.ErrSessionStopped) {
				t.Fatalf("sessions of a stopped sandbox = %v", err)
			}
			e.d.mu.Lock()
			e.d.byID["sb"].status = models.SandboxStatusStarted
			e.d.mu.Unlock()
			fresh, err := e.d.sessionsFor("sb")
			if err != nil || fresh == e.set || len(fresh.list()) != 0 {
				t.Fatalf("after %s: set %p (old %p) sessions %v %v", op, fresh, e.set, fresh.list(), err)
			}
		})
	}
}

// A run that starts after its session is deleted is killed at once.
func TestSessionDeletedWhileStarting(t *testing.T) {
	e := newSessionEnv(t, Config{})
	_, _ = e.set.create("s")
	started := make(chan struct{})
	release := make(chan struct{})
	start := e.set.start
	e.set.start = func(ctx context.Context, argv []string) (*Stream, error) {
		close(started)
		<-release
		return start(ctx, argv)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := e.set.exec(context.Background(), "s", toolhost.SessionCommand{Argv: []string{"mod"}}, false)
		errc <- err
	}()
	<-started
	if err := e.set.delete("s"); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-errc; !errors.Is(err, toolhost.ErrSessionNotFound) {
		t.Fatalf("exec into a deleted session = %v", err)
	}
	run := e.stream(t, 0)
	select {
	case <-run.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("run of a deleted session left going")
	}
}

// A sync exec whose caller leaves before its turn comes is withdrawn.
func TestSessionSyncExecCallerLeavesWhileWaiting(t *testing.T) {
	e := newSessionEnv(t, Config{})
	_, _ = e.set.create("s")
	first := e.exec(t, "s", "mod", true).ID
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := e.set.exec(ctx, "s", toolhost.SessionCommand{Argv: []string{"mod"}}, false)
		errc <- err
	}()
	waitFor(t, "second command to queue", func() bool {
		info, _ := e.set.get("s")
		return len(info.Commands) == 2
	})
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("withdrawn exec = %v", err)
	}
	if info, _ := e.set.get("s"); len(info.Commands) != 1 {
		t.Fatalf("withdrawn command kept: %+v", info.Commands)
	}
	e.stream(t, 0).events <- exitEvent(0)
	e.waitExit(t, "s", first)
}

func TestSessionLimitsDefaults(t *testing.T) {
	got := New(Config{}, nil).sessionLimits()
	if got != (sessionLimits{logBytes: 1 << 20, sessions: 16, kept: 64, budget: 16 << 20, inputWait: defaultSessionInputWait}) {
		t.Fatalf("defaults = %+v", got)
	}
	got = New(Config{SessionLogBytes: 1, MaxSessionsPerSandbox: 2, SessionCommandsKept: 3, SessionLogBudget: 4}, nil).sessionLimits()
	if got != (sessionLimits{logBytes: 1, sessions: 2, kept: 3, budget: 4, inputWait: defaultSessionInputWait}) {
		t.Fatalf("configured = %+v", got)
	}
}

// TestSessionInputNeverHangs: input to a command that does not read its
// stdin holds no request. The caller waits at most inputWait (408) or
// until it leaves; the write stays pending, and input sent while it is
// pending is refused at once (409) rather than queued with its body. The
// pending write ends with the command.
func TestSessionInputNeverHangs(t *testing.T) {
	e := newSessionEnv(t, Config{})
	_, _ = e.set.create("a")
	_, _ = e.set.create("b")
	stuck := func(session string, i int) (string, *fakeExecStream) {
		id := e.exec(t, session, "mod block", true).ID
		run := e.stream(t, i)
		run.mu.Lock()
		run.onStdin = func() { <-run.closed } // the guest never reads
		run.mu.Unlock()
		return id, run
	}
	input := func(ctx context.Context, session, cmd string) <-chan error {
		out := make(chan error, 1)
		go func() { out <- e.set.input(ctx, session, cmd, []byte("x\n")) }()
		return out
	}
	within := func(what string, ch <-chan error, d time.Duration) error {
		t.Helper()
		select {
		case err := <-ch:
			return err
		case <-time.After(d):
			t.Fatalf("%s: input still waiting after %s", what, d)
			return nil
		}
	}

	// A caller that leaves gets its context's error at once.
	e.set.limits.inputWait = time.Hour
	cmdA, runA := stuck("a", 0)
	ctx, cancel := context.WithCancel(context.Background())
	pending := input(ctx, "a", cmdA)
	waitFor(t, "the write to start", func() bool { runA.mu.Lock(); defer runA.mu.Unlock(); return len(runA.stdin) > 0 })
	cancel()
	if err := within("cancelled", pending, 5*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled input = %v", err)
	}
	// Its write is still pending: the next input is refused, not queued.
	if err := within("second", input(context.Background(), "a", cmdA), time.Second); !errors.Is(err, toolhost.ErrInputPending) {
		t.Fatalf("input behind a pending one = %v, want ErrInputPending", err)
	}

	// A caller that stays gets 408 after inputWait.
	e.set.limits.inputWait = 50 * time.Millisecond
	cmdB, _ := stuck("b", 1)
	if err := within("timed", input(context.Background(), "b", cmdB), 5*time.Second); !errors.Is(err, toolhost.ErrInputTimeout) {
		t.Fatalf("input the command never reads = %v, want ErrInputTimeout", err)
	}

	// The command ends: its pending write fails and frees the slot.
	runA.events <- exitEvent(0)
	e.waitExit(t, "a", cmdA)
	if err := within("after the end", input(context.Background(), "a", cmdA), time.Second); !errors.Is(err, toolhost.ErrCommandNotRunning) {
		t.Fatalf("input after the end = %v", err)
	}
	e.set.mu.Lock()
	c := e.set.sessions["a"].commands[cmdA]
	e.set.mu.Unlock()
	waitFor(t, "the pending write to end", func() bool { return len(c.stdinBusy) == 0 })
}

// TestSessionCommandKeepsItsTextOnce: a command's argv goes once its run
// has started or failed to start, so a kept command holds its text once.
// A queued async command whose start fails is a finished command like any
// other: the finished-command cap drops the oldest of them.
func TestSessionCommandKeepsItsTextOnce(t *testing.T) {
	e := newSessionEnv(t, Config{SessionCommandsKept: 3})
	_, _ = e.set.create("s")
	argvOf := func(id string) []string {
		e.set.mu.Lock()
		defer e.set.mu.Unlock()
		if c := e.set.sessions["s"].commands[id]; c != nil {
			return c.argv
		}
		return nil
	}
	failStarts := func(fail bool) {
		e.fake.mu.Lock()
		defer e.fake.mu.Unlock()
		e.fake.startErr = nil
		if fail {
			e.fake.startErr = errors.New("no free slot")
		}
	}
	var last []string
	for round := 0; round < 3; round++ {
		failStarts(false)
		blocker := e.exec(t, "s", "mod block", true).ID
		run := e.stream(t, round)
		if argv := argvOf(blocker); argv != nil {
			t.Fatalf("started command keeps argv %q", argv)
		}
		// Two commands queue behind it, then fail to start.
		queued := []string{
			e.exec(t, "s", "mod queued "+strings.Repeat("x", 1024), true).ID,
			e.exec(t, "s", "mod queued "+strings.Repeat("y", 1024), true).ID,
		}
		failStarts(true)
		run.events <- exitEvent(0)
		e.waitExit(t, "s", blocker)
		for _, id := range queued {
			if code := e.waitExit(t, "s", id); code != -1 {
				t.Fatalf("refused start exit = %d", code)
			}
			if argv := argvOf(id); argv != nil {
				t.Fatalf("refused command keeps argv %q", argv)
			}
		}
		last = append([]string{blocker}, queued...)
	}
	info, _ := e.set.get("s")
	if len(info.Commands) != 3 {
		t.Fatalf("session keeps %d commands, want the 3 newest", len(info.Commands))
	}
	for i, c := range info.Commands {
		if c.ID != last[i] {
			t.Fatalf("kept %s at %d, want %s", c.ID, i, last[i])
		}
	}
}
