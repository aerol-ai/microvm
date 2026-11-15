package codeinterp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeKernel runs "code" as a tiny script: "print X" emits stdout X,
// "sleep" blocks until interrupted or closed, "ignore" blocks until closed
// (it ignores interrupts), "die" kills the kernel mid-run, "fail" ends with
// an error event. Every other code is echoed back as a main result.
type fakeKernel struct {
	spec Spec

	mu          sync.Mutex
	done        chan struct{}
	interrupted chan struct{}
	closed      bool
	interrupts  int
	runs        int
}

func newFakeKernel(spec Spec) *fakeKernel {
	return &fakeKernel{spec: spec, done: make(chan struct{}), interrupted: make(chan struct{}, 8)}
}

func (k *fakeKernel) Execute(req Request, sink Sink) (Outcome, error) {
	k.mu.Lock()
	k.runs++
	n := k.runs
	k.mu.Unlock()
	sink(Event{Kind: EventCount, Count: n})
	switch req.Code {
	case "sleep":
		select {
		case <-k.interrupted:
			return Outcome{Status: "interrupted"}, nil
		case <-k.done:
			return Outcome{Died: true}, nil
		}
	case "ignore":
		<-k.done
		return Outcome{Died: true}, nil
	case "die":
		_ = k.Close()
		return Outcome{Died: true}, nil
	case "fail":
		sink(Event{Kind: EventError, ErrName: "ValueError", ErrValue: "bad"})
		return Outcome{Status: "error"}, nil
	}
	if len(req.Code) > 6 && req.Code[:6] == "print " {
		sink(Event{Kind: EventStdout, Text: req.Code[6:]})
		return Outcome{Status: "ok"}, nil
	}
	sink(Event{Kind: EventResult, Main: true, Bundle: map[string]any{"text/plain": req.Code + "|" + k.spec.Cwd + "|" + req.Env["K"]}})
	return Outcome{Status: "ok"}, nil
}

func (k *fakeKernel) Interrupt() error {
	k.mu.Lock()
	k.interrupts++
	k.mu.Unlock()
	select {
	case k.interrupted <- struct{}{}:
	default:
	}
	return nil
}

func (k *fakeKernel) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.closed {
		k.closed = true
		close(k.done)
	}
	return nil
}

func (k *fakeKernel) Done() <-chan struct{} { return k.done }

type fakeLauncher struct {
	mu       sync.Mutex
	launched []*fakeKernel
	fail     error
	block    chan struct{}
}

func (l *fakeLauncher) Launch(ctx context.Context, spec Spec) (Kernel, error) {
	if l.block != nil {
		select {
		case <-l.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail != nil {
		return nil, l.fail
	}
	k := newFakeKernel(spec)
	l.launched = append(l.launched, k)
	return k, nil
}

func (l *fakeLauncher) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.launched)
}

type collector struct {
	mu     sync.Mutex
	events []Event
}

func (c *collector) sink(e Event) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
}

func (c *collector) results() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, e := range c.events {
		switch e.Kind {
		case EventResult:
			out = append(out, fmt.Sprint(e.Bundle["text/plain"]))
		case EventStdout:
			out = append(out, "out:"+e.Text)
		case EventError:
			out = append(out, "err:"+e.ErrName)
		}
	}
	return out
}

func newTestManager(t *testing.T, l *fakeLauncher, mutate func(*Options)) *Manager {
	t.Helper()
	var n atomic.Int32
	opts := Options{
		Launcher:   l,
		DefaultCwd: "/home/user",
		newID:      func() string { return fmt.Sprintf("ctx-%d", n.Add(1)) },
	}
	if mutate != nil {
		mutate(&opts)
	}
	m := NewManager(opts)
	t.Cleanup(m.Close)
	return m
}

func TestCreateRunKeepsKernel(t *testing.T) {
	l := &fakeLauncher{}
	m := newTestManager(t, l, nil)
	info, err := m.Create(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if info.Language != LangPython || info.Cwd != "/home/user" || !info.Active || info.Default {
		t.Fatalf("info = %+v", info)
	}
	for i := 0; i < 3; i++ {
		var c collector
		res, err := m.Run(context.Background(), info.ID, Request{Code: "x", Env: map[string]string{"K": "v"}}, c.sink, RunPolicy{})
		if err != nil || res.Status != "ok" {
			t.Fatalf("run %d: %+v %v", i, res, err)
		}
		if got := c.results(); len(got) != 1 || got[0] != "x|/home/user|v" {
			t.Fatalf("run %d results = %v", i, got)
		}
		if c.events[0].Kind != EventCount || c.events[0].Count != i+1 {
			t.Fatalf("run %d count event = %+v (the same kernel must serve every run)", i, c.events[0])
		}
	}
	if l.count() != 1 {
		t.Fatalf("launched %d kernels, want 1", l.count())
	}
}

func TestCreateErrors(t *testing.T) {
	cases := []struct {
		name   string
		lang   string
		mutate func(*Options)
		l      *fakeLauncher
		want   error
	}{
		{name: "unknown language", lang: "cobol", want: ErrUnsupportedLanguage},
		{name: "language not offered", lang: "r", mutate: func(o *Options) { o.Languages = []string{LangPython} }, want: ErrUnsupportedLanguage},
		{name: "launch fails", lang: "python", l: &fakeLauncher{fail: &MissingInterpreterError{Language: "python", Programs: []string{"python3"}}}},
		{name: "limit", lang: "python", mutate: func(o *Options) { full := NewLimit(1); full.acquire(); o.Limit = full }, want: ErrLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := tc.l
			if l == nil {
				l = &fakeLauncher{}
			}
			m := newTestManager(t, l, tc.mutate)
			_, err := m.Create(context.Background(), tc.lang, "")
			if err == nil {
				t.Fatal("want error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if len(m.List()) != 0 {
				t.Fatal("failed create left a context behind")
			}
		})
	}
}

func TestLimitSharedAndReleased(t *testing.T) {
	lim := NewLimit(2)
	a := newTestManager(t, &fakeLauncher{}, func(o *Options) { o.Limit = lim })
	b := newTestManager(t, &fakeLauncher{}, func(o *Options) { o.Limit = lim })
	c1, err := a.Create(context.Background(), "python", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Default("python"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create(context.Background(), "python", ""); !errors.Is(err, ErrLimit) {
		t.Fatalf("third context: err = %v, want ErrLimit", err)
	}
	if err := a.Delete(c1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create(context.Background(), "python", ""); err != nil {
		t.Fatalf("after delete: %v", err)
	}
}

func TestDefaultsDaytonaStyle(t *testing.T) {
	l := &fakeLauncher{}
	m := newTestManager(t, l, func(o *Options) {
		o.DefaultID = func(lang string) string {
			if lang == LangPython {
				return "default"
			}
			return ""
		}
		o.ProtectDefaults = true
	})
	d, err := m.Default("")
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != "default" || !d.Default {
		t.Fatalf("default = %+v", d)
	}
	if l.count() != 0 {
		t.Fatal("a default context must not start its kernel until its first run")
	}
	again, _ := m.Default("python")
	if again.ID != d.ID {
		t.Fatal("Default must return the same context")
	}
	if got := m.List(); len(got) != 0 {
		t.Fatalf("Daytona hides the default from List, got %+v", got)
	}
	if err := m.Delete("default"); !errors.Is(err, ErrDefaultContext) {
		t.Fatalf("delete default: %v", err)
	}
	var c collector
	if _, err := m.Run(context.Background(), "default", Request{Code: "print hi"}, c.sink, RunPolicy{}); err != nil {
		t.Fatal(err)
	}
	if l.count() != 1 {
		t.Fatal("first run must start the default's kernel")
	}
}

func TestDefaultsE2BStyle(t *testing.T) {
	m := newTestManager(t, &fakeLauncher{}, func(o *Options) { o.ListDefaults = true })
	py, _ := m.Default("python")
	js, _ := m.Default("js")
	if js.Language != LangJavaScript {
		t.Fatalf("js default language = %q", js.Language)
	}
	user, err := m.Create(context.Background(), "python", "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	got := m.List()
	if len(got) != 3 || got[0].ID != py.ID || got[1].ID != js.ID || got[2].ID != user.ID {
		t.Fatalf("list must keep creation order with defaults first, got %+v", got)
	}
	if err := m.Delete(py.ID); err != nil {
		t.Fatalf("E2B deletes defaults: %v", err)
	}
	again, _ := m.Default("python")
	if again.ID == py.ID {
		t.Fatal("a deleted default must be replaced by a new context, not resurrected")
	}
}

func TestRunNotFoundAndDeleteUnknown(t *testing.T) {
	m := newTestManager(t, &fakeLauncher{}, nil)
	if _, err := m.Run(context.Background(), "nope", Request{Code: "x"}, func(Event) {}, RunPolicy{}); !IsNotFound(err) {
		t.Fatalf("run unknown: %v", err)
	}
	if err := m.Delete("nope"); !IsNotFound(err) {
		t.Fatalf("delete unknown: %v", err)
	}
	if _, err := m.Get("nope"); !IsNotFound(err) {
		t.Fatalf("get unknown: %v", err)
	}
	if _, err := m.Restart(context.Background(), "nope"); !IsNotFound(err) {
		t.Fatalf("restart unknown: %v", err)
	}
	if err := m.Interrupt("nope"); !IsNotFound(err) {
		t.Fatalf("interrupt unknown: %v", err)
	}
}

func TestTimeoutInterruptsThenKills(t *testing.T) {
	cases := []struct {
		name       string
		code       string
		wantStatus string
		wantDied   bool
	}{
		{name: "code stops on interrupt", code: "sleep", wantStatus: "interrupted"},
		{name: "code ignores interrupt", code: "ignore", wantDied: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &fakeLauncher{}
			m := newTestManager(t, l, nil)
			info, _ := m.Create(context.Background(), "python", "")
			res, err := m.Run(context.Background(), info.ID, Request{Code: tc.code}, func(Event) {},
				RunPolicy{Timeout: 20 * time.Millisecond, Grace: 20 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			if !res.TimedOut || res.Status != tc.wantStatus || res.Died != tc.wantDied {
				t.Fatalf("res = %+v", res)
			}
			got, _ := m.Get(info.ID)
			if got.Active == tc.wantDied {
				t.Fatalf("active = %v after died=%v", got.Active, tc.wantDied)
			}
			// The next run works; a killed kernel is replaced.
			if _, err := m.Run(context.Background(), info.ID, Request{Code: "x"}, func(Event) {}, RunPolicy{}); err != nil {
				t.Fatal(err)
			}
			want := 1
			if tc.wantDied {
				want = 2
			}
			if l.count() != want {
				t.Fatalf("kernels launched = %d, want %d", l.count(), want)
			}
			if got, _ := m.Get(info.ID); !got.Active {
				t.Fatal("a fresh kernel makes the context active again")
			}
		})
	}
}

func TestCancelPolicy(t *testing.T) {
	for _, interrupt := range []bool{true, false} {
		t.Run(fmt.Sprint("interruptOnCancel=", interrupt), func(t *testing.T) {
			l := &fakeLauncher{}
			m := newTestManager(t, l, nil)
			info, _ := m.Create(context.Background(), "python", "")
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan RunResult, 1)
			go func() {
				res, _ := m.Run(ctx, info.ID, Request{Code: "sleep"}, func(Event) {}, RunPolicy{InterruptOnCancel: interrupt})
				done <- res
			}()
			waitFor(t, func() bool { return l.count() == 1 && l.launched[0].runCount() == 1 })
			cancel()
			select {
			case res := <-done:
				if !interrupt {
					t.Fatalf("without InterruptOnCancel the run must keep going, got %+v", res)
				}
				if res.Status != "interrupted" {
					t.Fatalf("res = %+v", res)
				}
			case <-time.After(200 * time.Millisecond):
				if interrupt {
					t.Fatal("cancel did not interrupt the run")
				}
				// Daytona: the run continues until something stops it.
				_ = m.Interrupt(info.ID)
				res := <-done
				if res.Status != "interrupted" {
					t.Fatalf("res = %+v", res)
				}
			}
		})
	}
}

func (k *fakeKernel) runCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.runs
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func TestQueueOneRunAtATime(t *testing.T) {
	l := &fakeLauncher{}
	m := newTestManager(t, l, func(o *Options) { o.QueueLimit = 1 })
	info, _ := m.Create(context.Background(), "python", "")
	first := make(chan RunResult, 1)
	go func() {
		res, _ := m.Run(context.Background(), info.ID, Request{Code: "sleep"}, func(Event) {}, RunPolicy{})
		first <- res
	}()
	waitFor(t, func() bool { return l.launched[0].runCount() == 1 })
	second := make(chan error, 1)
	go func() {
		_, err := m.Run(context.Background(), info.ID, Request{Code: "x"}, func(Event) {}, RunPolicy{})
		second <- err
	}()
	waitFor(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.contexts[info.ID].waiting.Load() == 1
	})
	if _, err := m.Run(context.Background(), info.ID, Request{Code: "x"}, func(Event) {}, RunPolicy{}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("third run: %v, want ErrQueueFull", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Run(ctx, info.ID, Request{Code: "x"}, func(Event) {}, RunPolicy{}); err == nil {
		// The queue is full, so this may also be ErrQueueFull; both are fine.
		t.Fatal("cancelled waiter must not run")
	}
	_ = m.Interrupt(info.ID)
	<-first
	if err := <-second; err != nil {
		t.Fatalf("queued run: %v", err)
	}
}

func TestRestartAndDeleteDuringRun(t *testing.T) {
	for _, op := range []string{"restart", "delete"} {
		t.Run(op, func(t *testing.T) {
			l := &fakeLauncher{}
			m := newTestManager(t, l, nil)
			info, _ := m.Create(context.Background(), "python", "/w")
			done := make(chan RunResult, 1)
			go func() {
				res, _ := m.Run(context.Background(), info.ID, Request{Code: "ignore"}, func(Event) {}, RunPolicy{})
				done <- res
			}()
			waitFor(t, func() bool { return l.launched[0].runCount() == 1 })
			if op == "restart" {
				got, err := m.Restart(context.Background(), info.ID)
				if err != nil || got.ID != info.ID || got.Cwd != "/w" || !got.Active {
					t.Fatalf("restart = %+v %v", got, err)
				}
			} else if err := m.Delete(info.ID); err != nil {
				t.Fatal(err)
			}
			res := <-done
			if !res.Restarted {
				t.Fatalf("in-flight run must report Restarted, got %+v", res)
			}
			if op == "restart" {
				var c collector
				if _, err := m.Run(context.Background(), info.ID, Request{Code: "y"}, c.sink, RunPolicy{}); err != nil {
					t.Fatal(err)
				}
				if c.events[0].Count != 1 {
					t.Fatal("a restarted context must run on a fresh kernel")
				}
			} else if _, err := m.Get(info.ID); !IsNotFound(err) {
				t.Fatal("deleted context still listed")
			}
		})
	}
}

func TestKernelDeathMarksInactive(t *testing.T) {
	l := &fakeLauncher{}
	m := newTestManager(t, l, nil)
	info, _ := m.Create(context.Background(), "python", "")
	res, err := m.Run(context.Background(), info.ID, Request{Code: "die"}, func(Event) {}, RunPolicy{})
	if err != nil || !res.Died {
		t.Fatalf("res = %+v %v", res, err)
	}
	if got, _ := m.Get(info.ID); got.Active {
		t.Fatal("context must be inactive after its kernel died")
	}
	// Died between runs: closed while idle.
	if _, err := m.Run(context.Background(), info.ID, Request{Code: "x"}, func(Event) {}, RunPolicy{}); err != nil {
		t.Fatal(err)
	}
	_ = l.launched[1].Close()
	if _, err := m.Run(context.Background(), info.ID, Request{Code: "x"}, func(Event) {}, RunPolicy{}); err != nil {
		t.Fatal(err)
	}
	if l.count() != 3 {
		t.Fatalf("launched %d, want 3", l.count())
	}
}

func TestRelaunchFailureKeepsContext(t *testing.T) {
	l := &fakeLauncher{}
	m := newTestManager(t, l, nil)
	info, _ := m.Create(context.Background(), "python", "")
	_, _ = m.Run(context.Background(), info.ID, Request{Code: "die"}, func(Event) {}, RunPolicy{})
	l.mu.Lock()
	l.fail = errors.New("boom")
	l.mu.Unlock()
	if _, err := m.Run(context.Background(), info.ID, Request{Code: "x"}, func(Event) {}, RunPolicy{}); err == nil {
		t.Fatal("want launch error")
	}
	if _, err := m.Restart(context.Background(), info.ID); err == nil {
		t.Fatal("want restart launch error")
	}
	got, err := m.Get(info.ID)
	if err != nil || got.Active {
		t.Fatalf("context must remain, inactive: %+v %v", got, err)
	}
}

func TestIdleReaperStopsKernels(t *testing.T) {
	l := &fakeLauncher{}
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	m := newTestManager(t, l, func(o *Options) {
		o.IdleTTL = time.Hour
		o.now = func() time.Time { return time.Unix(0, now.Load()) }
	})
	info, _ := m.Create(context.Background(), "python", "")
	if _, err := m.Run(context.Background(), info.ID, Request{Code: "x"}, func(Event) {}, RunPolicy{}); err != nil {
		t.Fatal(err)
	}
	m.reapOnce()
	if l.launched[0].closed {
		t.Fatal("reaped a kernel that was not idle")
	}
	now.Add(int64(2 * time.Hour))
	m.reapOnce()
	select {
	case <-l.launched[0].Done():
	default:
		t.Fatal("idle kernel not stopped")
	}
	if got, _ := m.Get(info.ID); got.Active {
		t.Fatal("a reaped context lost its state and must say so")
	}
	if _, err := m.Run(context.Background(), info.ID, Request{Code: "x"}, func(Event) {}, RunPolicy{}); err != nil {
		t.Fatal(err)
	}
	if l.count() != 2 {
		t.Fatal("next run after a reap starts a new kernel")
	}
}

func TestCloseKillsEverything(t *testing.T) {
	l := &fakeLauncher{}
	lim := NewLimit(4)
	m := NewManager(Options{Launcher: l, Limit: lim, IdleTTL: time.Minute})
	a, _ := m.Create(context.Background(), "python", "")
	_, _ = m.Create(context.Background(), "bash", "")
	m.Close()
	m.Close() // idempotent
	for _, k := range l.launched {
		select {
		case <-k.Done():
		default:
			t.Fatal("kernel left running after Close")
		}
	}
	if _, err := m.Create(context.Background(), "python", ""); !errors.Is(err, ErrClosed) {
		t.Fatalf("create after close: %v", err)
	}
	if _, err := m.Get(a.ID); !errors.Is(err, ErrClosed) {
		t.Fatalf("get after close: %v", err)
	}
	if err := m.Delete(a.ID); !errors.Is(err, ErrClosed) {
		t.Fatalf("delete after close: %v", err)
	}
	if lim.used != 0 {
		t.Fatalf("limit slots leaked: %d", lim.used)
	}
}

func TestInterruptIdleIsNoop(t *testing.T) {
	l := &fakeLauncher{}
	m := newTestManager(t, l, nil)
	info, _ := m.Create(context.Background(), "python", "")
	if err := m.Interrupt(info.ID); err != nil {
		t.Fatal(err)
	}
	if l.launched[0].interrupts != 0 {
		t.Fatal("interrupting an idle context must not signal the kernel")
	}
}

func TestRandomIDShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := randomID()
		if len(id) != 36 || id[14] != '4' || seen[id] {
			t.Fatalf("bad id %q", id)
		}
		seen[id] = true
	}
}
