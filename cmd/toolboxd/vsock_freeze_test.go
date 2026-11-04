package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// freeze_fs / thaw_fs let the host copy a running Firecracker VM's disk while
// nothing writes to it. What matters: the root filesystem is flushed then
// frozen, it is always thawed in the end (by the host or by the safety
// timer), and a late safety timer never thaws a newer freeze.

func opRoundTrip(t *testing.T, h VsockHandler, msg VsockMessage) VsockResponse {
	t.Helper()
	host, guest := newPipePair()
	done := runHandlerInBackground(t, guest, h)
	line, _ := json.Marshal(msg)
	if _, err := host.Write(append(line, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
	var resp VsockResponse
	if err := json.NewDecoder(host).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	closePipeWriter(host)
	<-done
	return resp
}

// fakeTimers captures the safety thaws the handler schedules, so a test can
// fire one when it chooses.
type fakeTimers struct {
	mu     sync.Mutex
	timers []*fakeTimer
}

type fakeTimer struct {
	after   time.Duration
	fire    func()
	stopped bool
}

func (t *fakeTimer) Stop() bool { t.stopped = true; return true }

func (f *fakeTimers) afterFunc(d time.Duration, fn func()) thawTimer {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTimer{after: d, fire: fn}
	f.timers = append(f.timers, t)
	return t
}

func (f *fakeTimers) last(t *testing.T) *fakeTimer {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.timers) == 0 {
		t.Fatal("no safety thaw was scheduled")
	}
	return f.timers[len(f.timers)-1]
}

func freezeHandler() (*quiesceHandler, *fakeQuiesceOps, *fakeTimers) {
	q := &fakeQuiesceOps{}
	timers := &fakeTimers{}
	h := newQuiesceHandler(nil, nil, nil)
	h.quiesce = q
	h.afterFunc = timers.afterFunc
	return h, q, timers
}

func freezeData(ms int64) json.RawMessage {
	raw, _ := json.Marshal(map[string]int64{"thaw_after_ms": ms})
	return raw
}

func TestVsock_FreezeThenThawTheRootFilesystem(t *testing.T) {
	h, q, timers := freezeHandler()
	if resp := opRoundTrip(t, h, VsockMessage{Op: OpFreezeFS, Data: freezeData(90_000)}); !resp.Ok {
		t.Fatalf("freeze_fs = %+v, want Ok", resp)
	}
	// Flushed first, while writes still flow, then frozen.
	if q.syncCalls != 1 || !reflect.DeepEqual(q.recorded(), []string{"freeze"}) {
		t.Fatalf("after freeze_fs: %d syncs, calls %v; want 1 sync then freeze", q.syncCalls, q.recorded())
	}
	timer := timers.last(t)
	if timer.after != 90*time.Second {
		t.Fatalf("safety thaw after %s, want 90s", timer.after)
	}
	if resp := opRoundTrip(t, h, VsockMessage{Op: OpThawFS}); !resp.Ok {
		t.Fatalf("thaw_fs = %+v, want Ok", resp)
	}
	if !reflect.DeepEqual(q.recorded(), []string{"freeze", "thaw"}) || !timer.stopped || h.freeze.frozen {
		t.Fatalf("after thaw_fs: calls %v, timer stopped %v, frozen %v", q.recorded(), timer.stopped, h.freeze.frozen)
	}
	// The cancelled timer firing late changes nothing.
	timer.fire()
	if got := q.recorded(); len(got) != 2 {
		t.Fatalf("a stale safety thaw thawed again: %v", got)
	}
}

// A host retry keeps the freeze (no second FIFREEZE, which the kernel would
// refuse with EBUSY) and restarts the safety thaw.
func TestQuiesceHandler_RepeatedFreezeRestartsTheSafetyThaw(t *testing.T) {
	h, q, timers := freezeHandler()
	ctx := context.Background()
	if err := h.OnFreezeFS(ctx, freezeData(5_000)); err != nil {
		t.Fatal(err)
	}
	first := timers.last(t)
	if err := h.OnFreezeFS(ctx, freezeData(7_000)); err != nil {
		t.Fatal(err)
	}
	second := timers.last(t)
	if !reflect.DeepEqual(q.recorded(), []string{"freeze"}) {
		t.Fatalf("calls %v, want one freeze", q.recorded())
	}
	if !first.stopped || second.after != 7*time.Second {
		t.Fatalf("first timer stopped %v, second after %s; want the first replaced by a 7s one", first.stopped, second.after)
	}
	first.fire() // scheduled for the earlier freeze: must not thaw this one
	if !h.freeze.frozen || len(q.recorded()) != 1 {
		t.Fatalf("the first freeze's timer thawed the second freeze: %v", q.recorded())
	}
	second.fire()
	if h.freeze.frozen || !reflect.DeepEqual(q.recorded(), []string{"freeze", "thaw"}) {
		t.Fatalf("safety thaw: frozen %v, calls %v", h.freeze.frozen, q.recorded())
	}
}

// A host that died mid-copy never sends thaw_fs; the timer thaws.
func TestQuiesceHandler_SafetyThawWhenTheHostNeverThaws(t *testing.T) {
	h, q, timers := freezeHandler()
	if err := h.OnFreezeFS(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	timer := timers.last(t)
	if timer.after != defaultFreezeThawAfter {
		t.Fatalf("no thaw_after_ms gave %s, want the default %s", timer.after, defaultFreezeThawAfter)
	}
	timer.fire()
	if h.freeze.frozen || !reflect.DeepEqual(q.recorded(), []string{"freeze", "thaw"}) {
		t.Fatalf("frozen %v, calls %v", h.freeze.frozen, q.recorded())
	}
	// A thaw_fs arriving afterwards is still fine.
	if err := h.OnThawFS(context.Background()); err != nil {
		t.Fatalf("thaw after the safety thaw: %v", err)
	}
}

func TestQuiesceHandler_SafetyThawThatFailsLeavesTheFreezeForTheHost(t *testing.T) {
	h, q, timers := freezeHandler()
	if err := h.OnFreezeFS(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	q.thawErr = errors.New("EIO")
	timers.last(t).fire()
	if !h.freeze.frozen {
		t.Fatal("a failed safety thaw recorded the filesystem as thawed")
	}
	q.thawErr = nil
	if err := h.OnThawFS(context.Background()); err != nil || h.freeze.frozen {
		t.Fatalf("host thaw after a failed safety thaw = %v, frozen %v", err, h.freeze.frozen)
	}
}

func TestQuiesceHandler_FreezeFailures(t *testing.T) {
	t.Run("bad payload", func(t *testing.T) {
		h, q, _ := freezeHandler()
		err := h.OnFreezeFS(context.Background(), json.RawMessage(`{"thaw_after_ms":"soon"}`))
		if err == nil || !strings.Contains(err.Error(), "freeze_fs: decode") || len(q.recorded()) != 0 {
			t.Fatalf("OnFreezeFS = %v, calls %v; want a decode error and no freeze", err, q.recorded())
		}
	})
	t.Run("kernel refuses", func(t *testing.T) {
		h, q, timers := freezeHandler()
		q.freezeErr = errors.New("EBUSY")
		resp := opRoundTrip(t, h, VsockMessage{Op: OpFreezeFS})
		if resp.Ok || !strings.Contains(resp.Error, "freeze root filesystem: EBUSY") {
			t.Fatalf("freeze_fs = %+v, want the freeze error", resp)
		}
		if h.freeze.frozen || len(timers.timers) != 0 {
			t.Fatal("a failed freeze was recorded or scheduled a thaw")
		}
	})
	t.Run("flush fails", func(t *testing.T) {
		// The freeze flushes too; a failed pre-flush only costs pause time.
		h, q, _ := freezeHandler()
		q.syncErr = errors.New("EIO")
		if err := h.OnFreezeFS(context.Background(), nil); err != nil || !h.freeze.frozen {
			t.Fatalf("OnFreezeFS after a failed flush = %v, frozen %v; want frozen", err, h.freeze.frozen)
		}
	})
	t.Run("thaw fails", func(t *testing.T) {
		h, q, _ := freezeHandler()
		if err := h.OnFreezeFS(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		q.thawErr = errors.New("EIO")
		resp := opRoundTrip(t, h, VsockMessage{Op: OpThawFS})
		if resp.Ok || !strings.Contains(resp.Error, "thaw root filesystem: EIO") || !h.freeze.frozen {
			t.Fatalf("thaw_fs = %+v, frozen %v; want the error and still frozen", resp, h.freeze.frozen)
		}
	})
}

// An older agent answers "unknown op"; the host then asks for a stop.
func TestVsock_FreezeAndThawWithoutTheCapabilityAreUnknownOps(t *testing.T) {
	for _, op := range []VsockOp{OpFreezeFS, OpThawFS} {
		resp := opRoundTrip(t, &recordingHandler{}, VsockMessage{Op: op})
		if resp.Ok || !strings.Contains(resp.Error, `unknown op "`+string(op)+`"`) {
			t.Fatalf("%s to an agent without it = %+v, want unknown op", op, resp)
		}
	}
}

func TestClampFreezeThawAfter(t *testing.T) {
	for _, tc := range []struct{ in, want time.Duration }{
		{0, defaultFreezeThawAfter},
		{-time.Second, defaultFreezeThawAfter},
		{time.Millisecond, minFreezeThawAfter},
		{2 * time.Minute, 2 * time.Minute},
		{time.Hour, maxFreezeThawAfter},
	} {
		if got := clampFreezeThawAfter(tc.in); got != tc.want {
			t.Errorf("clampFreezeThawAfter(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// The production timer is a real *time.Timer.
func TestQuiesceHandler_ScheduleThawUsesARealTimerByDefault(t *testing.T) {
	h := newQuiesceHandler(nil, nil, nil)
	fired := make(chan struct{})
	timer := h.scheduleThaw(time.Millisecond, func() { close(fired) })
	if _, ok := timer.(*time.Timer); !ok {
		t.Fatalf("scheduleThaw returned %T, want *time.Timer", timer)
	}
	select {
	case <-fired:
	case <-time.After(5 * time.Second):
		t.Fatal("the real timer never fired")
	}
}

// A VM Stop froze resumes frozen; post_resume lifts the freeze before it
// does anything that might write, and disarms the safety thaw.
func TestQuiesceHandler_PostResumeThawsAFreeze(t *testing.T) {
	h, q, timers := freezeHandler()
	if err := h.OnFreezeFS(context.Background(), freezeData(60_000)); err != nil {
		t.Fatal(err)
	}
	if err := h.OnPostResume(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if h.freeze.frozen || !timers.last(t).stopped {
		t.Fatalf("frozen=%v timer stopped=%v after post_resume", h.freeze.frozen, timers.last(t).stopped)
	}
	got := q.recorded()
	thawAt := slicesIndex(got, "thaw")
	reseedAt := slicesIndex(got, "reseed")
	if thawAt < 0 || (reseedAt >= 0 && reseedAt < thawAt) {
		t.Fatalf("calls %v, want the thaw before anything else post_resume does", got)
	}
	// No freeze held: post_resume thaws nothing.
	before := len(q.recorded())
	if err := h.OnPostResume(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if slicesIndex(q.recorded()[before:], "thaw") >= 0 {
		t.Fatal("thawed with no freeze held")
	}
}

// A thaw that fails on resume keeps the freeze recorded (and its safety
// thaw armed) and does not fail post_resume.
func TestQuiesceHandler_PostResumeThawFailureKeepsTheFreeze(t *testing.T) {
	h, q, timers := freezeHandler()
	if err := h.OnFreezeFS(context.Background(), freezeData(60_000)); err != nil {
		t.Fatal(err)
	}
	q.thawErr = errors.New("EBUSY")
	if err := h.OnPostResume(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if !h.freeze.frozen || timers.last(t).stopped {
		t.Fatal("a failed thaw dropped the freeze or its safety thaw")
	}
}

func slicesIndex(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}
