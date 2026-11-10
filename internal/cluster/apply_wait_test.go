package cluster

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// heldFuture is a raft.ApplyFuture the test answers by hand, or never: raft
// drops the future of an entry it committed and queued for the FSM when it
// shuts down first (awaitApply).
type heldFuture struct {
	answer   chan error
	response any
}

func newHeldFuture() *heldFuture { return &heldFuture{answer: make(chan error, 1)} }

func (f *heldFuture) Error() error       { return <-f.answer }
func (f *heldFuture) Response() any      { return f.response }
func (f *heldFuture) Index() uint64      { return 1 }
func (f *heldFuture) answerWith(e error) { f.answer <- e }

// waitLeader is a Cluster whose leadership and term the test sets, with
// awaitApply's grace and poll interval shortened.
type waitLeader struct {
	c       *Cluster
	leading atomic.Bool
	term    atomic.Uint64
}

func newWaitLeader(grace time.Duration) *waitLeader {
	w := &waitLeader{c: &Cluster{}}
	w.leading.Store(true)
	w.term.Store(7)
	w.c.leaderTermHook = func() (bool, uint64) { return w.leading.Load(), w.term.Load() }
	w.c.applyWaitBoundsHook = func() (time.Duration, time.Duration) { return grace, time.Millisecond }
	return w
}

// settleLog records every outcome settle was called with.
type settleLog struct {
	mu       sync.Mutex
	outcomes []admissionOutcome
}

func (s *settleLog) settle(o admissionOutcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outcomes = append(s.outcomes, o)
}

func (s *settleLog) got() []admissionOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]admissionOutcome(nil), s.outcomes...)
}

type awaitResult struct {
	result  any
	outcome admissionOutcome
	err     error
	took    time.Duration
}

func runAwait(ctx context.Context, w *waitLeader, f raft.ApplyFuture, settle func(admissionOutcome)) <-chan awaitResult {
	out := make(chan awaitResult, 1)
	go func() {
		start := time.Now()
		r, o, err := w.c.awaitApply(ctx, f, 7, settle)
		out <- awaitResult{r, o, err, time.Since(start)}
	}()
	return out
}

func waitAwait(t *testing.T, ch <-chan awaitResult) awaitResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("awaitApply did not return")
		return awaitResult{}
	}
}

func waitSettled(t *testing.T, s *settleLog, want []admissionOutcome) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.got(); fmt.Sprint(got) == fmt.Sprint(want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("settle outcomes = %v, want %v", s.got(), want)
}

// A write raft never answers no longer hangs its caller: it is let go once
// its ctx ends, or once this server has stopped leading the term the write
// was proposed in (lost the leadership, raft stopped, or a later term) and
// the grace has passed. While this server still leads, a slow answer is
// waited for, past the grace.
func TestAwaitApplyIsBounded(t *testing.T) {
	const grace = 20 * time.Millisecond
	cases := []struct {
		name string
		// change runs once the write is waiting.
		change      func(w *waitLeader, cancel context.CancelFunc)
		wantErr     error
		wantOutcome admissionOutcome
		minTook     time.Duration
	}{
		{
			name:        "ctx ends",
			change:      func(_ *waitLeader, cancel context.CancelFunc) { cancel() },
			wantErr:     context.Canceled,
			wantOutcome: outcomeUnknown,
		},
		{
			name:        "leadership lost",
			change:      func(w *waitLeader, _ context.CancelFunc) { w.leading.Store(false) },
			wantErr:     ErrNotLeader,
			wantOutcome: outcomeUnknown,
			minTook:     grace,
		},
		{
			name: "leads a later term",
			// Lost the leadership and won it back: the write's term is over,
			// and the next term's barrier already dropped its hold.
			change:      func(w *waitLeader, _ context.CancelFunc) { w.term.Add(1) },
			wantErr:     ErrNotLeader,
			wantOutcome: outcomeUnknown,
			minTook:     grace,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWaitLeader(grace)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newHeldFuture()
			var settled settleLog
			done := runAwait(ctx, w, f, settled.settle)
			time.Sleep(5 * time.Millisecond)
			tc.change(w, cancel)
			got := waitAwait(t, done)
			if !errors.Is(got.err, tc.wantErr) || got.outcome != tc.wantOutcome || got.result != nil {
				t.Fatalf("awaitApply = (%v, %v, %v), want (nil, %v, %v)", got.result, got.outcome, got.err, tc.wantOutcome, tc.wantErr)
			}
			if got.took < tc.minTook {
				t.Fatalf("gave up after %v, before the %v grace", got.took, tc.minTook)
			}
			// The caller is gone, but settle still waits for raft: nothing is
			// settled until raft answers, and then with the real outcome.
			if s := settled.got(); len(s) != 0 {
				t.Fatalf("settled %v before raft answered", s)
			}
			f.answerWith(nil)
			waitSettled(t, &settled, []admissionOutcome{outcomeSettled})
		})
	}

	t.Run("slow answer while still leading", func(t *testing.T) {
		w := newWaitLeader(grace)
		f := newHeldFuture()
		f.response = "token"
		done := runAwait(context.Background(), w, f, nil)
		time.Sleep(5 * grace)
		select {
		case r := <-done:
			t.Fatalf("gave up while still leading: %+v", r)
		default:
		}
		f.answerWith(nil)
		got := waitAwait(t, done)
		if got.err != nil || got.outcome != outcomeSettled || got.result != "token" {
			t.Fatalf("awaitApply = (%v, %v, %v), want (token, settled, nil)", got.result, got.outcome, got.err)
		}
	})

	t.Run("answer within the grace wins", func(t *testing.T) {
		// raft answers in-flight entries as it steps down; that answer, not
		// the give-up, is what the caller gets.
		w := newWaitLeader(time.Minute)
		f := newHeldFuture()
		var settled settleLog
		done := runAwait(context.Background(), w, f, settled.settle)
		time.Sleep(5 * time.Millisecond)
		w.leading.Store(false)
		time.Sleep(5 * time.Millisecond)
		f.answerWith(raft.ErrLeadershipLost)
		got := waitAwait(t, done)
		if !errors.Is(got.err, ErrNotLeader) || got.outcome != outcomeUnknown {
			t.Fatalf("awaitApply = (%v, %v), want (unknown, ErrNotLeader)", got.outcome, got.err)
		}
		waitSettled(t, &settled, []admissionOutcome{outcomeUnknown})
	})
}

// An admitted create whose caller stopped waiting keeps counting against the
// worker until raft answers, and the answer releases it within the term:
// the hold follows the entry, not the caller.
func TestAwaitApplyHoldFollowsTheEntryNotTheCaller(t *testing.T) {
	l := newLedgerLeader(slotWorker("w1", 1, containerAndFC))
	l.c.applyWaitBoundsHook = func() (time.Duration, time.Duration) { return time.Minute, time.Millisecond }
	id, enqueued, err := l.admitNotEnqueued(ledgerReserve("sb-gone", "w1", "inc-gone", 1))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	enqueued()
	f := newHeldFuture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, outcome, err := l.c.awaitApply(ctx, f, l.term, func(o admissionOutcome) { l.c.settleHold(id, o) }); !errors.Is(err, context.Canceled) || outcome != outcomeUnknown {
		t.Fatalf("awaitApply with an ended ctx = (%v, %v), want (unknown, context.Canceled)", outcome, err)
	}
	if _, err := l.admit(ledgerReserve("sb-next", "w1", "inc-next", 1)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("while raft has not answered = %v, want ErrCapacityExceeded (the entry may still commit)", err)
	}
	// raft never appended it after all (it refused the entry): the slot is
	// free again in the same term.
	f.answerWith(raft.ErrNotLeader)
	deadline := time.Now().Add(5 * time.Second)
	for l.holds() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, err := l.admit(ledgerReserve("sb-next", "w1", "inc-next", 1)); err != nil {
		t.Fatalf("after raft answered = %v, want admitted", err)
	}
}

func TestApplyAnswerOf(t *testing.T) {
	refused := errors.New("placement refused")
	cases := []struct {
		name        string
		err         error
		response    any
		wantErr     error
		wantText    string
		wantOutcome admissionOutcome
		wantResult  any
	}{
		{name: "applied", response: "ok", wantOutcome: outcomeSettled, wantResult: "ok"},
		{name: "fsm refused", response: refused, wantErr: refused, wantText: "cluster: fsm apply: ", wantOutcome: outcomeSettled},
		{name: "not leader", err: raft.ErrNotLeader, wantErr: ErrNotLeader, wantOutcome: outcomeSettled},
		{name: "leadership lost", err: raft.ErrLeadershipLost, wantErr: ErrNotLeader, wantOutcome: outcomeUnknown},
		{name: "shut down", err: raft.ErrRaftShutdown, wantErr: raft.ErrRaftShutdown, wantText: "cluster: raft apply: ", wantOutcome: outcomeUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newHeldFuture()
			f.response = tc.response
			f.answerWith(tc.err)
			a := applyAnswerOf(f)
			if a.outcome != tc.wantOutcome || a.result != tc.wantResult {
				t.Fatalf("applyAnswerOf = (%v, %v), want (%v, %v)", a.result, a.outcome, tc.wantResult, tc.wantOutcome)
			}
			if tc.wantErr == nil {
				if a.err != nil {
					t.Fatalf("err = %v, want nil", a.err)
				}
				return
			}
			if !errors.Is(a.err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", a.err, tc.wantErr)
			}
			if tc.wantText != "" && (a.err == nil || len(a.err.Error()) < len(tc.wantText) || a.err.Error()[:len(tc.wantText)] != tc.wantText) {
				t.Fatalf("err = %q, want prefix %q", a.err, tc.wantText)
			}
		})
	}
}
