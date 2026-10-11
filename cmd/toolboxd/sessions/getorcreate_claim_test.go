package sessions

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// gatedManager returns a Manager whose process starts block on release, so
// a test can hold one GetOrCreate inside Create while others arrive. fail
// makes the first n starts fail.
func gatedManager(t *testing.T, release <-chan struct{}, entered chan<- struct{}, fail int32) *Manager {
	t.Helper()
	var failures atomic.Int32
	failures.Store(fail)
	mgr, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
		RecordingDir: t.TempDir(),
		StartProcess: func(cmd *exec.Cmd, start func() error) (func() (int, string), error) {
			entered <- struct{}{}
			<-release
			if failures.Add(-1) >= 0 {
				return nil, errors.New("start refused")
			}
			if err := start(); err != nil {
				return nil, err
			}
			return func() (int, string) { return waitProcess(cmd) }, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Close)
	return mgr
}

type claimResult struct {
	session *Session
	created bool
	err     error
}

// Regression for PR #641 review finding 2: callers treat created=true as an
// exclusive claim, so two concurrent GetOrCreate calls for one name must not
// both start a shell and both report created.
func TestGetOrCreateConcurrentCallersShareOneClaim(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	mgr := gatedManager(t, release, entered, 0)

	results := make(chan claimResult, 3)
	claim := func() {
		s, created, err := mgr.GetOrCreate(context.Background(), models.CreateSessionRequest{Name: "rlx-claim"})
		results <- claimResult{s, created, err}
	}
	go claim()
	<-entered // the first caller is inside Create, not yet published
	go claim()
	go claim()
	select {
	case <-entered:
		t.Fatal("a second caller started its own process while the first was still creating")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)

	var created int
	var first *Session
	for range 3 {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.created {
			created++
		}
		if first == nil {
			first = r.session
		} else if r.session != first {
			t.Fatal("concurrent callers got different sessions for one name")
		}
	}
	if created != 1 {
		t.Fatalf("created=true reported %d times; want exactly 1", created)
	}
	if got := len(mgr.List()); got != 1 {
		t.Fatalf("manager holds %d sessions; want 1", got)
	}
}

func TestGetOrCreateWaiterRetriesAfterCreatorFails(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	mgr := gatedManager(t, release, entered, 1)

	results := make(chan claimResult, 2)
	claim := func() {
		s, created, err := mgr.GetOrCreate(context.Background(), models.CreateSessionRequest{Name: "rlx-retry"})
		results <- claimResult{s, created, err}
	}
	go claim()
	<-entered
	go claim()
	time.Sleep(20 * time.Millisecond) // let the second caller start waiting
	close(release)

	var failed, created int
	for range 2 {
		r := <-results
		switch {
		case r.err != nil:
			failed++
		case r.created:
			created++
		}
	}
	if failed != 1 || created != 1 {
		t.Fatalf("failed=%d created=%d; want the creator to fail and the waiter to take over", failed, created)
	}
}

func TestGetOrCreateWaiterHonorsContext(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	mgr := gatedManager(t, release, entered, 0)
	defer close(release)

	go func() { _, _, _ = mgr.GetOrCreate(context.Background(), models.CreateSessionRequest{Name: "rlx-ctx"}) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := mgr.GetOrCreate(ctx, models.CreateSessionRequest{Name: "rlx-ctx"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter err = %v; want context deadline", err)
	}
}
