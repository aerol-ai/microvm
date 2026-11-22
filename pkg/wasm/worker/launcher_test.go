package worker

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// fakeLauncher is the root helper as the supervisor sees it (split mode).
type fakeLauncher struct {
	mu    sync.Mutex
	calls []string
	procs []*adoptedProc
	err   error
}

func (l *fakeLauncher) Launch(_ context.Context, key, socketPath, cacheDir string) (hostproc.Process, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, key+" "+socketPath+" "+cacheDir)
	if l.err != nil {
		return nil, l.err
	}
	p := newAdoptedProc(100 + len(l.procs))
	l.procs = append(l.procs, p)
	return p, nil
}

func (l *fakeLauncher) launched() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.procs)
}

// TestSupervisorLaunchesThroughTheHelper: with a launcher every worker
// starts through it, with its cache; the worker is ready at once (the
// launcher answers once it serves), outlives sandboxd, is stopped through
// its process, and is started again through the launcher when it dies.
func TestSupervisorLaunchesThroughTheHelper(t *testing.T) {
	s := NewSupervisor(nil)
	l := &fakeLauncher{}
	s.SetLauncher(l)
	if !s.Survives() {
		t.Fatal("a launched worker does not outlive sandboxd")
	}
	ctx := WithCompileCache(context.Background(), "/var/lib/sandboxd/cache/owners/operator")
	if err := s.Ensure(ctx, "sb-1", "/run/aerolvm-rootd/wasm/w-sb-1.sock"); err != nil {
		t.Fatal(err)
	}
	if l.calls[0] != "sb-1 /run/aerolvm-rootd/wasm/w-sb-1.sock /var/lib/sandboxd/cache/owners/operator" {
		t.Fatalf("launch %q", l.calls[0])
	}
	select {
	case <-s.Ready("sb-1"):
	default:
		t.Fatal("a launched worker is not ready")
	}
	// Alive: no second launch.
	if err := s.Ensure(ctx, "sb-1", "/run/aerolvm-rootd/wasm/w-sb-1.sock"); err != nil || l.launched() != 1 {
		t.Fatalf("second Ensure: %v, %d launches", err, l.launched())
	}
	// It dies: launched again, with the same cache.
	l.procs[0].exit()
	deadline := time.Now().Add(2 * time.Second)
	for l.launched() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if l.launched() != 2 || s.SpawnCount("sb-1") != 2 || l.calls[1] != l.calls[0] {
		t.Fatalf("relaunch: %d launches, spawn count %d, %v", l.launched(), s.SpawnCount("sb-1"), l.calls)
	}
	if err := s.Stop("sb-1"); err != nil {
		t.Fatal(err)
	}
	if sigs := l.procs[1].sigs; len(sigs) != 1 || sigs[0] != syscall.SIGKILL {
		t.Fatalf("stop signals %v", sigs)
	}
	// A launch the helper refuses fails the Ensure, and holds nothing.
	l.err = errors.New("refused")
	if err := s.Ensure(context.Background(), "sb-2", "/s"); !errors.Is(err, l.err) {
		t.Fatalf("refused launch: %v", err)
	}
	if s.SpawnCount("sb-2") != 0 {
		t.Fatal("a refused launch holds a slot")
	}
}
