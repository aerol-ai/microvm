package netns

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/cni"
)

func TestBringLoopbackUpExecFallbackCoverage95(t *testing.T) {
	dir := t.TempDir()
	ipPath := filepath.Join(dir, "ip")
	// Simulate `ip -n <name> link set lo up` success and failure so the
	// production exec path (loopbackUp == nil) is covered offline.
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = -n ] && [ \"$3\" = link ] && [ \"$4\" = set ] && [ \"$5\" = lo ]; then\n" +
		"  if [ \"$2\" = fail-lo ]; then\n" +
		"    echo 'RTNETLINK answers: Operation not permitted'\n" +
		"    exit 1\n" +
		"  fi\n" +
		"  exit 0\n" +
		"fi\n" +
		"exit 0\n"
	if err := os.WriteFile(ipPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	h := &Host{}
	if err := h.bringLoopbackUp(context.Background(), "ok-lo"); err != nil {
		t.Fatalf("bringLoopbackUp success: %v", err)
	}
	if err := h.bringLoopbackUp(context.Background(), "fail-lo"); err == nil {
		t.Fatal("want bringLoopbackUp error")
	}
}

func TestDeleteNetnsExecSuccessCoverage95(t *testing.T) {
	dir := t.TempDir()
	ipPath := filepath.Join(dir, "ip")
	if err := os.WriteFile(ipPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	h := &Host{}
	if err := h.deleteNetns(context.Background(), "sb-ok"); err != nil {
		t.Fatalf("deleteNetns success path: %v", err)
	}
}

func TestHostRemoveEmptyPathUsesRoot(t *testing.T) {
	removed := ""
	h := &Host{
		Runner:    cni.NewFakeRunner(),
		NetnsRoot: "/tmp/netns-root",
		delNetns: func(_ context.Context, name string) error {
			removed = name
			return nil
		},
	}
	if err := h.Remove(context.Background(), Slot{SandboxID: "sb-empty-path"}); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if removed != "sb-empty-path" {
		t.Fatalf("removed = %q", removed)
	}
}

func TestBuilderBuildPoolExhaustion(t *testing.T) {
	p := testPool(t, 1)
	host := NewFakeHost()
	b := NewBuilder(p, host)
	if _, err := b.Build(context.Background(), "sb-1"); err != nil {
		t.Fatalf("build1: %v", err)
	}
	if _, err := b.Build(context.Background(), "sb-2"); err == nil {
		t.Fatal("want pool exhaustion error")
	}
}

func TestPoolSeedRejectsZeroSizeCoverage95(t *testing.T) {
	st := openTestStore(t)
	p := New(st)
	err := p.Seed(context.Background(), SeedConfig{PoolSize: 0}, time.Unix(1, 0).UTC())
	if err == nil {
		t.Fatal("want seed size error")
	}
}

func TestRefillerRunDefaultIntervalCoverage95(t *testing.T) {
	// depth 0 → refillOnce no-ops after the interval<=0 default is applied.
	r := NewRefiller(testPool(t, 1), NewFakeHost(), 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refiller did not stop")
	}
}
