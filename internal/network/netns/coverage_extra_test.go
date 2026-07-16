package netns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/cni"
)

func TestHostHelpersAndCreateDeleteBranches(t *testing.T) {
	t.Run("netns root default and override", func(t *testing.T) {
		if got := (&Host{}).netnsRoot(); got != "/run/netns" {
			t.Fatalf("netnsRoot()=%q", got)
		}
		if got := (&Host{NetnsRoot: "/tmp/netns"}).netnsRoot(); got != "/tmp/netns" {
			t.Fatalf("netnsRoot()=%q", got)
		}
	})

	t.Run("ensureDir with mkdir seam", func(t *testing.T) {
		h := &Host{mkdir: func(string, os.FileMode) error { return errors.New("mkdir boom") }}
		if err := h.ensureDir("/tmp/x"); err == nil {
			t.Fatal("want ensureDir error")
		}
	})

	t.Run("create delete with injected hooks", func(t *testing.T) {
		h := &Host{
			addNetns: func(context.Context, string) error { return nil },
			delNetns: func(context.Context, string) error { return nil },
		}
		if err := h.createNetns(context.Background(), "sb-x"); err != nil {
			t.Fatalf("createNetns hook: %v", err)
		}
		if err := h.deleteNetns(context.Background(), "sb-x"); err != nil {
			t.Fatalf("deleteNetns hook: %v", err)
		}

		h.addNetns = func(context.Context, string) error { return errors.New("add boom") }
		h.delNetns = func(context.Context, string) error { return errors.New("del boom") }
		if err := h.createNetns(context.Background(), "sb-x"); err == nil {
			t.Fatal("want createNetns hook error")
		}
		if err := h.deleteNetns(context.Background(), "sb-x"); err == nil {
			t.Fatal("want deleteNetns hook error")
		}
	})

	t.Run("create delete fallback when ip missing", func(t *testing.T) {
		t.Setenv("PATH", "")
		h := &Host{}
		if err := h.createNetns(context.Background(), "sb-y"); err == nil {
			t.Fatal("want createNetns error when ip binary is unavailable")
		}
		if err := h.deleteNetns(context.Background(), "sb-y"); err == nil {
			t.Fatal("want deleteNetns error when ip binary is unavailable")
		}
	})

	t.Run("create and delete fallback idempotent output", func(t *testing.T) {
		dir := t.TempDir()
		ipPath := filepath.Join(dir, "ip")
		script := "#!/bin/sh\n" +
			"if [ \"$1\" = netns ] && [ \"$2\" = add ]; then\n" +
			"  echo 'File exists'\n" +
			"  exit 1\n" +
			"fi\n" +
			"if [ \"$1\" = netns ] && [ \"$2\" = del ]; then\n" +
			"  echo 'No such file'\n" +
			"  exit 1\n" +
			"fi\n" +
			"exit 0\n"
		if err := os.WriteFile(ipPath, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir)

		h := &Host{}
		if err := h.createNetns(context.Background(), "sb-z"); err != nil {
			t.Fatalf("createNetns should ignore file exists: %v", err)
		}
		if err := h.deleteNetns(context.Background(), "sb-z"); err != nil {
			t.Fatalf("deleteNetns should ignore missing netns output: %v", err)
		}
	})

	t.Run("delete fallback also ignores cannot-remove wording", func(t *testing.T) {
		dir := t.TempDir()
		ipPath := filepath.Join(dir, "ip")
		script := "#!/bin/sh\n" +
			"if [ \"$1\" = netns ] && [ \"$2\" = del ]; then\n" +
			"  echo 'Cannot remove namespace file'\n" +
			"  exit 1\n" +
			"fi\n" +
			"exit 0\n"
		if err := os.WriteFile(ipPath, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir)
		h := &Host{}
		if err := h.deleteNetns(context.Background(), "sb-cannot-remove"); err != nil {
			t.Fatalf("deleteNetns should ignore cannot-remove output: %v", err)
		}
	})
}

func TestHostRemovePathFallbackAndJoinedErrors(t *testing.T) {
	runner := cni.NewFakeRunner()
	runner.SetDelError(errors.New("cni del failed"))
	h := &Host{
		Runner:   runner,
		delNetns: func(context.Context, string) error { return errors.New("delete netns failed") },
	}
	err := h.Remove(context.Background(), Slot{NetnsPath: "/run/netns/sb-path", ContainerIP: "10.88.0.4"})
	if err == nil {
		t.Fatal("want joined delete error")
	}
}

func TestHostRemoveNoNameNoop(t *testing.T) {
	runner := cni.NewFakeRunner()
	h := &Host{Runner: runner}
	if err := h.Remove(context.Background(), Slot{}); err != nil {
		t.Fatalf("remove with empty sandbox and path should be no-op: %v", err)
	}
}

func TestPoolAndRefillNilAndErrorGuards(t *testing.T) {
	t.Run("slotFromStore nil", func(t *testing.T) {
		if got := slotFromStore(nil); got != nil {
			t.Fatalf("slotFromStore(nil)=%+v", got)
		}
	})

	t.Run("pool reassign nil store", func(t *testing.T) {
		if err := (&Pool{}).ReassignOwner(context.Background(), "a", "b", time.Now()); err != nil {
			t.Fatalf("nil-store ReassignOwner err=%v", err)
		}
	})

	t.Run("prewarm requires pool and host", func(t *testing.T) {
		if err := (*Pool)(nil).Prewarm(context.Background(), NewFakeHost(), time.Now()); err == nil {
			t.Fatal("want nil pool prewarm error")
		}
		p := testPool(t, 1)
		if err := p.Prewarm(context.Background(), nil, time.Now()); err == nil {
			t.Fatal("want nil host prewarm error")
		}
	})

	t.Run("claim pooled nil pool", func(t *testing.T) {
		slot, hit, err := (*Pool)(nil).ClaimPooled(context.Background(), "sb-x", time.Now())
		if err != nil || hit || slot != nil {
			t.Fatalf("nil pool claim => slot=%+v hit=%v err=%v", slot, hit, err)
		}
	})

	t.Run("claim pooled propagates store error", func(t *testing.T) {
		st := openTestStore(t)
		p := New(st)
		_ = st.Close()
		if _, _, err := p.ClaimPooled(context.Background(), "sb-x", time.Now()); err == nil {
			t.Fatal("want store error after close")
		}
	})

	t.Run("target depth error", func(t *testing.T) {
		st := openTestStore(t)
		p := New(st)
		_ = st.Close()
		if _, err := p.TargetDepth(context.Background(), 1); err == nil {
			t.Fatal("want TargetDepth error on closed store")
		}
	})

	t.Run("reconcile nil pool", func(t *testing.T) {
		reaped, err := (*Pool)(nil).Reconcile(context.Background(), nil, nil, nil, time.Now())
		if err != nil || reaped != 0 {
			t.Fatalf("nil pool reconcile => reaped=%d err=%v", reaped, err)
		}
	})
}

func TestReconcileDefaultExistsKeepsPooledSlot(t *testing.T) {
	st := openTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := p.Seed(ctx, SeedConfig{PoolSize: 1}, now); err != nil {
		t.Fatal(err)
	}
	slot, err := st.BeginPrewarmContainerNetnsSlot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	existingPath := filepath.Join(root, "kept.netns")
	if err := os.WriteFile(existingPath, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishPrewarmContainerNetnsSlot(ctx, slot.SlotID, existingPath, "10.88.0.8", now); err != nil {
		t.Fatal(err)
	}

	reaped, err := p.Reconcile(ctx, NewFakeHost(), nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 0 {
		t.Fatalf("reaped=%d, want 0", reaped)
	}
}

func TestRefillerDefaultsAndStopViaChannel(t *testing.T) {
	r := NewRefiller(nil, nil, 0, 0)
	if r.depth != 4 {
		t.Fatalf("depth=%d, want 4", r.depth)
	}
	if r.interval != 2*time.Second {
		t.Fatalf("interval=%s, want 2s", r.interval)
	}
	(*Refiller)(nil).Stop()

	p := testPool(t, 1)
	host := NewFakeHost()
	r = NewRefiller(p, host, 1, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	time.Sleep(15 * time.Millisecond)
	r.Stop()

	stats, err := p.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pooled == 0 {
		t.Fatalf("expected pooled slots after run/stop: %+v", stats)
	}
}

func TestRuntimeHandoffProvisionNilBuilderAndReleaseGetError(t *testing.T) {
	var h RuntimeHandoff
	path, ip, err := h.Provision(context.Background(), "sb-x")
	if err != nil || path != "" || ip != "" {
		t.Fatalf("nil builder provision => path=%q ip=%q err=%v", path, ip, err)
	}

	p := testPool(t, 1)
	h2 := NewRuntimeHandoff(p, NewFakeHost())
	_ = p.st.Close()
	if err := h2.Release(context.Background(), "sb-x"); err == nil {
		t.Fatal("want Release get error when store is closed")
	}
}

func TestFakeHostSetRemoveError(t *testing.T) {
	f := NewFakeHost()
	f.SetRemoveError(errors.New("remove boom"))
	if err := f.Remove(context.Background(), Slot{SandboxID: "sb-x"}); err == nil {
		t.Fatal("want fake host remove error")
	}
}

func TestReconcileSkipsUnknownState(t *testing.T) {
	reaped, err := (*Pool)(nil).Reconcile(context.Background(), NewFakeHost(), nil, func(string) bool { return false }, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 0 {
		t.Fatalf("reaped=%d, want 0", reaped)
	}
}

func TestReconcileStoreListError(t *testing.T) {
	st := openTestStore(t)
	p := New(st)
	_ = st.Close()
	if _, err := p.Reconcile(context.Background(), nil, nil, nil, time.Now()); err == nil {
		t.Fatal("want reconcile list error on closed store")
	}
}

func TestRefillOnceNoopOnNilOrError(t *testing.T) {
	var r Refiller
	r.refillOnce(context.Background())

	p := testPool(t, 1)
	r = *NewRefiller(p, NewFakeHost(), 1, time.Second)
	_ = p.st.Close()
	r.refillOnce(context.Background())
}

func TestTargetDepthClampsToZero(t *testing.T) {
	p := testPool(t, 1)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := p.Prewarm(ctx, NewFakeHost(), now); err != nil {
		t.Fatal(err)
	}
	need, err := p.TargetDepth(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if need != 0 {
		t.Fatalf("need=%d, want 0", need)
	}
}

type realizeSpyHost struct {
	removeCalls int
}

func (h *realizeSpyHost) Realize(context.Context, Slot) (string, string, error) {
	return "", "", nil
}

func (h *realizeSpyHost) Remove(context.Context, Slot) error {
	h.removeCalls++
	return nil
}

func TestPrewarmFinishFailureResetsAndRemoves(t *testing.T) {
	p := testPool(t, 1)
	host := &realizeSpyHost{}
	ctx := context.Background()
	now := time.Now().UTC()

	if err := p.Prewarm(ctx, host, now); err == nil {
		t.Fatal("want finish-prewarm validation error from empty path/ip")
	}
	if host.removeCalls == 0 {
		t.Fatal("expected host.Remove on finish-prewarm failure")
	}
	stats, err := p.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Free != 1 {
		t.Fatalf("slot should be reset to free, stats=%+v", stats)
	}
}

func TestBuilderRequiresPoolAndHost(t *testing.T) {
	if _, err := (*Builder)(nil).Build(context.Background(), "sb"); err == nil {
		t.Fatal("want nil builder error")
	}
	b := &Builder{}
	if _, err := b.Build(context.Background(), "sb"); err == nil {
		t.Fatal("want missing pool/host error")
	}
}

func TestPoolWrapperErrorPaths(t *testing.T) {
	p := testPool(t, 1)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := p.MarkRealized(ctx, "missing", "/run/netns/missing", "10.0.0.2", now); err == nil {
		t.Fatal("want MarkRealized error for missing sandbox")
	}
	if _, err := p.Adopt(ctx, "missing", now); err == nil {
		t.Fatal("want Adopt error for missing sandbox")
	}

	if _, err := p.Reserve(ctx, "sb-reserved", now); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Adopt(ctx, "sb-reserved", now); err == nil {
		t.Fatal("want Adopt error when slot is not realized")
	}
}

func TestReconcileReapsRefillCrashOwner(t *testing.T) {
	st := openTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := p.Seed(ctx, SeedConfig{PoolSize: 1}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.BeginPrewarmContainerNetnsSlot(ctx, now); err != nil {
		t.Fatal(err)
	}

	reaped, err := p.Reconcile(ctx, NewFakeHost(), nil, func(string) bool { return false }, now)
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 1 {
		t.Fatalf("reaped=%d, want 1", reaped)
	}
}

func TestReconcileReservedLiveOwnerNotReaped(t *testing.T) {
	p := testPool(t, 1)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := p.Reserve(ctx, "sb-live-reserved", now); err != nil {
		t.Fatal(err)
	}
	reaped, err := p.Reconcile(ctx, NewFakeHost(), func(context.Context, string) bool { return true }, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 0 {
		t.Fatalf("reaped=%d, want 0", reaped)
	}
}

func TestClaimPooledNoPooledSentinel(t *testing.T) {
	st := openTestStore(t)
	p := New(st)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := p.Seed(ctx, SeedConfig{PoolSize: 1}, now); err != nil {
		t.Fatal(err)
	}
	// No pooled row yet, store returns ErrNoPooledContainerNetnsSlot and wrapper maps to miss.
	slot, hit, err := p.ClaimPooled(ctx, "sb-x", now)
	if err != nil || hit || slot != nil {
		t.Fatalf("slot=%+v hit=%v err=%v", slot, hit, err)
	}
}

func TestRefillerRunExitsOnContextDone(t *testing.T) {
	r := NewRefiller(testPool(t, 1), NewFakeHost(), 1, 5*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)
	time.Sleep(10 * time.Millisecond)
	cancel()
	r.Stop()
}

type builderHost struct {
	realizePath string
	realizeIP   string
	realizeErr  error
	removeCalls int
}

func (h *builderHost) Realize(context.Context, Slot) (string, string, error) {
	if h.realizeErr != nil {
		return "", "", h.realizeErr
	}
	return h.realizePath, h.realizeIP, nil
}

func (h *builderHost) Remove(context.Context, Slot) error {
	h.removeCalls++
	return nil
}

func TestHostRealizeErrorPaths(t *testing.T) {
	runner := cni.NewFakeRunner()
	h := &Host{
		Runner: runner,
		mkdir:  func(string, os.FileMode) error { return errors.New("mkdir denied") },
	}
	if _, _, err := h.Realize(context.Background(), Slot{SandboxID: "sb-mkdir"}); err == nil {
		t.Fatal("want realize failure when netns root cannot be created")
	}

	h = &Host{
		Runner:    runner,
		NetnsRoot: t.TempDir(),
		addNetns:  func(context.Context, string) error { return errors.New("netns add failed") },
	}
	if _, _, err := h.Realize(context.Background(), Slot{SandboxID: "sb-add"}); err == nil {
		t.Fatal("want realize failure when createNetns fails")
	}

	if _, _, err := (&Host{Runner: runner}).Realize(context.Background(), Slot{}); err == nil {
		t.Fatal("want sandbox_id validation error")
	}
}

func TestRefillOnceNeedZeroAndPrewarmError(t *testing.T) {
	p := testPool(t, 1)
	ctx := context.Background()
	if err := p.Prewarm(ctx, NewFakeHost(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	r := NewRefiller(p, NewFakeHost(), 1, time.Second)
	r.refillOnce(ctx)

	host := NewFakeHost()
	host.SetRealizeError(errors.New("boom"))
	r = NewRefiller(testPool(t, 2), host, 2, time.Second)
	r.refillOnce(ctx)
}

func TestRuntimeHandoffProvisionClaimError(t *testing.T) {
	p := testPool(t, 1)
	h := NewRuntimeHandoff(p, NewFakeHost())
	_ = p.st.Close()
	if _, _, err := h.Provision(context.Background(), "sb-claim-err"); err == nil {
		t.Fatal("want provision error when claim pooled fails")
	}
}

func TestReconcileReapsReservedWhenHostNil(t *testing.T) {
	p := testPool(t, 1)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := p.Reserve(ctx, "sb-dead", now); err != nil {
		t.Fatal(err)
	}
	reaped, err := p.Reconcile(ctx, nil, func(context.Context, string) bool { return false }, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 1 {
		t.Fatalf("reaped=%d, want 1", reaped)
	}
}

func TestRefillerStopIdempotent(t *testing.T) {
	r := NewRefiller(testPool(t, 1), NewFakeHost(), 1, 5*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)
	time.Sleep(8 * time.Millisecond)
	r.Stop()
	cancel()
}

func TestBuilderRealizeErrorBubbles(t *testing.T) {
	p := testPool(t, 1)
	host := &builderHost{realizeErr: errors.New("realize failed")}
	b := NewBuilder(p, host)
	if _, err := b.Build(context.Background(), "sb-realize-err"); err == nil {
		t.Fatal("want build error when host realize fails")
	}
}
