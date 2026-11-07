package service

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Regression tests for the resize half of team quotas (review of PR #959,
// findings 4 and 6): one resize of a sandbox at a time, a quota hold at the
// larger size for the whole resize, a downsize that frees its room, and the
// rule for a runtime that changed when the store write did not.

// review923ResizeRuntime pauses the resize to 3 CPU inside the runtime until
// the test lets it finish.
type review923ResizeRuntime struct {
	*recordingRuntime
	firstEntered chan struct{}
	finishFirst  chan struct{}
}

func (r *review923ResizeRuntime) Resize(ctx context.Context, id string, req models.ResizeSandboxRequest) error {
	if req.CPU == 3 {
		close(r.firstEntered)
		<-r.finishFirst
	}
	return nil
}

// A 4-CPU team with two 1-CPU sandboxes: a resize of A to 3 pauses in the
// runtime, a second resize of A to 2 arrives, and a 1-CPU create asks for
// room. Before, the second resize replaced the first's claim (A=2), the
// create fit (2+1+1=4), and the first then left A at 3: 5 CPUs. Now the
// second resize waits for the first, and the first holds A at 3 until it
// settles, so the create is refused.
func TestReview923ConcurrentResizeMustNotBypassQuota(t *testing.T) {
	ctx := context.Background()
	rt := &review923ResizeRuntime{recordingRuntime: &recordingRuntime{}, firstEntered: make(chan struct{}), finishFirst: make(chan struct{})}
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	for _, id := range []string{"sb-a", "sb-b"} {
		seedStartedSandbox(t, st, id)
		sb, _ := st.Get(ctx, id)
		sb.OwnerRef, sb.CPU, sb.MemoryMB = "team:risk", 1, 512
		if err := st.Upsert(ctx, sb); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxCPU: 4}); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { _, err := svc.ResizeSandbox(ctx, "sb-a", models.ResizeSandboxRequest{CPU: 3}); first <- err }()
	<-rt.firstEntered
	// The second resize of the same sandbox waits for the first; it used to
	// run straight through, which is the race.
	second := make(chan error, 1)
	go func() { _, err := svc.ResizeSandbox(ctx, "sb-a", models.ResizeSandboxRequest{CPU: 2}); second <- err }()
	if !waitFor(5*time.Second, func() bool { return svc.resizeLocks.refs("sb-a") == 2 }) {
		t.Fatal("the second resize never queued behind the first")
	}
	ticket, createErr := svc.admitTeamQuotaCreate(ctx, "team:risk", models.CreateSandboxRequest{CPU: 1})
	close(rt.finishFirst)
	firstErr := <-first
	secondErr := <-second
	if firstErr != nil || secondErr != nil {
		t.Fatalf("resize errors: %v / %v", firstErr, secondErr)
	}
	if createErr == nil {
		defer ticket.settle(nil, errors.New("test cleanup"))
		sb, _ := st.Get(ctx, "sb-a")
		if sb.CPU+1+1 > 4 {
			t.Fatalf("quota bypass: resized A=%g + B=1 + admitted create=1 exceeds quota 4", sb.CPU)
		}
	}
	if !errors.Is(createErr, models.ErrTeamQuotaExceeded) {
		t.Fatalf("create while A was held at 3 = %v, want a quota refusal", createErr)
	}
	sb, _ := st.Get(ctx, "sb-a")
	q, err := svc.GetTeamQuota(ctx, "risk")
	if err != nil || sb.CPU != 2 || q.Usage.CPU != 3 {
		t.Fatalf("after both resizes: A=%g usage=%+v err=%v, want A=2 and usage 3 (the later resize wins, in order)", sb.CPU, q.Usage, err)
	}
	if n := svc.resizeLocks.refs("sb-a"); n != 0 {
		t.Fatalf("resize lock left %d holders", n)
	}
}

// A downsize is recorded: a sandbox cut from 2 CPU to 1 counts 1.
func TestReview923QuotaUsageMustFollowDownsize(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), resizeOKRuntime{&recordingRuntime{}})
	seedStartedSandbox(t, st, "sb-shrink")
	sb, _ := st.Get(ctx, "sb-shrink")
	sb.OwnerRef = "team:risk"
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxCPU: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ResizeSandbox(ctx, sb.ID, models.ResizeSandboxRequest{CPU: 1}); err != nil {
		t.Fatal(err)
	}
	q, err := svc.GetTeamQuota(ctx, "risk")
	if err != nil {
		t.Fatal(err)
	}
	if q.Usage.CPU != 1 {
		t.Fatalf("downsize to 1 CPU still charges %g CPU", q.Usage.CPU)
	}
}

// scriptedResizeRuntime records every Resize and fails the calls listed in
// fail (1-based).
type scriptedResizeRuntime struct {
	*recordingRuntime
	mu    sync.Mutex
	calls []models.ResizeSandboxRequest
	fail  map[int]error
}

func (r *scriptedResizeRuntime) Resize(_ context.Context, _ string, req models.ResizeSandboxRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, req)
	return r.fail[len(r.calls)]
}

func (r *scriptedResizeRuntime) resizes() []models.ResizeSandboxRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]models.ResizeSandboxRequest(nil), r.calls...)
}

// The runtime changed and the store write failed. The quota is given back
// only once the runtime is back at the old size; if that fails too, the
// larger size stays charged, and a recount from the store (which still shows
// the old size) does not drop it.
func TestResizeStoreFailureChargesTheSizeTheSandboxMayHold(t *testing.T) {
	cases := []struct {
		name       string
		rowCPU     float64
		revertErr  error
		wantCalls  int
		wantUsage  float64
		wantCreate bool
	}{
		{name: "runtime put back: hold undone", rowCPU: 1, wantCalls: 2, wantUsage: 1, wantCreate: true},
		{name: "runtime not put back: larger size kept", rowCPU: 1, revertErr: errors.New("revert refused"), wantCalls: 2, wantUsage: 3},
		{name: "old size unknown: larger size kept", rowCPU: 0, wantCalls: 1, wantUsage: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "state.db")
			rt := &scriptedResizeRuntime{recordingRuntime: &recordingRuntime{}, fail: map[int]error{2: tc.revertErr}}
			svc, st, _ := newServiceRuntimeHarnessAtPath(t, path, rt)
			seedStartedSandbox(t, st, "sb-drift")
			sb, _ := st.Get(ctx, "sb-drift")
			sb.OwnerRef, sb.CPU, sb.MemoryMB = "team:risk", tc.rowCPU, 512
			if err := st.Upsert(ctx, sb); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxCPU: 4}); err != nil {
				t.Fatal(err)
			}
			cb96SQL(t, path, `CREATE TRIGGER drift_freeze BEFORE UPDATE ON sandboxes BEGIN SELECT RAISE(ABORT, 'frozen'); END`)
			if _, err := svc.ResizeSandbox(ctx, "sb-drift", models.ResizeSandboxRequest{CPU: 3}); err == nil {
				t.Fatal("resize ignored a failed row write")
			}
			calls := rt.resizes()
			if len(calls) != tc.wantCalls || calls[0].CPU != 3 {
				t.Fatalf("runtime resizes = %+v, want %d starting with CPU 3", calls, tc.wantCalls)
			}
			if tc.wantCalls == 2 && (calls[1].CPU != tc.rowCPU || calls[1].MemoryMB != 0) {
				t.Fatalf("revert = %+v, want CPU %g and nothing else", calls[1], tc.rowCPU)
			}
			_, usage, _, _ := svc.teamQuotas.status(ctx, st, "risk")
			if usage.CPU != tc.wantUsage {
				t.Fatalf("usage = %+v, want CPU %g", usage, tc.wantUsage)
			}
			// A 2-CPU create fits only if the hold was undone. Its refusal
			// recounts from the store first, which must keep the hold.
			tk, err := svc.admitTeamQuotaCreate(ctx, "team:risk", models.CreateSandboxRequest{CPU: 2})
			if tc.wantCreate != (err == nil) {
				t.Fatalf("2-CPU create = %v, want admitted %v", err, tc.wantCreate)
			}
			tk.settle(nil, errors.New("cleanup"))
			if _, usage, _, _ = svc.teamQuotas.status(ctx, st, "risk"); usage.CPU != tc.wantUsage {
				t.Fatalf("usage after a recount = %+v, want CPU %g", usage, tc.wantUsage)
			}
		})
	}
}

// Only the resize that wrote a ledger entry may settle or undo it: a destroy
// that released the sandbox, or a later resize, is never overwritten.
func TestTeamResizeHoldIsFencedByGeneration(t *testing.T) {
	svc, st := quotaTestService(t)
	ctx := context.Background()
	if _, err := svc.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxCPU: 8}); err != nil {
		t.Fatal(err)
	}
	tk, _ := svc.admitTeamQuotaCreate(ctx, "team:risk", models.CreateSandboxRequest{CPU: 1})
	tk.settle(&models.CreateSandboxResponse{Sandbox: models.Sandbox{ID: "sb-1"}}, nil)

	// A destroy during the resize: the late settle must not bring it back.
	hold, err := svc.teamQuotas.beginResize(ctx, st, "risk", "sb-1", 4, models.DefaultMemoryMB)
	if err != nil {
		t.Fatal(err)
	}
	svc.releaseTeamQuota(&models.Sandbox{ID: "sb-1", OwnerRef: "team:risk"})
	hold.settle(4, models.DefaultMemoryMB)
	hold.undo()
	if _, usage, _, _ := svc.teamQuotas.status(ctx, st, "risk"); usage.Sandboxes != 0 || usage.CPU != 0 {
		t.Fatalf("a destroyed sandbox came back: %+v", usage)
	}

	// An older hold cannot undo a newer one.
	tk, _ = svc.admitTeamQuotaCreate(ctx, "team:risk", models.CreateSandboxRequest{CPU: 1})
	tk.settle(&models.CreateSandboxResponse{Sandbox: models.Sandbox{ID: "sb-2"}}, nil)
	older, _ := svc.teamQuotas.beginResize(ctx, st, "risk", "sb-2", 2, models.DefaultMemoryMB)
	newer, _ := svc.teamQuotas.beginResize(ctx, st, "risk", "sb-2", 6, models.DefaultMemoryMB)
	older.undo()
	if _, usage, _, _ := svc.teamQuotas.status(ctx, st, "risk"); usage.CPU != 6 {
		t.Fatalf("an older undo overwrote a newer hold: %+v", usage)
	}
	newer.settle(5, models.DefaultMemoryMB)
	if _, usage, _, _ := svc.teamQuotas.status(ctx, st, "risk"); usage.CPU != 5 {
		t.Fatalf("settle = %+v, want CPU 5", usage)
	}
	// A shrink of a team over a lowered quota passes, and frees room once settled.
	if _, err := svc.PutTeamQuota(ctx, "risk", models.TeamQuotaRequest{MaxCPU: 1}); err != nil {
		t.Fatal(err)
	}
	shrink, err := svc.teamQuotas.beginResize(ctx, st, "risk", "sb-2", 1, models.DefaultMemoryMB)
	if err != nil {
		t.Fatalf("shrink over a lowered quota = %v", err)
	}
	if _, usage, _, _ := svc.teamQuotas.status(ctx, st, "risk"); usage.CPU != 5 {
		t.Fatalf("a shrink freed room before it happened: %+v", usage)
	}
	shrink.settle(1, models.DefaultMemoryMB)
	if _, usage, _, _ := svc.teamQuotas.status(ctx, st, "risk"); usage.CPU != 1 {
		t.Fatalf("settled shrink = %+v, want CPU 1", usage)
	}
}

// clusterResizeHarness is a cluster-mode service with a real store and the
// quota stub as its cluster.
func clusterResizeHarness(t *testing.T, rt *scriptedResizeRuntime, stub *quotaStubCluster) (*Service, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, path, rt)
	svc.cfg.EnableCluster = true
	stub.Noop = cluster.NewNoop("node-a", "", "")
	svc.AttachCluster(stub)
	seedStartedSandbox(t, st, "sb-c")
	sb, _ := st.Get(context.Background(), "sb-c")
	sb.OwnerRef, sb.CPU, sb.MemoryMB = "team:risk", 1, 512
	if err := st.Upsert(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	return svc, path
}

// A cluster records the larger size in the replicated spec before the
// runtime grows, records a shrink only after it happened, and puts the old
// size back after a failure only while the spec still holds what it wrote.
func TestTeamQuotaClusterResizeProtocol(t *testing.T) {
	ctx := context.Background()
	t.Run("growth is written first and not again", func(t *testing.T) {
		stub := &quotaStubCluster{spec: &models.CreateSandboxRequest{Image: "a", CPU: 1, MemoryMB: 512}}
		svc, _ := clusterResizeHarness(t, &scriptedResizeRuntime{recordingRuntime: &recordingRuntime{}}, stub)
		if _, err := svc.ResizeSandbox(ctx, "sb-c", models.ResizeSandboxRequest{CPU: 3}); err != nil {
			t.Fatal(err)
		}
		if len(stub.upserts) != 1 || stub.upserts[0].CPU != 3 {
			t.Fatalf("spec writes = %+v, want one admitted write of CPU 3", stub.upserts)
		}
	})
	t.Run("mixed resize holds the larger memory until it succeeds", func(t *testing.T) {
		stub := &quotaStubCluster{spec: &models.CreateSandboxRequest{Image: "a", CPU: 1, MemoryMB: 512}}
		svc, _ := clusterResizeHarness(t, &scriptedResizeRuntime{recordingRuntime: &recordingRuntime{}}, stub)
		if _, err := svc.ResizeSandbox(ctx, "sb-c", models.ResizeSandboxRequest{CPU: 2, MemoryMB: 256}); err != nil {
			t.Fatal(err)
		}
		if len(stub.upserts) != 2 || stub.upserts[0].CPU != 2 || stub.upserts[0].MemoryMB != 512 || stub.upserts[1].MemoryMB != 256 {
			t.Fatalf("spec writes = %+v, want CPU 2 at memory 512 first, then memory 256", stub.upserts)
		}
	})
	t.Run("shrink is written after it happened", func(t *testing.T) {
		stub := &quotaStubCluster{spec: &models.CreateSandboxRequest{Image: "a", CPU: 1, MemoryMB: 512}}
		svc, _ := clusterResizeHarness(t, &scriptedResizeRuntime{recordingRuntime: &recordingRuntime{}}, stub)
		if _, err := svc.ResizeSandbox(ctx, "sb-c", models.ResizeSandboxRequest{CPU: 0.5}); err != nil {
			t.Fatal(err)
		}
		if len(stub.upserts) != 1 || stub.upserts[0].CPU != 0.5 {
			t.Fatalf("spec writes = %+v, want one write-through of CPU 0.5", stub.upserts)
		}
	})
	t.Run("runtime failure writes the old size back", func(t *testing.T) {
		stub := &quotaStubCluster{spec: &models.CreateSandboxRequest{Image: "a", CPU: 1, MemoryMB: 512}}
		rt := &scriptedResizeRuntime{recordingRuntime: &recordingRuntime{}, fail: map[int]error{1: errors.New("no room")}}
		svc, _ := clusterResizeHarness(t, rt, stub)
		if _, err := svc.ResizeSandbox(ctx, "sb-c", models.ResizeSandboxRequest{CPU: 3}); err == nil {
			t.Fatal("a failed runtime resize succeeded")
		}
		if len(stub.upserts) != 2 || stub.upserts[1].CPU != 1 {
			t.Fatalf("spec writes = %+v, want the old CPU 1 written back", stub.upserts)
		}
	})
	t.Run("store failure with the runtime put back writes the old size back", func(t *testing.T) {
		stub := &quotaStubCluster{spec: &models.CreateSandboxRequest{Image: "a", CPU: 1, MemoryMB: 512}}
		rt := &scriptedResizeRuntime{recordingRuntime: &recordingRuntime{}}
		svc, path := clusterResizeHarness(t, rt, stub)
		cb96SQL(t, path, `CREATE TRIGGER c_freeze BEFORE UPDATE ON sandboxes BEGIN SELECT RAISE(ABORT, 'frozen'); END`)
		if _, err := svc.ResizeSandbox(ctx, "sb-c", models.ResizeSandboxRequest{CPU: 3}); err == nil {
			t.Fatal("resize ignored a failed row write")
		}
		if len(rt.resizes()) != 2 || len(stub.upserts) != 2 || stub.spec.CPU != 1 {
			t.Fatalf("runtime %+v spec writes %+v, want the runtime and the spec back at CPU 1", rt.resizes(), stub.upserts)
		}
	})
	t.Run("store failure with the runtime stuck keeps the larger size", func(t *testing.T) {
		stub := &quotaStubCluster{spec: &models.CreateSandboxRequest{Image: "a", CPU: 1, MemoryMB: 512}}
		rt := &scriptedResizeRuntime{recordingRuntime: &recordingRuntime{}, fail: map[int]error{2: errors.New("stuck")}}
		svc, path := clusterResizeHarness(t, rt, stub)
		cb96SQL(t, path, `CREATE TRIGGER c_freeze BEFORE UPDATE ON sandboxes BEGIN SELECT RAISE(ABORT, 'frozen'); END`)
		if _, err := svc.ResizeSandbox(ctx, "sb-c", models.ResizeSandboxRequest{CPU: 3}); err == nil {
			t.Fatal("resize ignored a failed row write")
		}
		if len(stub.upserts) != 1 || stub.spec.CPU != 3 {
			t.Fatalf("spec writes = %+v, want the admitted CPU 3 kept", stub.upserts)
		}
	})
	t.Run("growth is judged against the spec the leader counts", func(t *testing.T) {
		// The row says 4 CPU but the spec (what the leader counts) says 1:
		// going to 3 shrinks the row and grows the count, so it is admitted
		// first. A memory-only resize leaves the spec's CPU alone.
		stub := &quotaStubCluster{spec: &models.CreateSandboxRequest{Image: "a", CPU: 1, MemoryMB: 512}}
		svc, _ := clusterResizeHarness(t, &scriptedResizeRuntime{recordingRuntime: &recordingRuntime{}}, stub)
		big := &models.Sandbox{ID: "sb-c", OwnerRef: "team:risk", CPU: 4, MemoryMB: 512}
		hold, err := svc.admitTeamQuotaResize(ctx, big, models.ResizeSandboxRequest{CPU: 3})
		if err != nil || hold == nil || len(stub.upserts) != 1 || stub.upserts[0].CPU != 3 {
			t.Fatalf("admit = %v %v %+v, want CPU 3 admitted first", hold, err, stub.upserts)
		}
		hold, err = svc.admitTeamQuotaResize(ctx, big, models.ResizeSandboxRequest{MemoryMB: 1024})
		if err != nil || hold == nil || len(stub.upserts) != 2 || stub.upserts[1].CPU != 3 || stub.upserts[1].MemoryMB != 1024 {
			t.Fatalf("memory-only admit = %v %v %+v", hold, err, stub.upserts)
		}
		if h, err := svc.admitTeamQuotaResize(ctx, big, models.ResizeSandboxRequest{DiskGB: 50}); h != nil || err != nil {
			t.Fatalf("a disk-only resize takes no quota hold: %v %v", h, err)
		}
	})
	t.Run("undo leaves a size someone else wrote since", func(t *testing.T) {
		stub := &quotaStubCluster{spec: &models.CreateSandboxRequest{Image: "a", CPU: 1, MemoryMB: 512}}
		svc, _ := clusterResizeHarness(t, &scriptedResizeRuntime{recordingRuntime: &recordingRuntime{}}, stub)
		hold, err := svc.admitTeamQuotaResize(ctx, &models.Sandbox{ID: "sb-c", OwnerRef: "team:risk", CPU: 1, MemoryMB: 512}, models.ResizeSandboxRequest{CPU: 3, MemoryMB: 512})
		if err != nil || hold == nil {
			t.Fatalf("admit = %v %v", hold, err)
		}
		stub.spec.CPU = 5 // a replay recorded another size
		hold.undo()
		if len(stub.upserts) != 1 || stub.spec.CPU != 5 {
			t.Fatalf("undo overwrote a newer size: %+v", stub.upserts)
		}
		stub.spec.CPU = 3
		stub.upsertErr = errors.New("leader gone")
		hold.undo() // logs; the larger size stays counted
		if stub.spec.CPU != 3 {
			t.Fatalf("a failed undo changed the spec: %+v", stub.spec)
		}
	})
}

// A growing resize whose size the cluster does not hold is refused when the
// team has a quota, or when the quota cannot be read: not knowing is not
// being under. Before, it passed unchecked.
func TestTeamQuotaClusterGrowthWithoutSpecFailsClosed(t *testing.T) {
	ctx := context.Background()
	sb := &models.Sandbox{ID: "sb-1", OwnerRef: "team:risk", CPU: 1, MemoryMB: 512}
	stub := &quotaStubCluster{read: cluster.TeamQuotaReadResponse{Found: true, Quota: cluster.TeamQuotaRecord{Team: "risk", MaxCPU: 64}}}
	svc := clusterQuotaService(t, stub)
	if _, err := svc.admitTeamQuotaResize(ctx, sb, models.ResizeSandboxRequest{CPU: 2, MemoryMB: 512}); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("growth with no spec and a quota = %v, want ErrTeamQuotaUnavailable", err)
	}
	stub.readErr = errors.New("leader gone")
	if _, err := svc.admitTeamQuotaResize(ctx, sb, models.ResizeSandboxRequest{CPU: 2, MemoryMB: 512}); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("growth with no spec and no quota read = %v, want ErrTeamQuotaUnavailable", err)
	}
	plain := New(svc.cfg, svc.logger, nil, nil, nil, nil, nil, nil, nil)
	plain.AttachCluster(cluster.NewNoop("n", "", ""))
	if _, err := plain.admitTeamQuotaResize(ctx, sb, models.ResizeSandboxRequest{CPU: 2, MemoryMB: 512}); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("growth with no quota store = %v, want ErrTeamQuotaUnavailable", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := svc.admitTeamQuotaResize(cancelled, sb, models.ResizeSandboxRequest{CPU: 2, MemoryMB: 512}); !errors.Is(err, ErrTeamQuotaUnavailable) {
		t.Fatalf("growth whose spec lock was abandoned = %v", err)
	}
}

// A spec write-through waits for the sandbox's spec lock, and one whose
// caller left first writes nothing.
func TestSpecWriteThroughsShareOneLockPerSandbox(t *testing.T) {
	stub := &quotaStubCluster{spec: &models.CreateSandboxRequest{Image: "a", CPU: 1}}
	svc := clusterQuotaService(t, stub)
	unlock, err := svc.specLocks.lockCtx(context.Background(), "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	svc.replicateSpecPatch(ctx, "sb-1", func(spec *models.CreateSandboxRequest) { spec.CPU = 9 })
	if err := svc.commitPolicySpec(ctx, "sb-1", &models.CreateSandboxRequest{}, nil); !errors.Is(err, ErrEgressSpecCommitFailed) {
		t.Fatalf("policy commit while the spec is locked = %v", err)
	}
	if len(stub.upserts) != 0 {
		t.Fatalf("a write-through ran without the lock: %+v", stub.upserts)
	}
	unlock()
	svc.replicateSpecPatch(context.Background(), "sb-1", func(spec *models.CreateSandboxRequest) { spec.CPU = 9 })
	if len(stub.upserts) != 1 || stub.upserts[0].CPU != 9 {
		t.Fatalf("write-through after the lock freed = %+v", stub.upserts)
	}
	svc.logger = nil
	svc.replicateSpecPatch(ctx, "sb-1", func(*models.CreateSandboxRequest) {})
	if len(stub.upserts) != 1 {
		t.Fatalf("a write-through whose caller left wrote anyway: %+v", stub.upserts)
	}
}
