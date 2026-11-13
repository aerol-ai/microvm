package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// laggingSpecCluster is a cluster.VersionedSpecClient whose reads lag its
// writes the way a worker's do when they reach a follower: after each write
// the next lag reads return the copy from before it. Writes check the
// version the way the leader does.
type laggingSpecCluster struct {
	*cluster.Noop

	mu                   sync.Mutex
	spec, prev           *models.CreateSandboxRequest
	version, prevVersion uint64
	lag, staleLeft       int
	// unchecked writes whatever version a write carries, like a cluster
	// where some server predates the check (UpsertSpecIfVersion drops it).
	unchecked bool
	// interleave runs once, just before the next write is checked: another
	// node's write landing between this node's read and its write.
	interleave func(*models.CreateSandboxRequest)
	// moved makes every write find the spec moved on.
	moved bool

	reads, writes, conflicts int
}

func newLaggingSpecCluster(spec *models.CreateSandboxRequest, lag int) *laggingSpecCluster {
	return &laggingSpecCluster{Noop: cluster.NewNoop("node-a", "", ""), spec: spec, prev: spec, version: 10, prevVersion: 10, lag: lag}
}

func cloneSpecForTest(in *models.CreateSandboxRequest) *models.CreateSandboxRequest {
	if in == nil {
		return nil
	}
	raw, err := json.Marshal(in)
	if err != nil {
		panic(err)
	}
	var out models.CreateSandboxRequest
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return &out
}

func (l *laggingSpecCluster) SpecAndVersionOf(string) (*models.CreateSandboxRequest, uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reads++
	if l.staleLeft > 0 {
		l.staleLeft--
		if l.prev == nil {
			return nil, 0
		}
		return cloneSpecForTest(l.prev), l.prevVersion
	}
	if l.spec == nil {
		return nil, 0
	}
	return cloneSpecForTest(l.spec), l.version
}

// SpecOf and UpsertSpec are the same store without versions: what a caller
// that ignored VersionedSpecClient would see (unversioned below).
func (l *laggingSpecCluster) SpecOf(id string) *models.CreateSandboxRequest {
	spec, _ := l.SpecAndVersionOf(id)
	return spec
}

func (l *laggingSpecCluster) UpsertSpec(ctx context.Context, id string, spec *models.CreateSandboxRequest, _ cluster.PlacementSecrets) error {
	return l.UpsertSpecIfVersion(ctx, id, spec, 0)
}

func (l *laggingSpecCluster) UpsertSpecIfVersion(_ context.Context, id string, spec *models.CreateSandboxRequest, version uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.interleave != nil {
		other := cloneSpecForTest(l.spec)
		l.interleave(other)
		l.interleave = nil
		l.spec, l.version = other, l.version+1
	}
	if l.moved || (!l.unchecked && version != 0 && version != l.version) {
		l.conflicts++
		return fmt.Errorf("%w: %s at %d, write read %d", cluster.ErrSpecVersionConflict, id, l.version, version)
	}
	l.prev, l.prevVersion = l.spec, l.version
	l.spec, l.version = cloneSpecForTest(spec), l.version+1
	l.staleLeft = l.lag
	l.writes++
	return nil
}

func (l *laggingSpecCluster) current() *models.CreateSandboxRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return cloneSpecForTest(l.spec)
}

// unversioned hides the VersionedSpecClient methods, so writeReplicatedSpec
// takes its plain read-then-write path.
type unversioned struct{ cluster.Client }

func setTags(tags map[string]string) func(*models.CreateSandboxRequest) (bool, error) {
	return func(spec *models.CreateSandboxRequest) (bool, error) {
		if spec == nil || reflect.DeepEqual(spec.Tags, tags) {
			return false, nil
		}
		spec.Tags = tags
		return true, nil
	}
}

func setCPU(cpu float64) func(*models.CreateSandboxRequest) (bool, error) {
	return func(spec *models.CreateSandboxRequest) (bool, error) {
		if spec == nil || spec.CPU == cpu {
			return false, nil
		}
		spec.CPU = cpu
		return true, nil
	}
}

// TestWriteReplicatedSpecReadsPastStaleCopies walks the read-change-write
// that every spec write-through shares. Each case starts from CPU 1 and no
// tags at version 10, runs its earlier writes, then one more.
func TestWriteReplicatedSpecReadsPastStaleCopies(t *testing.T) {
	base := func() *models.CreateSandboxRequest {
		return &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 512}
	}
	tagsV := map[string]string{"k": "v"}
	cases := []struct {
		name       string
		spec       *models.CreateSandboxRequest
		lag        int
		setup      func(*laggingSpecCluster)
		before     []func(*models.CreateSandboxRequest) (bool, error)
		edit       func(*models.CreateSandboxRequest) (bool, error)
		ctxDone    bool
		plain      bool // through unversioned
		wantErr    error
		wantCPU    float64
		wantTags   map[string]string
		wantWrites int
		wantReads  int // reads made by the last write alone
		wantRefuse int
	}{
		{name: "fresh read: one write", spec: base(), edit: setTags(tagsV),
			wantCPU: 1, wantTags: tagsV, wantWrites: 1, wantReads: 1},
		{name: "read older than this node's resize: read again, keep the new size", spec: base(), lag: 1,
			before: []func(*models.CreateSandboxRequest) (bool, error){setCPU(4)}, edit: setTags(tagsV),
			wantCPU: 4, wantTags: tagsV, wantWrites: 2, wantReads: 2},
		{name: "same stale read without versions puts the old size back (the bug)", spec: base(), lag: 1, plain: true,
			before: []func(*models.CreateSandboxRequest) (bool, error){setCPU(4)}, edit: setTags(tagsV),
			wantCPU: 1, wantTags: tagsV, wantWrites: 2, wantReads: 1},
		{name: "tags set then set back: the skip is decided on a fresh copy", spec: base(), lag: 1,
			before: []func(*models.CreateSandboxRequest) (bool, error){setTags(tagsV)}, edit: setTags(nil),
			wantCPU: 1, wantTags: nil, wantWrites: 2, wantReads: 2},
		{name: "another node writes between read and write: refused, change redone on its copy", spec: base(),
			setup: func(l *laggingSpecCluster) {
				l.interleave = func(s *models.CreateSandboxRequest) { s.CPU = 2 }
			},
			edit: setTags(tagsV), wantCPU: 2, wantTags: tagsV, wantWrites: 1, wantReads: 2, wantRefuse: 1},
		{name: "an older server in the cluster: no check, the racing write is lost as before", spec: base(),
			setup: func(l *laggingSpecCluster) {
				l.unchecked = true
				l.interleave = func(s *models.CreateSandboxRequest) { s.CPU = 2 }
			},
			edit: setTags(tagsV), wantCPU: 1, wantTags: tagsV, wantWrites: 1, wantReads: 1},
		{name: "spec keeps moving: gives up after specWriteAttempts reads", spec: base(),
			setup: func(l *laggingSpecCluster) { l.moved = true }, edit: setTags(tagsV),
			wantErr: cluster.ErrSpecVersionConflict, wantCPU: 1, wantReads: specWriteAttempts, wantRefuse: specWriteAttempts},
		{name: "context ends while waiting: the refusal is returned", spec: base(), ctxDone: true,
			setup: func(l *laggingSpecCluster) { l.moved = true }, edit: setTags(tagsV),
			wantErr: cluster.ErrSpecVersionConflict, wantCPU: 1, wantReads: 1, wantRefuse: 1},
		{name: "no replicated spec: nothing to write", spec: nil, edit: setTags(tagsV), wantReads: 1},
		{name: "edit fails: its error, nothing written", spec: base(),
			edit:    func(*models.CreateSandboxRequest) (bool, error) { return false, errors.New("bad spec") },
			wantErr: errors.New("bad spec"), wantCPU: 1, wantReads: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newLaggingSpecCluster(tc.spec, tc.lag)
			if tc.setup != nil {
				tc.setup(stub)
			}
			var c cluster.Client = stub
			if tc.plain {
				c = unversioned{stub}
			}
			svc := &Service{}
			ctx := context.Background()
			for i, edit := range tc.before {
				if err := svc.writeReplicatedSpec(ctx, c, "sb-1", edit); err != nil {
					t.Fatalf("earlier write %d: %v", i, err)
				}
			}
			stub.mu.Lock()
			readsBefore := stub.reads
			stub.mu.Unlock()
			if tc.ctxDone {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err := svc.writeReplicatedSpec(ctx, c, "sb-1", tc.edit)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("write = %v, want nil", err)
			case tc.wantErr != nil && (err == nil || (!errors.Is(err, tc.wantErr) && err.Error() != tc.wantErr.Error())):
				t.Fatalf("write = %v, want %v", err, tc.wantErr)
			}
			got := stub.current()
			if tc.spec == nil {
				if got != nil {
					t.Fatalf("spec = %+v, want none", got)
				}
			} else if got.CPU != tc.wantCPU || !reflect.DeepEqual(got.Tags, tc.wantTags) {
				t.Fatalf("spec CPU %v tags %v, want CPU %v tags %v", got.CPU, got.Tags, tc.wantCPU, tc.wantTags)
			}
			stub.mu.Lock()
			defer stub.mu.Unlock()
			if reads := stub.reads - readsBefore; stub.writes != tc.wantWrites || reads != tc.wantReads || stub.conflicts != tc.wantRefuse {
				t.Fatalf("writes %d, reads by the last write %d, refused %d; want %d, %d, %d", stub.writes, reads, stub.conflicts, tc.wantWrites, tc.wantReads, tc.wantRefuse)
			}
		})
	}
}

// TestResizeThenTagsKeepsTheNewSize is the lost update end to end through
// the service: a failover sandbox resized and then given tags at once, on a
// worker whose next read reaches a follower that has not applied the
// resize. Before the fix the tags write read CPU 1 and wrote it back.
func TestResizeThenTagsKeepsTheNewSize(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	stub := newLaggingSpecCluster(&models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 512, DiskGB: 1}, 1)
	svc.AttachCluster(stub)
	now := time.Now().UTC()
	const id = "sb-resize-tags"
	if err := st.Create(ctx, &models.Sandbox{
		ID: id, Image: "alpine", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-resize-tags", ContainerIP: "10.0.0.40", Failover: recreateFailover(),
		CPU: 1, MemoryMB: 512, DiskGB: 1, Runtime: models.RuntimeDocker,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if _, err := svc.ResizeSandbox(ctx, id, models.ResizeSandboxRequest{CPU: 4, MemoryMB: 2048}); err != nil {
		t.Fatalf("ResizeSandbox: %v", err)
	}
	if err := svc.UpdateTags(ctx, id, map[string]string{"team": "a"}); err != nil {
		t.Fatalf("UpdateTags: %v", err)
	}
	got := stub.current()
	if got.CPU != 4 || got.MemoryMB != 2048 || got.Tags["team"] != "a" {
		t.Fatalf("replicated spec CPU %v memory %d tags %v, want CPU 4 memory 2048 tags team=a", got.CPU, got.MemoryMB, got.Tags)
	}
}

// TestPolicyCommitKeepsAnEarlierSpecWrite: commitPolicySpec, the strict
// writer, reads past a copy from before this node's last write too.
func TestPolicyCommitKeepsAnEarlierSpecWrite(t *testing.T) {
	ctx := context.Background()
	svc := New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleMixed}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, nil, nil, nil)
	stub := newLaggingSpecCluster(&models.CreateSandboxRequest{Image: "alpine", CPU: 1}, 1)
	svc.AttachCluster(stub)
	if err := svc.writeReplicatedSpec(ctx, stub, "sb-p", setCPU(3)); err != nil {
		t.Fatal(err)
	}
	if err := svc.commitPolicySpec(ctx, "sb-p", &models.CreateSandboxRequest{NetworkBlockAll: true}, []string{"TOKEN"}); err != nil {
		t.Fatalf("commitPolicySpec: %v", err)
	}
	got := stub.current()
	if got.CPU != 3 || !got.NetworkBlockAll || len(got.EgressWithheldEnv) != 1 {
		t.Fatalf("spec CPU %v block-all %v withheld %v, want CPU 3, block-all, TOKEN withheld", got.CPU, got.NetworkBlockAll, got.EgressWithheldEnv)
	}
	stub.moved = true
	if err := svc.commitPolicySpec(ctx, "sb-p", &models.CreateSandboxRequest{}, nil); !errors.Is(err, ErrEgressSpecCommitFailed) {
		t.Fatalf("commit against a spec that keeps moving = %v, want ErrEgressSpecCommitFailed", err)
	}
}

// TestTeamQuotaResizeReadsPastAStaleSpec: a growing resize decides its
// admission from the spec, and its undo decides from the spec too. Both
// right after a write is when a worker's read is most likely stale: the
// admission would have written the old CPU back with the new memory, and
// the undo found "not what I wrote" and left the larger size counted.
func TestTeamQuotaResizeReadsPastAStaleSpec(t *testing.T) {
	ctx := context.Background()
	svc := New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleMixed}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, nil, nil, nil)
	stub := newLaggingSpecCluster(&models.CreateSandboxRequest{Image: "a", CPU: 1, MemoryMB: 512}, 1)
	svc.AttachCluster(stub)
	sb := &models.Sandbox{ID: "sb-q", OwnerRef: "team:risk", CPU: 1, MemoryMB: 512}

	cpuHold, err := svc.admitTeamQuotaResize(ctx, sb, models.ResizeSandboxRequest{CPU: 2})
	if err != nil || cpuHold == nil {
		t.Fatalf("CPU growth = %v %v", cpuHold, err)
	}
	memHold, err := svc.admitTeamQuotaResize(ctx, sb, models.ResizeSandboxRequest{MemoryMB: 1024})
	if err != nil || memHold == nil {
		t.Fatalf("memory growth = %v %v", memHold, err)
	}
	if got := stub.current(); got.CPU != 2 || got.MemoryMB != 1024 {
		t.Fatalf("spec CPU %v memory %d after both growths, want CPU 2 memory 1024", got.CPU, got.MemoryMB)
	}
	if memHold.oldCPU != 2 || memHold.wroteCPU != 2 {
		t.Fatalf("memory hold old/wrote CPU = %v/%v, want 2/2 (read from the fresh copy)", memHold.oldCPU, memHold.wroteCPU)
	}
	// The memory resize fails: its undo runs right after its own write.
	svc.unwriteResizeSpec(memHold)
	if got := stub.current(); got.CPU != 2 || got.MemoryMB != 512 {
		t.Fatalf("spec CPU %v memory %d after the undo, want CPU 2 memory 512", got.CPU, got.MemoryMB)
	}
}

// TestSpecReadFloors pins the per-sandbox floor: it only rises, it expires
// after specFloorTTL, and a full map drops expired entries on the next
// raise.
func TestSpecReadFloors(t *testing.T) {
	var f specReadFloors
	if got := f.get("a"); got != 0 {
		t.Fatalf("empty floor = %d", got)
	}
	f.raise("a", 11)
	f.raise("a", 7)
	if got := f.get("a"); got != 11 {
		t.Fatalf("floor after a lower raise = %d, want 11", got)
	}
	f.mu.Lock()
	f.m["a"] = specReadFloor{version: 11, at: time.Now().Add(-specFloorTTL - time.Second)}
	f.mu.Unlock()
	if got := f.get("a"); got != 0 {
		t.Fatalf("expired floor = %d, want 0", got)
	}
	f.mu.Lock()
	old := time.Now().Add(-specFloorTTL - time.Second)
	for i := 0; i < specFloorSweepAt; i++ {
		f.m[fmt.Sprintf("old-%d", i)] = specReadFloor{version: 1, at: old}
	}
	f.m["fresh"] = specReadFloor{version: 5, at: time.Now()}
	f.mu.Unlock()
	f.raise("b", 3)
	f.mu.Lock()
	n := len(f.m)
	f.mu.Unlock()
	if n != 2 || f.get("fresh") != 5 || f.get("b") != 3 {
		t.Fatalf("after the sweep: %d floors, fresh=%d b=%d; want 2, 5, 3", n, f.get("fresh"), f.get("b"))
	}
}
