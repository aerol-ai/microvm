package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// V3 (review 2026-11-15): an idle worker has no IDs to read, but that must
// not become a fresh authority to run a delayed create after the real
// leader is unreachable. The worker's lease ran out a minute ago and the
// leader is down: the empty confirm may succeed, but the recreate-policy
// create after it must not. Before the fix both succeeded with zero
// authoritative reads, and the new sandbox was neither fenced nor frozen.
func TestEmptyLeaseReadCannotAuthorizeDelayedCreate(t *testing.T) {
	ctx := context.Background()
	rt := newFreezeRuntime()
	svc, st, lc := newLeaseService(t, rt)
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	svc.beginOwnershipLease(time.Now().Add(-time.Minute))
	lc.down()
	before := lc.readCount()
	if err := svc.confirmOwnership(ctx, time.Now()); err != nil {
		t.Fatalf("an idle confirm failed: %v", err)
	}
	err := svc.persistSandboxCreate(ctx, leaseCreateRow("delayed", true))
	if !errors.Is(err, ErrOwnershipFenced) {
		svc.enforceOwnershipLease(ctx, time.Now().Add(time.Second))
		t.Fatalf("recreate create with the leader unreachable: %v (want ErrOwnershipFenced); authoritative reads=%d fenced=%v frozen=%v",
			err, lc.readCount()-before, svc.OwnershipFenced("delayed"), rt.isFrozen("ctr-delayed"))
	}
	if lc.readCount() != before+1 {
		t.Fatalf("authoritative reads = %d, want the create's one", lc.readCount()-before)
	}
	if _, err := st.Get(ctx, "delayed"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("the refused create left its row: %v", err)
	}
}

// A confirm with nothing to read leaves the lease where the last read put
// it, in the process and in the file: the file is written again so its
// fence drops what is gone, but its read time stays and its countdown only
// shrinks. Before any read in this process it writes nothing at all.
func TestIdleConfirmDoesNotRenewTheLease(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	path := filepath.Join(t.TempDir(), "ownership-lease")
	svc.cfg.OwnershipLeaseFile = path

	// Idle from the start: no read, no file.
	if err := svc.confirmOwnership(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an idle confirm wrote a lease file before any read proved one: %v", err)
	}

	// A real read, then the sandbox goes and the node is idle.
	seedLeaseRow(t, st, "a", true, models.SandboxStatusStarted)
	lc.up(selfPlacement("a"))
	read := time.Now().Add(-5 * time.Second)
	if err := svc.confirmOwnership(ctx, read); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	reads := lc.readCount()
	if err := svc.confirmOwnership(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if lc.readCount() != reads {
		t.Fatalf("an idle confirm sent %d reads", lc.readCount()-reads)
	}
	l := readLeaseFile(t, path)
	if l.ConfirmedUnixMs != read.UnixMilli() || len(l.Fence) != 0 {
		t.Fatalf("idle confirm wrote %+v; want the read at %d kept and an empty fence", l, read.UnixMilli())
	}
	if l.Remaining() > 10*time.Second+100*time.Millisecond {
		t.Fatalf("idle confirm left %s of a 15s lease read 5s ago", l.Remaining())
	}
	svc.ownership.mu.Lock()
	confirmed, last := svc.ownership.confirmed, svc.ownership.read
	svc.ownership.mu.Unlock()
	if !confirmed.Equal(read) || !last.Equal(read) {
		t.Fatalf("lease confirmed %v, read %v; want both at the last read %v", confirmed, last, read)
	}
}

// The create's read (requireFreshOwnership). A node with a recent read pays
// a clock read. A node with no recent read (idle, failing reads, or not one
// read since it started) reads first, with the new sandbox in the read:
// with the leader up, and its reservation naming this node, the create goes
// on and its lease is fresh, so the next check does not fence it; with the
// leader down it is refused before its row is written. A sandbox without the
// recreate policy never reads.
func TestRecreateCreateReadsAfterAnIdleSpell(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lastRead  time.Duration // 0: no read since the start
		down      bool
		recreate  bool
		wantReads int
		wantErr   bool
	}{
		{name: "recent read: no new one", lastRead: 2 * time.Second, recreate: true, wantReads: 0},
		{name: "idle past two thirds of the lease", lastRead: 11 * time.Second, recreate: true, wantReads: 1},
		{name: "idle for a minute, leader down", lastRead: time.Minute, down: true, recreate: true, wantReads: 1, wantErr: true},
		{name: "no read since the start", recreate: true, wantReads: 1},
		{name: "no read since the start, leader down", down: true, recreate: true, wantReads: 1, wantErr: true},
		{name: "no recreate policy", lastRead: time.Minute, down: true, recreate: false, wantReads: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := newFreezeRuntime()
			svc, st, lc := newLeaseService(t, rt)
			svc.beginOwnershipLease(time.Now().Add(-time.Hour))
			if tc.lastRead > 0 {
				// The last real read, of a sandbox since gone.
				seedLeaseRow(t, st, "old", true, models.SandboxStatusStarted)
				lc.up(selfPlacement("old"))
				if err := svc.confirmOwnership(ctx, time.Now().Add(-tc.lastRead)); err != nil {
					t.Fatal(err)
				}
				if err := st.Delete(ctx, "old"); err != nil {
					t.Fatal(err)
				}
			}
			if tc.down {
				lc.down()
			} else {
				lc.up(reservedFor("new", "worker-a", "inc-new"))
			}
			reads, sizes := lc.readCount(), len(lc.batchSizes)
			err := svc.persistSandboxCreate(ctx, leaseCreateRow("new", tc.recreate))
			if got := lc.readCount() - reads; got != tc.wantReads {
				t.Fatalf("reads = %d, want %d", got, tc.wantReads)
			}
			if tc.wantErr {
				if !errors.Is(err, ErrOwnershipFenced) {
					t.Fatalf("create = %v, want ErrOwnershipFenced", err)
				}
				if _, err := st.Get(ctx, "new"); !errors.Is(err, storepkg.ErrNotFound) {
					t.Fatalf("the refused create left its row: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("create = %v", err)
			}
			if tc.wantReads > 0 && !slices.Contains(lc.batchSizes[sizes:], 1) {
				t.Fatalf("the create's read did not carry the new sandbox: batches %v", lc.batchSizes[sizes:])
			}
			svc.enforceOwnershipLease(ctx, time.Now().Add(time.Second))
			if svc.OwnershipFenced("new") || rt.isFrozen("ctr-new") {
				t.Fatal("a create on a fresh lease was fenced at the next check")
			}
		})
	}
}

// Single-node mode has no lease: the gate is a no-op and reads nothing.
func TestRequireFreshOwnershipSingleNode(t *testing.T) {
	svc, _, lc := newLeaseService(t, newFreezeRuntime())
	svc.cfg.EnableCluster = false
	lc.down()
	if err := svc.requireFreshOwnership(context.Background(), "sb", ""); err != nil {
		t.Fatalf("single node: %v", err)
	}
	if lc.readCount() != 0 {
		t.Fatalf("single node sent %d reads", lc.readCount())
	}
}

// reservedFor is a new create's placement: reserved for owner, lifetime inc.
func reservedFor(id, owner, inc string) cluster.Placement {
	return cluster.Placement{SandboxID: id, OwnerNodeID: owner, OwnerAPIURL: "http://" + owner, IncarnationID: inc, State: cluster.PlacementStateReserved}
}

// The read must give the sandbox to this node, not only be answered (b3's
// follow-up to V3). An idle node is cut off, the leader hands the sandbox to
// another node, the node comes back: its read succeeds, but the answer names
// worker-b, so the create is refused before its row is written. Before this
// check that create was accepted, and not fenced either. A placement being
// deleted, orphaned, missing, or of another lifetime refuses too; a
// reservation or a placement for this node, of this lifetime (or with no
// lifetime on either side), lets it go on.
func TestRecreateCreateNeedsTheLeaderToNameThisNode(t *testing.T) {
	placed := func(id, owner, inc string) cluster.Placement {
		p := reservedFor(id, owner, inc)
		p.State = cluster.PlacementStatePlaced
		return p
	}
	deleting := reservedFor("delayed", "worker-a", "inc-delayed")
	deleting.State = cluster.PlacementStateDeleting
	orphaned := placed("delayed", "", "inc-delayed")
	for _, tc := range []struct {
		name      string
		placement *cluster.Placement
		ok        bool
	}{
		{name: "given to another node", placement: ptr(placed("delayed", "worker-b", "inc-delayed"))},
		{name: "reserved for another node", placement: ptr(reservedFor("delayed", "worker-b", "inc-delayed"))},
		{name: "being deleted", placement: &deleting},
		{name: "orphaned", placement: &orphaned},
		{name: "no placement", placement: nil},
		{name: "another lifetime", placement: ptr(placed("delayed", "worker-a", "inc-other"))},
		{name: "reserved for this node", placement: ptr(reservedFor("delayed", "worker-a", "inc-delayed")), ok: true},
		{name: "placed on this node", placement: ptr(placed("delayed", "worker-a", "inc-delayed")), ok: true},
		{name: "no lifetime on the placement", placement: ptr(placed("delayed", "worker-a", "")), ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc, st, lc := newLeaseService(t, newFreezeRuntime())
			svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
			svc.beginOwnershipLease(time.Now().Add(-time.Minute))
			if tc.placement != nil {
				lc.up(*tc.placement)
			} else {
				lc.up()
			}
			err := svc.persistSandboxCreate(ctx, leaseCreateRow("delayed", true))
			if tc.ok {
				if err != nil {
					t.Fatalf("create = %v", err)
				}
				return
			}
			if !errors.Is(err, ErrOwnershipFenced) {
				t.Fatalf("create = %v, want ErrOwnershipFenced; fenced=%v", err, svc.OwnershipFenced("delayed"))
			}
			if _, err := st.Get(ctx, "delayed"); !errors.Is(err, storepkg.ErrNotFound) {
				t.Fatalf("the refused create left its row: %v", err)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// createCountingRuntime counts instance creates, to show a refused create
// never started one.
type createCountingRuntime struct {
	*freezeRuntime
	creates atomic.Int32
}

func (r *createCountingRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, id, token string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	r.creates.Add(1)
	return &models.SandboxRuntimeState{ContainerID: "ctr-" + id, ContainerIP: "10.0.0.2", Status: models.SandboxStatusStarted}, nil
}

// The check runs before the create starts anything (review: "before allowing
// a recreate executor to start"), not only before its row is written: a
// refused create never reached the runtime, so no executor ran even
// briefly, and it reserved no capacity to give back. With the leader's
// placement naming this node the create does reach the runtime.
func TestRecreateCreateChecksOwnershipBeforeItStarts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		down      bool
		owner     string
		wantStart bool
	}{
		{name: "leader down", down: true},
		{name: "given to another node", owner: "worker-b"},
		{name: "reserved for this node", owner: "worker-a", wantStart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &createCountingRuntime{freezeRuntime: newFreezeRuntime()}
			svc, _, lc := newLeaseService(t, rt)
			svc.beginOwnershipLease(time.Now().Add(-time.Minute))
			if tc.down {
				lc.down()
			} else {
				lc.up(reservedFor("sb-prestart", tc.owner, ""))
			}
			_, err := svc.CreateSandboxWithID(context.Background(), models.CreateSandboxRequest{
				Image:    "alpine:3.20",
				Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
			}, "sb-prestart")
			started := rt.creates.Load() > 0
			if started != tc.wantStart {
				t.Fatalf("runtime creates = %d (err %v), want started %v", rt.creates.Load(), err, tc.wantStart)
			}
			if !tc.wantStart && !errors.Is(err, ErrOwnershipFenced) {
				t.Fatalf("create = %v, want ErrOwnershipFenced", err)
			}
			if !tc.wantStart && svc.admitter != nil && svc.admitter.Snapshot().ReservedCPU != 0 {
				t.Fatal("a refused create left capacity reserved")
			}
		})
	}
}

// The other three create paths (Firecracker, WASM, isolate) check before
// they start too: with no fresh read and the leader down, each is refused
// with ErrOwnershipFenced before admission, so no instance starts.
func TestEveryCreatePathChecksOwnershipBeforeItStarts(t *testing.T) {
	recreate := &models.Failover{Policy: models.FailoverPolicyRecreate}
	for _, tc := range []struct {
		name   string
		create func(*Service) error
	}{
		{"firecracker", func(svc *Service) error {
			_, err := svc.createFirecrackerSandbox(context.Background(), models.CreateSandboxRequest{
				Runtime: models.RuntimeFirecracker, Image: "docker://alpine", Failover: recreate}, "sb-fc")
			return err
		}},
		{"wasm", func(svc *Service) error {
			_, err := svc.createWasmSandbox(context.Background(), models.CreateSandboxRequest{
				Runtime: models.RuntimeWasm, ModuleRef: "file:///opt/app.wasm", Failover: recreate}, "sb-wasm")
			return err
		}},
		{"isolate", func(svc *Service) error {
			_, err := svc.createIsolateSandbox(context.Background(), models.CreateSandboxRequest{
				Runtime: models.RuntimeIsolate, ModuleRef: models.JSBundleRefForNode("bundle-1", "worker-a"), Failover: recreate}, "sb-iso")
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &createCountingRuntime{freezeRuntime: newFreezeRuntime()}
			svc, _, lc := newLeaseService(t, rt)
			svc.SetFirecrackerRuntime(rt)
			svc.wasm, svc.isolate = rt, rt
			svc.beginOwnershipLease(time.Now().Add(-time.Minute))
			lc.down()
			if err := tc.create(svc); !errors.Is(err, ErrOwnershipFenced) {
				t.Fatalf("create = %v, want ErrOwnershipFenced", err)
			}
			if rt.creates.Load() != 0 {
				t.Fatalf("runtime creates = %d, want none", rt.creates.Load())
			}
		})
	}
}
