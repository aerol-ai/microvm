package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A snapshot commit writes an image before the catalogue row that owns it.
// These tests pin the rollback rule between the two: the cleanup intent is
// recorded first, cleared once the row is in, the image is removed right away
// when the row cannot be written, and anything left (a crash, a failed
// remove) is the pending-image janitor's.

const rollbackSnapName = "snapshots/rollback:v1"

type commitRollbackHarness struct {
	svc  *Service
	st   *store.Store
	path string
	rt   *fakeSnapshotRuntime
	tag  string
}

func newCommitRollbackHarness(t *testing.T, gcEnabled bool) *commitRollbackHarness {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Create(context.Background(), seedSnapshotSandbox("sb-rollback", time.Now().UTC())); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	rt := &fakeSnapshotRuntime{imageID: "sha256:rollback"}
	svc := &Service{
		cfg:    config.Config{ImageBuildGCEnabled: gcEnabled, ImageBuildGCTTL: time.Hour},
		store:  st,
		docker: rt,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return &commitRollbackHarness{svc: svc, st: st, path: path, rt: rt, tag: docker.SnapshotImageTagForOwner("", rollbackSnapName)}
}

func (h *commitRollbackHarness) create() (*models.SandboxSnapshot, error) {
	snap, _, err := h.svc.CreateSnapshotWithOwnership(context.Background(), "sb-rollback", models.CreateSandboxSnapshotRequest{Name: rollbackSnapName})
	return snap, err
}

// ledgerAt lists the pending-image ledger, read through a fresh
// handle so a test that closed the service's store can still look.
func ledgerAt(t *testing.T, path string) []store.PendingImageGCEntry {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st.Close()
	entries, err := st.ListPendingImageGCDue(context.Background(), time.Now().UTC().Add(24*time.Hour), 0)
	if err != nil {
		t.Fatalf("list ledger: %v", err)
	}
	return entries
}

func TestCreateSnapshotCommitRollback(t *testing.T) {
	cases := []struct {
		name string
		// gc is cfg.ImageBuildGCEnabled.
		gc    bool
		setup func(t *testing.T, h *commitRollbackHarness)
		// wantErr: the create must fail.
		wantErr bool
		// wantCommit: the runtime commit ran.
		wantCommit bool
		// wantRemoved: the commit's tag was removed right away.
		wantRemoved bool
		// wantIntent: the (docker, tag) cleanup intent is still in the ledger.
		wantIntent bool
	}{
		{
			name: "success clears the intent", gc: true,
			wantCommit: true,
		},
		{
			name: "store insert fails: image removed, intent cleared", gc: true,
			setup: func(t *testing.T, h *commitRollbackHarness) {
				cb96SQL(t, h.path, `CREATE TRIGGER fail_snap BEFORE INSERT ON sandbox_snapshots BEGIN SELECT RAISE(ABORT, 'disk full'); END`)
			},
			wantErr: true, wantCommit: true, wantRemoved: true,
		},
		{
			name: "normalize fails: image removed, intent cleared", gc: true,
			setup: func(t *testing.T, h *commitRollbackHarness) {
				h.svc.testNormalizeSnapshotErr = errors.New("classify failed")
			},
			wantErr: true, wantCommit: true, wantRemoved: true,
		},
		{
			name: "image remove fails: intent left for the janitor", gc: true,
			setup: func(t *testing.T, h *commitRollbackHarness) {
				h.svc.testNormalizeSnapshotErr = errors.New("classify failed")
				h.rt.removeErr = errors.New("engine busy")
			},
			wantErr: true, wantCommit: true, wantRemoved: true, wantIntent: true,
		},
		{
			name: "tag still named by a live sandbox: kept, intent left", gc: true,
			setup: func(t *testing.T, h *commitRollbackHarness) {
				sb := seedSnapshotSandbox("sb-uses-tag", time.Now().UTC())
				sb.Image = h.tag
				if err := h.st.Create(context.Background(), sb); err != nil {
					t.Fatal(err)
				}
				h.svc.testNormalizeSnapshotErr = errors.New("classify failed")
			},
			wantErr: true, wantCommit: true, wantIntent: true,
		},
		{
			name: "ref check fails: nothing removed, intent left", gc: true,
			setup: func(t *testing.T, h *commitRollbackHarness) {
				h.svc.testBeforeStoreCreateSnapshot = func(*models.SandboxSnapshot) { _ = h.st.Close() }
			},
			wantErr: true, wantCommit: true, wantIntent: true,
		},
		{
			name: "commit fails: intent left for a late tag", gc: true,
			setup: func(t *testing.T, h *commitRollbackHarness) {
				h.rt.err = errors.New("commit failed")
			},
			wantErr: true, wantCommit: true, wantIntent: true,
		},
		{
			name: "intent cannot be written: no commit", gc: true,
			setup: func(t *testing.T, h *commitRollbackHarness) {
				cb96SQL(t, h.path, `CREATE TRIGGER fail_gc BEFORE INSERT ON pending_image_gc BEGIN SELECT RAISE(ABORT, 'disk full'); END`)
			},
			wantErr: true,
		},
		{
			name: "gc disabled: no intent, rollback still removes", gc: false,
			setup: func(t *testing.T, h *commitRollbackHarness) {
				h.svc.testNormalizeSnapshotErr = errors.New("classify failed")
			},
			wantErr: true, wantCommit: true, wantRemoved: true,
		},
		{
			name: "intent clear fails after the insert: the janitor drops it", gc: true,
			setup: func(t *testing.T, h *commitRollbackHarness) {
				cb96SQL(t, h.path, `CREATE TRIGGER keep_gc BEFORE DELETE ON pending_image_gc BEGIN SELECT RAISE(ABORT, 'locked'); END`)
			},
			wantCommit: true, wantIntent: true,
		},
		{
			name: "whitelisted tag: no intent", gc: true,
			setup: func(t *testing.T, h *commitRollbackHarness) {
				h.svc.cfg.ImageGCWhitelist = []string{docker.SnapshotImageNamespace + "/"}
			},
			wantCommit: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCommitRollbackHarness(t, tc.gc)
			if tc.setup != nil {
				tc.setup(t, h)
			}
			snap, err := h.create()
			if tc.wantErr != (err != nil) {
				t.Fatalf("create = %+v, %v; want error %v", snap, err, tc.wantErr)
			}
			if got := h.rt.hits == 1; got != tc.wantCommit {
				t.Fatalf("commit ran = %v, want %v", got, tc.wantCommit)
			}
			if removed := h.rt.removeHits > 0 && h.rt.lastRemoved == h.tag; removed != tc.wantRemoved {
				t.Fatalf("tag removed = %v (hits %d, last %q), want %v", removed, h.rt.removeHits, h.rt.lastRemoved, tc.wantRemoved)
			}
			intent := false
			for _, e := range ledgerAt(t, h.path) {
				if e.Image == h.tag {
					if e.Engine != models.ContainerEngineDocker {
						t.Fatalf("intent engine = %q, want the sandbox's engine", e.Engine)
					}
					intent = true
				}
			}
			if intent != tc.wantIntent {
				t.Fatalf("intent present = %v, want %v", intent, tc.wantIntent)
			}
		})
	}
}

// The intent names the engine whose store the commit writes: a containerd
// sandbox's own engine, the node's engine ("") for a Firecracker VM, and none
// for a WASM checkpoint, which is a file.
func TestSnapshotCommitEngine(t *testing.T) {
	cases := []struct {
		sandbox    models.Sandbox
		wantEngine string
		wantOK     bool
	}{
		{models.Sandbox{Runtime: models.RuntimeDocker}, models.ContainerEngineDocker, true},
		{models.Sandbox{Runtime: models.RuntimeGvisor, Engine: models.ContainerEngineContainerd}, models.ContainerEngineContainerd, true},
		{models.Sandbox{Runtime: models.RuntimeFirecracker}, "", true},
		{models.Sandbox{Runtime: models.RuntimeWasm}, "", false},
		{models.Sandbox{Runtime: models.RuntimeIsolate}, "", false},
	}
	for _, tc := range cases {
		engine, ok := snapshotCommitEngine(&tc.sandbox)
		if engine != tc.wantEngine || ok != tc.wantOK {
			t.Errorf("snapshotCommitEngine(%s/%s) = %q,%v; want %q,%v", tc.sandbox.Runtime, tc.sandbox.Engine, engine, ok, tc.wantEngine, tc.wantOK)
		}
	}
	// A runtime with no engine image is never rolled back through one.
	h := newCommitRollbackHarness(t, true)
	h.svc.rollbackSnapshotCommit(context.Background(), false, "", h.tag)
	if h.rt.removeHits != 0 {
		t.Fatal("a WASM rollback removed an engine image")
	}
}

// A daemon that died between the commit and the insert left only the intent.
// The janitor reclaims the tag once the TTL passes; had the row landed, it
// keeps the image and drops the intent instead.
func TestPendingImageGCReclaimsACrashedSnapshotCommit(t *testing.T) {
	for _, rowLanded := range []bool{false, true} {
		h := newCommitRollbackHarness(t, true)
		if err := h.st.SchedulePendingImageGC(context.Background(), models.ContainerEngineDocker, h.tag, time.Now().UTC().Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if rowLanded {
			if err := h.st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{
				Name: rollbackSnapName, Image: h.tag, SourceSandboxID: "sb-rollback", CreatedAt: time.Now().UTC(),
			}); err != nil {
				t.Fatal(err)
			}
		}
		h.svc.runPendingImageGC(context.Background())
		if removed := h.rt.removeHits == 1 && h.rt.lastRemoved == h.tag; removed == rowLanded {
			t.Fatalf("row landed %v: tag removed = %v", rowLanded, removed)
		}
		if ledger := ledgerAt(t, h.path); len(ledger) != 0 {
			t.Fatalf("row landed %v: ledger = %+v, want drained", rowLanded, ledger)
		}
	}
}

// signalRemoveRuntime reports every RemoveImage on a channel so a test can
// see a removal that happens on another goroutine.
type signalRemoveRuntime struct {
	*fakeSnapshotRuntime
	removed chan string
}

func (r *signalRemoveRuntime) RemoveImage(_ context.Context, ref string) error {
	r.removed <- ref
	return nil
}

// The janitor must never remove a snapshot tag whose create is in flight. The
// sweep here has already listed the (due) intent when the create is between
// its commit and its insert; without snapshotMu it would see no row naming
// the tag and remove the image the create just committed.
func TestPendingImageGCLeavesAnInFlightSnapshotCommitAlone(t *testing.T) {
	h := newCommitRollbackHarness(t, true)
	// TTL 0: the intent the create writes is due at once, as a stale
	// intent from an earlier failed attempt would be.
	h.svc.cfg.ImageBuildGCTTL = 0
	rt := &signalRemoveRuntime{fakeSnapshotRuntime: h.rt, removed: make(chan string, 4)}
	h.svc.docker = rt

	listed := make(chan struct{})
	h.svc.testAfterPendingImageGCList = func() { close(listed) }
	sweepDone := make(chan struct{})
	h.svc.testBeforeStoreCreateSnapshot = func(*models.SandboxSnapshot) {
		go func() {
			defer close(sweepDone)
			h.svc.runPendingImageGC(context.Background())
		}()
		<-listed
		// Give an unguarded sweep every chance to remove the tag now.
		select {
		case ref := <-rt.removed:
			t.Errorf("janitor removed %q while its create was in flight", ref)
		case <-time.After(150 * time.Millisecond):
		}
	}
	snap, err := h.create()
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	<-sweepDone
	select {
	case ref := <-rt.removed:
		t.Fatalf("janitor removed %q after its create finished", ref)
	default:
	}
	if _, err := h.st.GetSnapshot(context.Background(), "", snap.Name); err != nil {
		t.Fatalf("snapshot row: %v", err)
	}
	if ledger := ledgerAt(t, h.path); len(ledger) != 0 {
		t.Fatalf("ledger = %+v, want the intent gone", ledger)
	}
}
