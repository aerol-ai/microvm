package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/ownerlease"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func readLeaseFile(t *testing.T, path string) ownerlease.Lease {
	t.Helper()
	l, err := ownerlease.Read(path)
	if err != nil {
		t.Fatalf("lease file: %v", err)
	}
	return l
}

// TestOwnershipLeaseFile (T3): each successful read writes the lease for
// the runtime supervisor: every recreate-policy sandbox fenced, only the
// ones the read proved still here owned, the lease counted from the read's
// send time. A failed or older read changes nothing.
func TestOwnershipLeaseFile(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	path := filepath.Join(t.TempDir(), "ownership-lease")
	svc.cfg.OwnershipLeaseFile = path
	seedLeaseRow(t, st, "a", true, models.SandboxStatusStarted)
	seedLeaseRow(t, st, "b", true, models.SandboxStatusStarted)
	seedLeaseRow(t, st, "c", false, models.SandboxStatusStarted)
	moved := selfPlacement("b")
	moved.OwnerNodeID = "worker-b"
	lc.up(selfPlacement("a"), moved, selfPlacement("c"))

	sent := time.Now().Add(-2 * time.Second)
	if err := svc.confirmOwnership(ctx, sent); err != nil {
		t.Fatal(err)
	}
	l := readLeaseFile(t, path)
	slices.Sort(l.Fence)
	if !slices.Equal(l.Fence, []string{"ctr-a", "ctr-b"}) || !slices.Equal(l.Owned, []string{"ctr-a"}) {
		t.Fatalf("fence %v owned %v, want both recreate sandboxes fenced and only ctr-a owned", l.Fence, l.Owned)
	}
	if l.ConfirmedUnixMs != sent.UnixMilli() || l.LeaseMs != cluster.OwnershipLease(svc.cfg).Milliseconds() {
		t.Fatalf("confirmed %d lease %d", l.ConfirmedUnixMs, l.LeaseMs)
	}
	// Counted from the send, not the write: about 2 s of 15 already gone.
	if r := l.Remaining(); r > 13*time.Second+500*time.Millisecond || r < 12*time.Second {
		t.Fatalf("remaining %v, want about 13s", r)
	}

	lc.down()
	if err := svc.confirmOwnership(ctx, time.Now()); err == nil {
		t.Fatal("a failed read confirmed")
	}
	if again := readLeaseFile(t, path); again.ConfirmedUnixMs != l.ConfirmedUnixMs {
		t.Fatal("a failed read renewed the file")
	}
	lc.up(selfPlacement("a"), selfPlacement("b"))
	if err := svc.confirmOwnership(ctx, sent.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if again := readLeaseFile(t, path); again.ConfirmedUnixMs != l.ConfirmedUnixMs {
		t.Fatal("an older read replaced a newer one")
	}
}

// Off in single-node mode and without the setting; a failed write is
// counted and logged, and the next read writes again.
func TestOwnershipLeaseFileOffAndFailures(t *testing.T) {
	ctx := context.Background()
	single, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), newFreezeRuntime())
	single.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "ownership-lease")
	if err := single.publishOwnershipFence(ctx); err != nil {
		t.Fatal(err)
	}
	single.recordOwnershipRead(ctx, time.Now(), nil, nil, "worker-a")
	if _, err := os.Stat(single.cfg.OwnershipLeaseFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("single-node mode wrote the file: %v", err)
	}
	var none *Service
	if none.ownershipLeaseFileOn() {
		t.Fatal("a nil service writes a lease file")
	}

	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	seedLeaseRow(t, st, "a", true, models.SandboxStatusStarted)
	lc.up(selfPlacement("a"))
	if err := svc.confirmOwnership(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "missing", "ownership-lease")
	before := ownershipLeaseFileWriteErrors.Value()
	if err := svc.confirmOwnership(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if ownershipLeaseFileWriteErrors.Value() != before+1 {
		t.Fatal("a failed write was not counted")
	}

	// A write that cannot list the sandboxes leaves the file alone.
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "ownership-lease")
	_ = st.Close()
	if err := svc.publishOwnershipFence(ctx); err == nil {
		t.Fatal("a fence written without the sandbox list")
	}
	if _, err := os.Stat(svc.cfg.OwnershipLeaseFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("written without the sandbox list: %v", err)
	}
}

// leaseCreateRow is a row for persistSandboxCreate.
func leaseCreateRow(id string, recreate bool) *models.Sandbox {
	now := time.Now().UTC()
	sb := &models.Sandbox{ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
		ContainerID: "ctr-" + id, AuditIncarnationID: "inc-" + id, CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
	if recreate {
		sb.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
	}
	return sb
}

// A recreate-policy sandbox is in the fence when its create returns (R9),
// under the same read: a sandboxd that dies right after still leaves it for
// the supervisor to freeze, and nothing waits on a writer that could be
// lost with it. Any other sandbox changes nothing.
func TestPersistSandboxCreatePublishesTheFence(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	path := filepath.Join(t.TempDir(), "ownership-lease")
	svc.cfg.OwnershipLeaseFile = path
	seedLeaseRow(t, st, "a", true, models.SandboxStatusStarted)
	lc.up(selfPlacement("a"))
	sent := time.Now()
	if err := svc.confirmOwnership(ctx, sent); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id       string
		recreate bool
		fence    []string
	}{
		{"plain", false, []string{"ctr-a"}},
		{"moves", true, []string{"ctr-a", "ctr-moves"}},
	} {
		if err := svc.persistSandboxCreate(ctx, leaseCreateRow(tc.id, tc.recreate)); err != nil {
			t.Fatal(err)
		}
		l := readLeaseFile(t, path)
		slices.Sort(l.Fence)
		if !slices.Equal(l.Fence, tc.fence) {
			t.Fatalf("%s: create returned with fence %v, want %v", tc.id, l.Fence, tc.fence)
		}
		if l.ConfirmedUnixMs != sent.UnixMilli() || !slices.Equal(l.Owned, []string{"ctr-a"}) {
			t.Fatalf("%s: the create changed the read: %+v", tc.id, l)
		}
	}

	// A fence that cannot be written fails the create and takes its row.
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "missing", "ownership-lease")
	if err := svc.persistSandboxCreate(ctx, leaseCreateRow("unfenced", true)); err == nil {
		t.Fatal("a create whose fence was not written succeeded")
	}
	if _, err := st.Get(ctx, "unfenced"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("the row of a create whose fence failed is still there: %v", err)
	}
}

// A process that has not confirmed its lease yet writes nothing on its own:
// its first recreate-policy create runs the read first. With the leader
// unreachable that create fails, nothing is written and its row is gone.
func TestPersistSandboxCreateConfirmsFirst(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	path := filepath.Join(t.TempDir(), "ownership-lease")
	svc.cfg.OwnershipLeaseFile = path

	lc.down()
	if err := svc.persistSandboxCreate(ctx, leaseCreateRow("a", true)); !errors.Is(err, ErrOwnershipFenced) {
		t.Fatalf("create with no read and no leader: %v, want ErrOwnershipFenced", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("written before any read: %v", err)
	}
	if _, err := st.Get(ctx, "a"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("the refused create left its row: %v", err)
	}

	lc.up()
	reads := lc.readCount()
	if err := svc.persistSandboxCreate(ctx, leaseCreateRow("a", true)); err != nil {
		t.Fatal(err)
	}
	if l := readLeaseFile(t, path); !slices.Equal(l.Fence, []string{"ctr-a"}) || lc.readCount() != reads+1 {
		t.Fatalf("fence %v after %d reads, want ctr-a after one more", l.Fence, lc.readCount()-reads)
	}
}

// A read's rows were listed before it went out. A sandbox created while it
// was out is already in the file, and the read's write keeps it: every
// write lists the fence afresh.
func TestOwnershipReadKeepsASandboxCreatedMeanwhile(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	path := filepath.Join(t.TempDir(), "ownership-lease")
	svc.cfg.OwnershipLeaseFile = path
	seedLeaseRow(t, st, "a", true, models.SandboxStatusStarted)
	lc.up(selfPlacement("a"))
	if err := svc.confirmOwnership(ctx, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	stale, err := svc.localRecreateSandboxes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.persistSandboxCreate(ctx, leaseCreateRow("new", true)); err != nil {
		t.Fatal(err)
	}
	svc.recordOwnershipRead(ctx, time.Now(), stale, map[string]cluster.Placement{"a": selfPlacement("a")}, "worker-a")
	l := readLeaseFile(t, path)
	slices.Sort(l.Fence)
	if !slices.Equal(l.Fence, []string{"ctr-a", "ctr-new"}) {
		t.Fatalf("a read listed before the create dropped it from the fence: %v", l.Fence)
	}
}

// The capacity heartbeat says whether this node's runtime enforces the
// ownership lease with sandboxd down, so the leader knows it may fail the
// node over early on the operator's "machine is gone" (C19).
func TestCapacityReportsOwnershipLeaseFile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		cfg  config.Config
		want bool
	}{
		{cfg: config.Config{}, want: false},
		{cfg: config.Config{OwnershipLeaseFile: "/run/aerolvm/lease.json"}, want: false}, // not a cluster
		{cfg: config.Config{EnableCluster: true}, want: false},
		{cfg: config.Config{EnableCluster: true, OwnershipLeaseFile: "/run/aerolvm/lease.json"}, want: true},
	} {
		svc := New(tc.cfg, logger, nil, nil, nil, nil, nil, nil, nil)
		if got := svc.Capacity().OwnershipLeaseFile; got != tc.want {
			t.Fatalf("cfg %+v: OwnershipLeaseFile = %v, want %v", tc.cfg.OwnershipLeaseFile, got, tc.want)
		}
	}
}
