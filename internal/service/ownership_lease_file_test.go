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

// A recreate-policy sandbox created between reads joins the fence at once,
// under the same read: a sandboxd that dies before its next read still
// leaves it for the supervisor to freeze. Nothing is written before this
// process's first read.
func TestOwnershipLeaseFileFollowsCreates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	path := filepath.Join(t.TempDir(), "ownership-lease")
	svc.cfg.OwnershipLeaseFile = path
	go svc.runOwnershipLeaseFileWriter(ctx)

	seedLeaseRow(t, st, "a", true, models.SandboxStatusStarted)
	svc.kickOwnershipLeaseFile()
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("written before any read: %v", err)
	}

	lc.up(selfPlacement("a"))
	sent := time.Now()
	if err := svc.confirmOwnership(ctx, sent); err != nil {
		t.Fatal(err)
	}
	seedLeaseRow(t, st, "d", true, models.SandboxStatusStarted)
	svc.kickOwnershipLeaseFile()
	svc.kickOwnershipLeaseFile() // a second kick while one waits is dropped
	deadline := time.Now().Add(5 * time.Second)
	for {
		l := readLeaseFile(t, path)
		if slices.Contains(l.Fence, "ctr-d") {
			if l.ConfirmedUnixMs != sent.UnixMilli() || !slices.Equal(l.Owned, []string{"ctr-a"}) {
				t.Fatalf("the rewrite changed the read: %+v", l)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ctr-d never joined the fence: %+v", l)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Off in single-node mode and without the setting; a failed write is
// counted and logged, and the next read writes again.
func TestOwnershipLeaseFileOffAndFailures(t *testing.T) {
	ctx := context.Background()
	single, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), newFreezeRuntime())
	single.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "ownership-lease")
	single.kickOwnershipLeaseFile()
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

	// The writer skips a kick it cannot list the sandboxes for.
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "ownership-lease")
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { svc.runOwnershipLeaseFileWriter(wctx); close(done) }()
	_ = st.Close()
	svc.kickOwnershipLeaseFile()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if _, err := os.Stat(svc.cfg.OwnershipLeaseFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("written without the sandbox list: %v", err)
	}
}

// StartOwnershipLease starts the writer with the setting on.
func TestStartOwnershipLeaseStartsTheFileWriter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	path := filepath.Join(t.TempDir(), "ownership-lease")
	svc.cfg.OwnershipLeaseFile = path
	svc.StartOwnershipLease(ctx)
	if err := svc.confirmOwnership(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	seedLeaseRow(t, st, "e", true, models.SandboxStatusStarted)
	lc.up(selfPlacement("e"))
	svc.kickOwnershipLeaseFile()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if l, err := ownerlease.Read(path); err == nil && slices.Contains(l.Fence, "ctr-e") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the writer StartOwnershipLease started never rewrote the file")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Persisting a recreate-policy sandbox queues a rewrite; any other does not.
func TestPersistSandboxCreateKicksTheLeaseFile(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newLeaseService(t, newFreezeRuntime())
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "ownership-lease")
	now := time.Now().UTC()
	for _, tc := range []struct {
		id       string
		recreate bool
		kicks    int
	}{{"plain", false, 0}, {"moves", true, 1}} {
		sb := &models.Sandbox{ID: tc.id, Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
			ContainerID: "ctr-" + tc.id, AuditIncarnationID: "inc-" + tc.id, CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
			CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
		if tc.recreate {
			sb.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
		}
		if err := svc.persistSandboxCreate(ctx, sb); err != nil {
			t.Fatal(err)
		}
		if got := len(svc.ownershipFile.kicks()); got != tc.kicks {
			t.Fatalf("%s: %d kicks queued, want %d", tc.id, got, tc.kicks)
		}
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
