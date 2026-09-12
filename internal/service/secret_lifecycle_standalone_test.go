package service

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// A node that left a cluster (cluster mode off, no peer transport) still holds
// the rows it wrote as a member. Nothing here can ever be sent to a peer, so
// the reconciler must retire it — after the grace — instead of leaking it
// forever, while never touching what a live local sandbox still needs.

func standaloneLifecycleService(t *testing.T, grace time.Duration) (*Service, *storepkg.Store) {
	t.Helper()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := &Service{
		cfg:     config.Config{SecretOutboxStandaloneGrace: grace, SecretTombRetentionDays: 1},
		store:   st,
		cluster: cluster.NewNoop("self", "http://self", ""), // a standalone daemon's client: no pusher
	}
	return svc, st
}

func seedPeerObligations(t *testing.T, st *storepkg.Store) {
	t.Helper()
	ctx := context.Background()
	// Destroyed-while-clustered: tomb + delete obligation to two peers.
	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-deleted", "inc-d", []string{"peer-a", "peer-b"}); err != nil {
		t.Fatal(err)
	}
	// Replication still pending to a peer when the node left.
	if err := st.UpsertSecretPutOutbox(ctx, "sb-pending", "inc-p", 1, []string{"self", "peer-c"}); err != nil {
		t.Fatal(err)
	}
}

func lifecycleCounts(t *testing.T, st *storepkg.Store) (deletes, puts int64, tombs int64) {
	t.Helper()
	stats, err := st.SecretLifecycleStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return stats.OutboxPending, stats.PutOutboxPending, stats.Tombstones
}

func TestStandaloneReconcileRetiresPeerObligationsAfterGrace(t *testing.T) {
	svc, st := standaloneLifecycleService(t, time.Hour)
	seedPeerObligations(t, st)
	ctx := context.Background()
	if svc.secretPeerPusher() != nil {
		t.Fatal("test setup: a standalone service must have no peer pusher")
	}
	if d, p, tombs := lifecycleCounts(t, st); d != 1 || p != 1 || tombs != 1 {
		t.Fatalf("seed = deletes %d puts %d tombs %d", d, p, tombs)
	}
	// Within the grace: everything is kept (a brief cluster-off restart).
	base := time.Now().UTC()
	secretLifecycleNow = func() time.Time { return base.Add(30 * time.Minute) }
	t.Cleanup(func() { secretLifecycleNow = time.Now })
	retiredBefore := secretDeleteOutboxRetiredStandalone.Value()
	if err := svc.ReconcileSecretDeleteOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReconcileSecretPutOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	if d, p, _ := lifecycleCounts(t, st); d != 1 || p != 1 {
		t.Fatalf("within grace: deletes %d puts %d, want both kept", d, p)
	}
	if secretDeleteOutboxRetiredStandalone.Value() != retiredBefore {
		t.Fatal("nothing should have been counted as retired within the grace")
	}
	// Past the grace: both obligations are retired and counted; the tomb
	// stays (it is a delete fence, pruned by its own retention).
	secretLifecycleNow = func() time.Time { return base.Add(2 * time.Hour) }
	putsBefore := secretPutOutboxRetiredStandalone.Value()
	if err := svc.ReconcileSecretDeleteOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	if d, p, tombs := lifecycleCounts(t, st); d != 0 || p != 0 || tombs != 1 {
		t.Fatalf("past grace: deletes %d puts %d tombs %d, want 0/0/1", d, p, tombs)
	}
	if secretDeleteOutboxRetiredStandalone.Value() != retiredBefore+1 || secretPutOutboxRetiredStandalone.Value() != putsBefore+1 {
		t.Fatal("retirements not counted")
	}
	// The tomb is no longer pinned by an outbox row: retention prunes it.
	secretLifecycleNow = time.Now
	if _, err := st.PruneClusterSecretTombs(ctx, time.Now().UTC().Add(time.Minute), 100); err != nil {
		t.Fatal(err)
	}
	if _, _, tombs := lifecycleCounts(t, st); tombs != 0 {
		t.Fatalf("tomb survived after its outbox was retired: %d", tombs)
	}
	// Idempotent and quiet when there is nothing left.
	if err := svc.ReconcileSecretDeleteOutbox(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStandaloneReconcileZeroGraceRetiresImmediatelyAndPagesOldestFirst(t *testing.T) {
	svc, st := standaloneLifecycleService(t, 0)
	ctx := context.Background()
	// More rows than one page, all past a zero grace.
	for i := range secretDeleteReconcileBatch + 5 {
		if err := st.UpsertSecretDeleteOutbox(ctx, "sb-"+strconv.Itoa(i), "inc", []string{"peer-x"}, 1); err != nil {
			t.Fatal(err)
		}
	}
	// The zero grace compares against "now"; rows written this instant have
	// updated_at == now and must count as retirable, so advance the clock a hair.
	secretLifecycleNow = func() time.Time { return time.Now().Add(time.Second) }
	t.Cleanup(func() { secretLifecycleNow = time.Now })
	if err := svc.ReconcileSecretDeleteOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := lifecycleCounts(t, st); d != 0 {
		t.Fatalf("zero grace left %d delete obligations", d)
	}
}

// Cluster mode with the transport not yet attached keeps every row: only a
// node that is genuinely standalone gives obligations up.
func TestClusterModeWithoutTransportKeepsObligations(t *testing.T) {
	svc, st := standaloneLifecycleService(t, 0)
	svc.cfg.EnableCluster = true
	seedPeerObligations(t, st)
	secretLifecycleNow = func() time.Time { return time.Now().Add(48 * time.Hour) }
	t.Cleanup(func() { secretLifecycleNow = time.Now })
	ctx := context.Background()
	if err := svc.ReconcileSecretDeleteOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReconcileSecretPutOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	if d, p, _ := lifecycleCounts(t, st); d != 1 || p != 1 {
		t.Fatalf("cluster mode without transport retired rows: deletes %d puts %d", d, p)
	}
}

// Sealed rows for sandboxes this standalone node no longer has are orphaned
// ciphertext; rows for live local sandboxes (exact lifecycle) are kept.
func TestStandaloneRetirementScanTombsOrphanedCiphertextOnly(t *testing.T) {
	svc, st := standaloneLifecycleService(t, time.Hour)
	ctx := context.Background()
	now := time.Now().UTC()
	live := &models.Sandbox{ID: "sb-live", Image: "alpine", Status: models.SandboxStatusStarted, CPU: 1, MemoryMB: 128,
		Runtime: models.RuntimeDocker, AuditIncarnationID: "inc-live", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
	if err := st.Create(ctx, live); err != nil {
		t.Fatal(err)
	}
	reused := &models.Sandbox{ID: "sb-reused", Image: "alpine", Status: models.SandboxStatusStarted, CPU: 1, MemoryMB: 128,
		Runtime: models.RuntimeDocker, AuditIncarnationID: "inc-new", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
	if err := st.Create(ctx, reused); err != nil {
		t.Fatal(err)
	}
	seal := func(sb, inc string) {
		if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
			Ref: secrets.FormatRef(sb, inc, secrets.RefVersion), SandboxID: sb, Version: secrets.RefVersion,
			Recipients: []string{"self", "peer-a"}, SealedPayload: []byte("sealed"), SealGeneration: 1,
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	seal("sb-live", "inc-live")  // live, exact lifecycle: keep
	seal("sb-reused", "inc-old") // sandbox exists under a newer lifecycle: orphan
	seal("sb-gone", "inc-gone")  // no sandbox row: orphan
	retiredBefore := secretCiphertextRetiredTotal.Value()

	// Within the grace nothing moves.
	secretLifecycleNow = func() time.Time { return now.Add(10 * time.Minute) }
	t.Cleanup(func() { secretLifecycleNow = time.Now })
	if err := svc.runSecretRetirementScan(ctx); err != nil {
		t.Fatal(err)
	}
	for _, sb := range []string{"sb-live", "sb-reused", "sb-gone"} {
		if _, err := st.GetClusterSecretForSandboxIncarnation(ctx, sb, map[string]string{"sb-live": "inc-live", "sb-reused": "inc-old", "sb-gone": "inc-gone"}[sb]); err != nil {
			t.Fatalf("%s retired within the grace: %v", sb, err)
		}
	}
	// Past the grace the orphans are tombed with a peer-delete obligation,
	// the live row is untouched.
	secretLifecycleNow = func() time.Time { return now.Add(2 * time.Hour) }
	if err := svc.runSecretRetirementScan(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetClusterSecretForSandboxIncarnation(ctx, "sb-live", "inc-live"); err != nil {
		t.Fatalf("live sandbox's ciphertext retired: %v", err)
	}
	for sb, inc := range map[string]string{"sb-reused": "inc-old", "sb-gone": "inc-gone"} {
		if _, err := st.GetClusterSecretForSandboxIncarnation(ctx, sb, inc); err == nil {
			t.Fatalf("orphan %s/%s still sealed", sb, inc)
		}
		if gen, err := st.ClusterSecretTombGenerationForIncarnation(ctx, sb, inc); err != nil || gen == 0 {
			t.Fatalf("orphan %s/%s not tombed: gen %d err %v", sb, inc, gen, err)
		}
		outbox, err := st.GetSecretDeleteOutboxForIncarnation(ctx, sb, inc)
		if err != nil || outbox == nil || len(outbox.Recipients) != 1 || outbox.Recipients[0] != "peer-a" {
			t.Fatalf("orphan %s/%s peer-delete obligation = %+v err %v", sb, inc, outbox, err)
		}
	}
	if secretCiphertextRetiredTotal.Value() != retiredBefore+2 {
		t.Fatalf("ciphertext retirements counted = %d, want +2", secretCiphertextRetiredTotal.Value()-retiredBefore)
	}
	// Those fresh obligations then age out like any other standalone row.
	secretLifecycleNow = func() time.Time { return time.Now().Add(3 * time.Hour) }
	if err := svc.ReconcileSecretDeleteOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	if d, _, tombs := lifecycleCounts(t, st); d != 0 || tombs != 2 {
		t.Fatalf("after retirement: deletes %d tombs %d, want 0/2", d, tombs)
	}
	// The scan is idempotent once everything is settled.
	if err := svc.runSecretRetirementScan(ctx); err != nil {
		t.Fatal(err)
	}
	if secretCiphertextRetiredTotal.Value() != retiredBefore+2 {
		t.Fatal("second scan retired again")
	}
}

// The maintenance loop starts standalone too: the boot pass runs the
// retirements with a pre-cancelled context (no 30s ticker wait).
func TestStandaloneLifecycleLoopRunsBootPass(t *testing.T) {
	svc, st := standaloneLifecycleService(t, 0)
	seedPeerObligations(t, st)
	secretLifecycleNow = func() time.Time { return time.Now().Add(time.Second) }
	t.Cleanup(func() { secretLifecycleNow = time.Now })
	ctx := context.Background()
	if err := svc.ReconcileSecretDeleteOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	loopCtx, cancel := context.WithCancel(ctx)
	cancel()
	svc.StartSecretDeleteOutboxReconcile(loopCtx)
	time.Sleep(20 * time.Millisecond)
	if d, p, _ := lifecycleCounts(t, st); d != 0 || p != 0 {
		t.Fatalf("standalone boot pass left deletes %d puts %d", d, p)
	}
	// Nil-safety and the storeless guard.
	if err := (&Service{}).retireStandaloneSecretOutbox(ctx); err != nil {
		t.Fatal(err)
	}
	if err := (*Service)(nil).retireStandaloneSecretOutbox(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStandaloneReconcileSurfacesStoreErrors(t *testing.T) {
	svc, st := standaloneLifecycleService(t, 0)
	seedPeerObligations(t, st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReconcileSecretDeleteOutbox(context.Background()); err == nil {
		t.Fatal("closed store did not surface")
	}
	if err := svc.runSecretRetirementScan(context.Background()); err == nil {
		t.Fatal("closed store did not surface from the retirement scan")
	}
}
