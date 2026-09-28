package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

// A node that was a cluster member boots standalone (SB_ENABLE_CLUSTER=false)
// with peer obligations it can never send. Before, the lifecycle reconciler
// was wired only inside the cluster branch and those rows leaked forever; now
// the standalone boot pass retires them (zero grace here so the test does not
// wait an hour).
func TestRunStandaloneBootRetiresStrandedPeerObligations(t *testing.T) {
	paths := setBaseRunEnv(t)
	t.Setenv("SB_ENABLE_CLUSTER", "false")
	t.Setenv("SB_SECRET_OUTBOX_STANDALONE_GRACE", "0s")

	// What a cluster member leaves behind: a destroy's tomb + peer-delete
	// obligation, and a replication PUT still owed to a peer.
	seed, err := store.Open(paths.dbPath)
	if err != nil {
		t.Fatalf("seed store: %v", err)
	}
	ctx := context.Background()
	if _, err := seed.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-clustered", "inc-1", []string{"peer-a", "peer-b"}); err != nil {
		t.Fatal(err)
	}
	if err := seed.UpsertSecretPutOutbox(ctx, "sb-pending", "inc-2", 1, []string{"peer-c"}); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	// Rows carry updated_at = now; a zero grace retires rows not newer than
	// "now", so give the clock a moment before the daemon reads them.
	time.Sleep(1100 * time.Millisecond)

	if err := runWithAutoCancel(t, 700*time.Millisecond, nil); err != nil {
		t.Fatalf("Run standalone: %v", err)
	}

	after, err := store.Open(paths.dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = after.Close() })
	stats, err := after.SecretLifecycleStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.OutboxPending != 0 || stats.PutOutboxPending != 0 {
		t.Fatalf("standalone boot left deletes=%d puts=%d stranded", stats.OutboxPending, stats.PutOutboxPending)
	}
	if stats.Tombstones != 1 {
		t.Fatalf("tombstone = %d, want the delete fence kept for its own retention", stats.Tombstones)
	}
}
