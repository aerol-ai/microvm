package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

// The rejoin re-fanout has two passes: a synchronous validation pass and an
// asynchronous pusher-backed scan. Only the first filtered recipients before
// forming its placement batch. The second still validated a whole page first,
// so one unrelated member restart produced fleet-wide validation work: with
// 100k HA sandboxes and three local ciphertext copies each, ~300k placement
// ids across the fleet, ~10k authoritative batch RPCs at the 32-row page size.
//
// The previous zero-work test could not see it: its stub cluster is not a
// SecretPeerPusher, so ReFanoutClusterSecretsForNodes never started the second
// pass at all. This one supplies a pusher.
func TestRejoinAsyncScanFiltersRecipientsBeforePlacementRead(t *testing.T) {
	st := openSealTestStore(t)
	cl := newRejoinAuditCluster("node-a")
	svc := &Service{
		cfg:                  config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		store:                st,
		cluster:              cl,
		testSecretPeerPusher: &fakePeerPusher{},
	}

	// 50 local secrets, none of them owed to the rejoining node.
	for i := range 50 {
		seedClusterSecretRow(t, st, fmt.Sprintf("sb-%03d", i), []string{"node-a", "node-b"})
	}

	if err := svc.ReFanoutClusterSecretsForNodes(context.Background(), map[string]struct{}{"node-rejoin": {}}); err != nil {
		t.Fatalf("refanout: %v", err)
	}
	waitForRefanoutScan(t, svc)

	auth, _ := cl.counts()
	if auth != 0 {
		t.Fatalf("authoritative placement batches = %d for zero owed secrets; the asynchronous pass validated a whole page before filtering", auth)
	}
	cl.mu.Lock()
	ids := len(cl.authBatchGotIDs)
	cl.mu.Unlock()
	if ids != 0 {
		t.Fatalf("validated %d placement ids for an unrelated rejoin; want 0", ids)
	}
}

// The shared filter must not turn into a way to skip work that IS owed: the
// asynchronous pass still has to validate and push the owed rows.
func TestRejoinAsyncScanStillPushesOwedSecrets(t *testing.T) {
	st := openSealTestStore(t)
	const owed = "sb-owed-async"
	cl := newRejoinAuditCluster("node-a")
	cl.placement = cluster.Placement{
		SandboxID: owed, OwnerNodeID: "node-a",
		IncarnationID: "inc-" + owed, SecretSealGeneration: 1,
		SecretRecipients: []string{"node-a", "node-rejoin"},
		State:            cluster.PlacementStatePlaced,
	}
	pusher := &fakePeerPusher{}
	svc := &Service{
		cfg:                  config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		store:                st,
		cluster:              cl,
		testSecretPeerPusher: pusher,
	}

	for i := range 10 {
		seedClusterSecretRow(t, st, fmt.Sprintf("sb-unrelated-%02d", i), []string{"node-a", "node-b"})
	}
	seedClusterSecretRow(t, st, owed, []string{"node-a", "node-rejoin"})

	_ = svc.ReFanoutClusterSecretsForNodes(context.Background(), map[string]struct{}{"node-rejoin": {}})
	waitForRefanoutScan(t, svc)

	cl.mu.Lock()
	got := append([]string(nil), cl.authBatchGotIDs...)
	cl.mu.Unlock()
	if len(got) == 0 {
		t.Fatal("no placement read for a secret that IS owed to the rejoining node")
	}
	for _, id := range got {
		if id != owed {
			t.Fatalf("placement batch asked for %q; only owed rows belong in the read (got %v)", id, got)
		}
	}
}

// waitForRefanoutScan blocks until the single-flight asynchronous scan is done.
func waitForRefanoutScan(t *testing.T, s *Service) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s.secretRefanoutMu.Lock()
		running := s.secretRefanoutRunning
		s.secretRefanoutMu.Unlock()
		if !running {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("asynchronous re-fanout scan did not finish")
}
