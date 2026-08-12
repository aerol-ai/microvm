package service

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func requireServiceScaleGates(t *testing.T) {
	t.Helper()
	if os.Getenv("AEROLVM_SCALE_GATES") != "1" {
		t.Skip("set AEROLVM_SCALE_GATES=1 to run large scale gates")
	}
}

func TestScaleGateIngressShardAssignmentAt10KMembers(t *testing.T) {
	requireServiceScaleGates(t)
	const members = 10_000
	known := make([]cluster.Member, 0, members)
	for i := 0; i < members; i++ {
		known = append(known, cluster.Member{
			NodeID: fmt.Sprintf("ing-%05d", i),
			Role:   config.NodeRoleIngress,
			Alive:  true,
			APIURL: fmt.Sprintf("http://10.1.%d.%d:21212", (i/256)%256, i%256),
		})
	}
	stub := &stubIngressCluster{Noop: cluster.NewNoop("ing-05000", "http://self", ""), members: known}
	filter := clusterIngressShardFilter(stub, "ing-05000")
	if filter.ShardCount != cluster.DefaultPlacementShardCount {
		t.Fatalf("shard count=%d, want %d", filter.ShardCount, cluster.DefaultPlacementShardCount)
	}
	if len(filter.Shards) == 0 {
		t.Fatal("10k ingress member assignment gave this node zero shards")
	}
	// RF=2 (primary+replica) ⇒ expected load ≈ 2*ShardCount/N ≈ 3.3; allow
	// hash skew so the gate tracks the replication factor, not RF=1's old max=3.
	const ingressRF = 2
	maxExpected := (cluster.DefaultPlacementShardCount*ingressRF)/members + 3
	if len(filter.Shards) > maxExpected {
		t.Fatalf("10k ingress member assignment too wide: got %d shards, max expected %d (RF=%d)", len(filter.Shards), maxExpected, ingressRF)
	}
}

func TestScaleGateIngressDeltaAt100KPlacements(t *testing.T) {
	requireServiceScaleGates(t)
	const placements = 100_000
	svc := &Service{
		cfg: config.Config{
			EnableCluster: true,
			Domain:        "",
		},
	}
	view := makeScalePlacements(placements)
	desired, needL4 := svc.buildClusterIngressIntents(view, "self")
	if !needL4 {
		t.Fatal("scale view with raw TCP ports did not request L4 bootstrap")
	}
	if len(desired) != placements*3 {
		t.Fatalf("desired route intents=%d, want %d", len(desired), placements*3)
	}
	ops, commit := svc.planClusterIngressDelta(desired)
	if len(ops) != len(desired) {
		t.Fatalf("initial delta ops=%d, want %d", len(ops), len(desired))
	}
	commit()

	view[placements/2].Version++
	desired, _ = svc.buildClusterIngressIntents(view, "self")
	ops, _ = svc.planClusterIngressDelta(desired)
	if len(ops) > 3 {
		t.Fatalf("one placement mutation produced %d route ops, want <=3", len(ops))
	}
}

func TestScaleGateConcurrentSealDeletePlane(t *testing.T) {
	requireServiceScaleGates(t)
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	svc := &Service{
		cfg:            config.Config{},
		cipher:         cipher,
		store:          st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster: &placementRecipientsCluster{
			Noop:       cluster.NewNoop("node-a", "http://a", ""),
			recipients: []string{"node-a", "node-b"},
			members: []cluster.Member{
				{NodeID: "node-a", Alive: true},
				{NodeID: "node-b", Alive: true},
			},
		},
		testSecretPeerPusher: &fakePeerPusher{acked: []string{"node-b"}},
	}

	const (
		lifecycleN = 100_000
		raceN      = 256
		workers    = 256
	)

	type job struct {
		id  string
		gen int64
	}
	jobs := make(chan job, workers)
	var wg sync.WaitGroup
	errCh := make(chan error, lifecycleN+raceN*8)
	now := time.Now().UTC()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				ref := secrets.FormatRef(j.id, 1)
				if err := st.PutClusterSecret(ctx, store.ClusterSecretRecord{
					Ref: ref, SandboxID: j.id, Version: 1,
					Recipients: []string{"node-a", "node-b"}, SealedPayload: []byte("sealed"),
					SealGeneration: j.gen, CreatedAt: now, UpdatedAt: now,
				}); err != nil {
					errCh <- err
					continue
				}
				if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, j.id, []string{"node-b"}); err != nil {
					errCh <- err
				}
			}
		}()
	}
	for i := 0; i < lifecycleN; i++ {
		jobs <- job{id: fmt.Sprintf("seal-del-%06d", i), gen: 1}
	}
	close(jobs)
	wg.Wait()

	// Same-sandbox delete/reseal races with real v4 envelopes.
	req := models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	var raceWG sync.WaitGroup
	for i := 0; i < raceN; i++ {
		id := fmt.Sprintf("race-%03d", i)
		handle, err := svc.SealAndDistribute(ctx, id, req, []string{"node-a", "node-b"}, SealStrict)
		if err != nil {
			t.Fatalf("race seed seal: %v", err)
		}
		blob, err := svc.loadSecretBlob(ctx, handle.Ref)
		if err != nil || blob == nil {
			t.Fatalf("race seed blob: %v", err)
		}
		gen := blob.SealGeneration
		for k := 0; k < 4; k++ {
			raceWG.Add(2)
			go func() {
				defer raceWG.Done()
				if err := svc.DeleteClusterSecretsLocal(ctx, id, gen); err != nil {
					errCh <- err
				}
			}()
			go func(b secrets.SecretBlob) {
				defer raceWG.Done()
				_ = svc.UpsertClusterSecretBlob(ctx, b)
			}(*blob)
		}
	}
	raceWG.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent secret lifecycle: %v", err)
		}
	}

	rows, err := st.ListClusterSecrets(ctx)
	if err != nil {
		t.Fatalf("list secrets after delete plane: %v", err)
	}
	for _, rec := range rows {
		if strings.HasPrefix(rec.SandboxID, "seal-del-") {
			t.Fatalf("unique lifecycle left secret row for %s", rec.SandboxID)
		}
		tomb, terr := st.HasClusterSecretTomb(ctx, rec.SandboxID)
		if terr != nil {
			t.Fatal(terr)
		}
		if !tomb && rec.SealGeneration <= 1 {
			t.Fatalf("race resurrected stale generation for %s gen=%d without tomb", rec.SandboxID, rec.SealGeneration)
		}
	}
	outbox, err := st.ListSecretDeleteOutbox(ctx)
	if err != nil {
		t.Fatalf("list delete outbox after delete plane: %v", err)
	}
	if len(outbox) < lifecycleN {
		t.Fatalf("durable delete jobs=%d, want >= %d", len(outbox), lifecycleN)
	}
	// Fair reconcile must rotate attempted rows instead of starving the tail.
	first, err := st.ListSecretDeleteOutboxBatch(ctx, 64)
	if err != nil || len(first) != 64 {
		t.Fatalf("first outbox batch len=%d err=%v", len(first), err)
	}
	for _, rec := range first {
		if err := st.BumpSecretDeleteOutboxAttempt(ctx, rec.SandboxID); err != nil {
			t.Fatal(err)
		}
	}
	second, err := st.ListSecretDeleteOutboxBatch(ctx, 64)
	if err != nil || len(second) != 64 {
		t.Fatalf("second outbox batch len=%d err=%v", len(second), err)
	}
	overlap := 0
	firstSet := map[string]struct{}{}
	for _, rec := range first {
		firstSet[rec.SandboxID] = struct{}{}
	}
	for _, rec := range second {
		if _, ok := firstSet[rec.SandboxID]; ok {
			overlap++
		}
	}
	if overlap != 0 {
		t.Fatalf("attempted outbox rows still headed the next batch: overlap=%d", overlap)
	}
}

// TestScaleGateSecretPutOutboxDrainsWithoutSilentDrop pins the durable create
// fan-out contract: incomplete peer PUTs land in put-outbox, the reconciler
// drains them, and fanout-failure metric growth without outbox is a silent-drop
// bug. Full 2k-process soak remains operator-run (make integration-cluster-*).
func TestScaleGateSecretPutOutboxDrainsWithoutSilentDrop(t *testing.T) {
	requireServiceScaleGates(t)
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	svc := &Service{
		cfg:            config.Config{},
		cipher:         cipher,
		store:          st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster: &placementRecipientsCluster{
			Noop:       cluster.NewNoop("node-a", "http://a", ""),
			recipients: []string{"node-a", "node-b"},
			members: []cluster.Member{
				{NodeID: "node-a", Alive: true},
				{NodeID: "node-b", Alive: true},
			},
		},
		// Never ACK — forces durable put-outbox for remaining peers.
		testSecretPeerPusher: &fakePeerPusher{acked: nil},
	}

	const n = 256
	beforeFailures := secretFanoutFailuresTotal.Value()
	now := time.Now().UTC()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("put-outbox-%03d", i)
		if err := st.PutClusterSecret(ctx, store.ClusterSecretRecord{
			Ref: secrets.FormatRef(id, 1), SandboxID: id, Version: 1,
			Recipients: []string{"node-a", "node-b"}, SealedPayload: []byte("sealed"),
			SealGeneration: 1, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		svc.enqueueSecretFanout(id, secrets.SecretBlob{
			SandboxID: id, Version: 1, SealGeneration: 1,
			Recipients: []string{"node-a", "node-b"}, SealedPayload: []byte("sealed"),
		}, []string{"node-a", "node-b"}, svc.testSecretPeerPusher)
	}
	deadline := time.Now().Add(10 * time.Second)
	var outbox []store.SecretPutOutboxRecord
	for {
		var err error
		outbox, err = st.ListSecretPutOutboxBatch(ctx, n+1)
		if err != nil {
			t.Fatalf("list put outbox: %v", err)
		}
		if len(outbox) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	failures := secretFanoutFailuresTotal.Value() - beforeFailures
	if failures > 0 && len(outbox) == 0 {
		t.Fatalf("fanout failures grew by %d with empty put-outbox (silent drop)", failures)
	}
	if len(outbox) == 0 {
		t.Fatal("expected durable put-outbox rows after incomplete fan-out")
	}

	svc.testSecretPeerPusher = &fakePeerPusher{acked: []string{"node-b"}}
	if err := svc.ReconcileSecretPutOutbox(ctx); err != nil {
		t.Fatalf("reconcile put outbox: %v", err)
	}
	remaining, err := st.ListSecretPutOutboxBatch(ctx, n+1)
	if err != nil {
		t.Fatalf("list put outbox after reconcile: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("put outbox remaining=%d after successful reconcile, want 0", len(remaining))
	}
}
