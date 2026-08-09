package service

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
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
		cfg:            config.Config{SecretRecipientFanoutEnabled: true},
		cipher:         cipher,
		store:          st,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:        cluster.NewNoop("node-a", "http://a", ""),
	}
	const n = 1000
	var wg sync.WaitGroup
	errCh := make(chan error, n*2)
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("seal-del-%04d", i)
			req := models.CreateSandboxRequest{
				Image:    "alpine",
				Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
				Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
			}
			if _, err := svc.SealAndDistribute(ctx, id, req, []string{"node-a", "node-b"}, SealStrict); err != nil {
				errCh <- err
				return
			}
			if err := svc.DeleteClusterSecrets(ctx, id); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent seal/delete: %v", err)
	}
}
