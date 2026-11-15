package service

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// When a worker turns off the recreate policy of a sandbox it cannot freeze
// alone, the sealed copies of its secrets on its backup nodes are retired
// with it: a delete journalled for every backup, pending pushes dropped,
// and the holder set that would re-push or reseal cleared. The owner keeps
// its own copy. Before, the policy went off and the copies stayed on the
// backups for the sandbox's life.
func TestDisarmRetiresTheBackupCopies(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	svc.SetWasmRuntime(&fakeCapacityRuntime{})
	svc.cfg.OwnershipLeaseFile = filepath.Join(t.TempDir(), "lease")
	sc := newSpecLeaseCluster(lc)
	svc.AttachCluster(sc)

	const id, inc = "wasm-ha", "inc-wasm-ha"
	seedRuntimeRow(t, st, id, models.RuntimeWasm, models.SandboxStatusStarted, true)
	sc.specs[id] = &models.CreateSandboxRequest{Image: "alpine:3.20", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	now := time.Now().UTC()
	if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref: secrets.FormatRef(id, inc, secrets.RefVersion), SandboxID: id, Version: secrets.RefVersion,
		Recipients: []string{"worker-a", "worker-b", "worker-c"}, SealedPayload: []byte("sealed"),
		SealGeneration: 2, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, id, inc, 2, []string{"worker-c"}); err != nil {
		t.Fatal(err)
	}
	setSecretHolderTargets(id, inc, 2, []string{"worker-a", "worker-b", "worker-c"})
	addSecretHolderNodes(id, inc, 2, "worker-a", "worker-b")
	t.Cleanup(func() { clearSecretFanoutHolders(id) })
	before := secretBackupsRetiredTotal.Value()

	lc.up(selfPlacement(id))
	if !svc.disarmUnfencedRecreate(ctx) {
		t.Fatal("the disarm left work to retry")
	}
	if got, _ := st.Get(ctx, id); got.Failover != nil && got.Failover.ShouldRecreate() {
		t.Fatal("policy still recreate")
	}
	job, err := st.GetSecretDeleteOutboxForIncarnation(ctx, id, inc)
	if err != nil || job == nil {
		t.Fatalf("no delete journalled for the backups: %+v err=%v", job, err)
	}
	if !slices.Equal(job.Recipients, []string{"worker-b", "worker-c"}) || job.Generation != 2 || job.AwaitingPromotion {
		t.Fatalf("delete job = %+v, want worker-b and worker-c at generation 2", job)
	}
	if put, _ := st.GetSecretPutOutboxForIncarnation(ctx, id, inc); put != nil {
		t.Fatalf("a push to a backup is still pending: %+v", put)
	}
	if own, _ := st.GetClusterSecretForSandboxIncarnation(ctx, id, inc); own == nil {
		t.Fatal("the owner's own copy was removed")
	}
	if gen := secretHolderGeneration(id, inc); gen != 0 {
		t.Fatalf("holder set still tracked at generation %d", gen)
	}
	if got := secretBackupsRetiredTotal.Value() - before; got != 2 {
		t.Fatalf("retired counter moved by %d, want 2", got)
	}
}

// A boot refan-out neither seeds holders nor retransmits for a row whose
// sandbox's recreate policy was turned off here: that would hand the retired
// backups their copy again, and a dead backup would be resealed onto a new
// node. The same row with the policy still on is retransmitted as before.
func TestRefanoutSkipsATurnedOffRecreate(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	for _, tc := range []struct {
		name     string
		recreate bool
		want     bool
	}{
		{"policy still recreate", true, true},
		{"policy turned off", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := cb96OpenStore(t)
			svc := cb96Service(st, config.Config{EnableCluster: true})
			svc.cipher = cipher
			svc.cluster = cluster.NewNoop("node-a", "http://a", "")
			svc.secretProvider = secrets.NewLocalProvider(cipher, newSecretBlobStore(st))
			id := "refan-" + map[bool]string{true: "on", false: "off"}[tc.recreate]
			if _, err := svc.putClusterSecretsForRecipientsAndIncarnation(ctx, id, cb96SecretReq(), []string{"node-a", "node-b"}, "inc"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { clearSecretFanoutHolders(id) })
			clearSecretFanoutHolders(id)
			now := time.Now().UTC()
			sb := &models.Sandbox{ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted, Runtime: models.RuntimeWasm,
				AuditIncarnationID: "inc", CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
			if tc.recreate {
				sb.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
			}
			if err := st.Create(ctx, sb); err != nil {
				t.Fatal(err)
			}
			rec, err := st.GetClusterSecretForSandboxIncarnation(ctx, id, "inc")
			if err != nil || rec == nil {
				t.Fatalf("sealed row: %+v err=%v", rec, err)
			}
			placements := map[string]cluster.Placement{id: {
				SandboxID: id, IncarnationID: "inc", OwnerNodeID: "node-a", State: cluster.PlacementStatePlaced,
				SecretRef: rec.Ref, SecretSealGeneration: rec.SealGeneration, SecretRecipients: []string{"node-a", "node-b"},
			}}
			blob, err := svc.prepareSecretRefanoutRecord(ctx, *rec, true, placements, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := blob != nil; got != tc.want {
				t.Fatalf("retransmit = %v, want %v", got, tc.want)
			}
			if seeded := secretHolderGeneration(id, "inc") != 0; seeded != tc.want {
				t.Fatalf("holders seeded = %v, want %v", seeded, tc.want)
			}
		})
	}
}

// recreateTurnedOff answers only for this node's own row in the same
// lifecycle; clearRecreateFailover reports a store failure so the disarm is
// retried, and on a single node it changes the policy alone.
func TestClearRecreateFailoverEdges(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newLeaseService(t, newFreezeRuntime())
	seedRuntimeRow(t, st, "edge-off", models.RuntimeWasm, models.SandboxStatusStarted, false)
	seedRuntimeRow(t, st, "edge-on", models.RuntimeWasm, models.SandboxStatusStarted, true)
	for _, tc := range []struct {
		id, inc string
		want    bool
	}{
		{"edge-off", "inc-edge-off", true},
		{"edge-on", "inc-edge-on", false},
		{"edge-off", "inc-other", false},
		{"missing", "inc-missing", false},
	} {
		if got := svc.recreateTurnedOff(ctx, tc.id, tc.inc); got != tc.want {
			t.Errorf("recreateTurnedOff(%s, %s) = %v, want %v", tc.id, tc.inc, got, tc.want)
		}
	}
	if (&Service{}).recreateTurnedOff(ctx, "edge-off", "inc-edge-off") {
		t.Error("a service without a store answered")
	}

	// A single node has no backups to retire: only the row changes.
	single, sst, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), newFreezeRuntime())
	seedRuntimeRow(t, sst, "solo", models.RuntimeWasm, models.SandboxStatusStarted, true)
	row, _ := sst.Get(ctx, "solo")
	if changed, err := single.clearRecreateFailover(ctx, row); err != nil || !changed {
		t.Fatalf("single node: changed=%v err=%v", changed, err)
	}

	row, _ = st.Get(ctx, "edge-on")
	_ = st.Close()
	if changed, err := svc.clearRecreateFailover(ctx, row); err == nil || changed {
		t.Fatalf("closed store: changed=%v err=%v", changed, err)
	}
}
