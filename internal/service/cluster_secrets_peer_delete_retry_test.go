package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
)

// laggingFSMCluster models a follower whose local FSM snapshot has not yet
// applied a placement removal the Raft leader already committed: the
// authoritative read is empty while PlacementsByIDs still returns the old
// lifecycle. Peer-PUT validation reads the local snapshot; a peer DELETE must
// therefore treat the same snapshot as the last evidence that can fence it.
type laggingFSMCluster struct {
	*cluster.Noop
	authoritative map[string]cluster.Placement
	local         map[string]cluster.Placement
	localNil      bool
}

func (c *laggingFSMCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.authoritative[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

func (c *laggingFSMCluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	if c.localNil {
		return nil
	}
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.local[id]; ok {
			out[id] = p
		}
	}
	return out
}

func (c *laggingFSMCluster) PlacementOf(id string) (cluster.Placement, bool) {
	p, ok := c.local[id]
	return p, ok
}

// A peer DELETE that already succeeded loses both pieces of evidence the
// authorizer consults — the ciphertext row (deleted by the first apply) and
// the authoritative placement (removed when the sandbox was destroyed). The
// originator's durable outbox retries the identical request after a lost ACK;
// refusing it strands the outbox row and the originator's tomb forever.
func TestPeerDeleteRetryAfterLostAckIsAcknowledgedFromTomb(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	const sandboxID, incarnationID = "sb-peer-retry", "inc-retry"
	putSecretRow(t, st, sandboxID, incarnationID, 3, []string{"node-a", "node-b"})
	cl := &placementOnlyCluster{
		Noop: cluster.NewNoop("node-b", "http://b", ""),
		placement: cluster.Placement{
			SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: incarnationID,
			SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 3,
		},
	}
	svc := &Service{cfg: config.Config{EnableCluster: true}, store: st, cluster: cl}

	if err := svc.DeleteClusterSecretsLocal(ctx, sandboxID, incarnationID, 3, "node-a"); err != nil {
		t.Fatalf("first peer delete: %v", err)
	}
	if _, err := st.GetClusterSecretForSandboxIncarnation(ctx, sandboxID, incarnationID); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("ciphertext remains after acknowledged delete: %v", err)
	}
	tombBefore, err := st.ClusterSecretTombGenerationForIncarnation(ctx, sandboxID, incarnationID)
	if err != nil || tombBefore != 3 {
		t.Fatalf("tomb after first delete = %d err=%v, want 3", tombBefore, err)
	}

	// The ACK was lost; meanwhile the destroy finished and the placement is gone.
	cl.placement = cluster.Placement{}
	if err := svc.DeleteClusterSecretsLocal(ctx, sandboxID, incarnationID, 3, "node-a"); err != nil {
		t.Fatalf("retry after lost ACK must be acknowledged, got %v", err)
	}
	// A retry with a lower generation (an older outbox row) is equally covered.
	if err := svc.DeleteClusterSecretsLocal(ctx, sandboxID, incarnationID, 2, "node-a"); err != nil {
		t.Fatalf("older-generation retry must be acknowledged, got %v", err)
	}
	tombAfter, err := st.ClusterSecretTombGenerationForIncarnation(ctx, sandboxID, incarnationID)
	if err != nil || tombAfter != tombBefore {
		t.Fatalf("idempotent retry changed the tomb: before=%d after=%d err=%v", tombBefore, tombAfter, err)
	}
}

// The same evidence gap exists on the very first attempt when the fan-out
// DELETE lands after the placement removal on a peer that never received the
// PUT (the put-outbox still listed it). With nothing local and no lifecycle
// anywhere, nothing can land later either: acknowledge without minting a tomb
// on an unauthenticated say-so.
func TestPeerDeleteWithoutLocalStateOrLifecycleIsAcknowledgedWithoutTomb(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	const sandboxID, incarnationID = "sb-peer-never-put", "inc-never"
	cl := &laggingFSMCluster{Noop: cluster.NewNoop("node-b", "http://b", "")}
	svc := &Service{cfg: config.Config{EnableCluster: true}, store: st, cluster: cl}

	if err := svc.DeleteClusterSecretsLocal(ctx, sandboxID, incarnationID, 1, "node-a"); err != nil {
		t.Fatalf("delete with no local state and no lifecycle must be acknowledged, got %v", err)
	}
	if gen, err := st.ClusterSecretTombGenerationForIncarnation(ctx, sandboxID, incarnationID); err != nil || gen != 0 {
		t.Fatalf("acknowledging an unauthenticated delete must not mint a tomb: gen=%d err=%v", gen, err)
	}

	// An ID reused by a new lifecycle is the same situation for the old one.
	cl.authoritative = map[string]cluster.Placement{sandboxID: {
		SandboxID: sandboxID, OwnerNodeID: "node-c", IncarnationID: "inc-replacement",
	}}
	cl.local = cl.authoritative
	if err := svc.DeleteClusterSecretsLocal(ctx, sandboxID, incarnationID, 1, "node-a"); err != nil {
		t.Fatalf("delete for a superseded incarnation must be acknowledged, got %v", err)
	}
	if gen, err := st.ClusterSecretTombGenerationForIncarnation(ctx, sandboxID, incarnationID); err != nil || gen != 0 {
		t.Fatalf("superseded incarnation acknowledged with a tomb: gen=%d err=%v", gen, err)
	}
}

// A lagging follower still lets a PUT through validatePeerSecretBlob while its
// local snapshot shows the lifecycle live, so the DELETE must still be fenced
// (tomb) and still authorized against that snapshot while it lasts.
func TestPeerDeleteAuthorizesAgainstLaggingLocalSnapshot(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	const sandboxID, incarnationID = "sb-peer-lag", "inc-lag"
	live := cluster.Placement{
		SandboxID: sandboxID, OwnerNodeID: "node-a", IncarnationID: incarnationID,
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 1,
	}
	cl := &laggingFSMCluster{
		Noop:  cluster.NewNoop("node-b", "http://b", ""),
		local: map[string]cluster.Placement{sandboxID: live},
	}
	svc := &Service{cfg: config.Config{EnableCluster: true}, store: st, cluster: cl}

	if err := svc.DeleteClusterSecretsLocal(ctx, sandboxID, incarnationID, 1, "node-intruder"); !errors.Is(err, ErrClusterSecretOriginatorDenied) {
		t.Fatalf("foreign peer against a live local snapshot = %v, want denied", err)
	}
	if gen, err := st.ClusterSecretTombGenerationForIncarnation(ctx, sandboxID, incarnationID); err != nil || gen != 0 {
		t.Fatalf("denied delete minted a tomb: gen=%d err=%v", gen, err)
	}
	if err := svc.DeleteClusterSecretsLocal(ctx, sandboxID, incarnationID, 1, "node-a"); err != nil {
		t.Fatalf("owner against a live local snapshot: %v", err)
	}
	if gen, err := st.ClusterSecretTombGenerationForIncarnation(ctx, sandboxID, incarnationID); err != nil || gen != 1 {
		t.Fatalf("owner delete must fence the lagging lifecycle: gen=%d err=%v", gen, err)
	}

	// An unreadable local snapshot is unavailability, not absence.
	cl.local = nil
	cl.localNil = true
	if err := svc.DeleteClusterSecretsLocal(ctx, "sb-peer-lag-2", "inc-lag-2", 1, "node-a"); !errors.Is(err, ErrClusterSecretPlacementUnavailable) {
		t.Fatalf("nil local snapshot = %v, want placement unavailable", err)
	}
}
