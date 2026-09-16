package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// A reseal stages generation G+1 on its replacement recipients before the Raft
// CAS. A replacement that was already a backup holds one row per ref, so the
// staged PUT overwrites its committed G copy. If the owner dies before the
// CAS, Raft still hands out G and the surviving backup must be able to open
// the staged bytes it holds for that same lifecycle — otherwise failover is
// stranded on "generation mismatch: placement=1 store=2" while the plaintext
// is sitting on disk.
func TestOpenClusterSecretsForNodeTakesOverStagedResealGeneration(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	const sandboxID, incarnationID = "sb-staged-takeover", "inc-staged"
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, cipher: cipher, store: st,
		cluster:        cluster.NewNoop("node-b", "http://b", ""),
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	req := models.CreateSandboxRequest{
		Image:    "private.example.com/app:latest",
		Registry: &models.RegistryAuth{Server: "private.example.com", Username: "u", Password: "committed-password"},
	}
	committed, err := svc.sealAndDistributeForIncarnation(ctx, sandboxID, req, []string{"node-a", "node-b"}, incarnationID)
	if err != nil {
		t.Fatalf("seal committed generation: %v", err)
	}
	if committed.SealGeneration != 1 {
		t.Fatalf("committed generation = %d, want 1", committed.SealGeneration)
	}
	redacted := RedactClusterSecrets(req)
	if _, err := svc.OpenClusterSecretsForNode(ctx, sandboxID, redacted, committed, "node-b"); err != nil {
		t.Fatalf("open committed generation: %v", err)
	}

	// The owner (node-a) reseals for a dead backup: G+1 lands on node-b with
	// the replacement recipient set and overwrites its G row. The owner then
	// dies before promoting it, so the placement handle still says G.
	sealCtx := secrets.ContextWithIncarnationID(ctx, incarnationID)
	staged, err := svc.secretProvider.Put(sealCtx, sandboxID, secretsFromRequest(req), []string{"node-a", "node-b", "node-c"})
	if err != nil {
		t.Fatalf("stage reseal: %v", err)
	}
	if staged.Ref != committed.Ref || staged.SealGeneration != committed.SealGeneration+1 {
		t.Fatalf("staged handle = %+v, want same ref at generation %d", staged, committed.SealGeneration+1)
	}
	if _, err := svc.provider().Open(sealCtx, sandboxID, secrets.Handle{
		Ref: committed.Ref, Version: committed.Version, SealGeneration: committed.SealGeneration,
	}, "node-b"); !errors.Is(err, secrets.ErrVersionMismatch) {
		t.Fatalf("precondition: provider must still refuse the stale handle, got %v", err)
	}

	merged, err := svc.OpenClusterSecretsForNode(ctx, sandboxID, redacted, committed, "node-b")
	if err != nil {
		t.Fatalf("failover open of a staged reseal must succeed, got %v", err)
	}
	if merged.Registry == nil || merged.Registry.Password != "committed-password" {
		t.Fatalf("staged takeover lost the credential: %+v", merged.Registry)
	}

	// The takeover is only for a node the staged envelope names. node-d never
	// was a recipient of either generation and must still be refused.
	if _, err := svc.OpenClusterSecretsForNode(ctx, sandboxID, redacted, committed, "node-d"); err == nil {
		t.Fatal("non-recipient opened a staged reseal generation")
	}
	// A retired recipient of G that the reseal dropped holds the new bytes
	// only if the PUT reached it; node-a is in both sets here, so the guard is
	// exercised through node-e, which is in neither.
	if _, err := svc.OpenClusterSecretsForNode(ctx, sandboxID, redacted, committed, "node-e"); err == nil {
		t.Fatal("stranger opened a staged reseal generation")
	}
}

// Standalone mode never reseals and never fails over: the strict generation
// check stays as-is so a stale handle is still an error there.
func TestOpenClusterSecretsForNodeKeepsStrictGenerationOutsideCluster(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	const sandboxID, incarnationID = "sb-strict-standalone", "inc-strict"
	svc := &Service{
		cipher: cipher, store: st,
		cluster:        cluster.NewNoop("node-a", "http://a", ""),
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
	}
	req := models.CreateSandboxRequest{Image: "alpine", Env: map[string]string{"TOKEN": "t"}}
	committed, err := svc.sealAndDistributeForIncarnation(ctx, sandboxID, req, []string{"node-a"}, incarnationID)
	if err != nil {
		t.Fatal(err)
	}
	sealCtx := secrets.ContextWithIncarnationID(ctx, incarnationID)
	if _, err := svc.secretProvider.Put(sealCtx, sandboxID, secretsFromRequest(req), []string{"node-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.OpenClusterSecretsForNode(ctx, sandboxID, RedactClusterSecrets(req), committed, "node-a"); !errors.Is(err, secrets.ErrVersionMismatch) {
		t.Fatalf("standalone stale handle = %v, want version mismatch", err)
	}
}
