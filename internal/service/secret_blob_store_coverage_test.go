package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestOpenClusterSecretsRemainingGuards(t *testing.T) {
	ctx := context.Background()
	req := models.CreateSandboxRequest{Image: "alpine", Registry: &models.RegistryAuth{Server: "ghcr.io", Username: "u"}}
	out, err := (*Service)(nil).OpenClusterSecretsForNode(ctx, "sb", req, cluster.PlacementSecrets{}, "node-a")
	if err != nil || out.Image != "alpine" {
		t.Fatalf("empty handle = %+v %v", out, err)
	}

	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	svc := &Service{store: st, cipher: cipher, secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st))}
	bad := cluster.PlacementSecrets{Ref: "not-a-ref", Version: secrets.RefVersion, SealGeneration: 1, IncarnationID: "inc-a"}
	if _, err := svc.OpenClusterSecretsForNode(ctx, "sb", req, bad, ""); err == nil {
		t.Fatal("invalid handle was accepted")
	}

	ref := secrets.FormatRef("sb-open31", "inc-a", secrets.RefVersion)
	handle := cluster.PlacementSecrets{Ref: ref, Version: secrets.RefVersion, SealGeneration: 1, IncarnationID: "inc-a"}
	if _, err := (&Service{store: st}).OpenClusterSecretsForNode(ctx, "", req, handle, "node-a"); err == nil {
		t.Fatal("nil provider was accepted")
	}
	if _, err := svc.OpenClusterSecretsForNode(ctx, "sb-open31", req, handle, "node-a"); err == nil {
		t.Fatal("missing blob open succeeded")
	}

	blob := wave30BoundBlob(t, cipher, "sb-open31", "inc-a", []string{"node-a"}, 1)
	if err := newSecretBlobStore(st).Put(ctx, blob); err != nil {
		t.Fatal(err)
	}
	got, err := svc.OpenClusterSecretsForNode(ctx, "", req, handle, "node-a")
	if err != nil {
		t.Fatalf("open by ref: %v", err)
	}
	if got.Registry == nil || got.Registry.Password != "p" {
		t.Fatalf("merged secrets = %+v", got.Registry)
	}
}

func TestSecretBlobStoreAdapterGuards(t *testing.T) {
	ctx := context.Background()
	if newSecretBlobStore(nil) != nil {
		t.Fatal("nil store adapter")
	}
	st := openSealTestStore(t)
	a := newSecretBlobStore(st).(secretBlobStoreAdapter)
	if err := a.Put(ctx, secrets.SecretBlob{Ref: "bad", SandboxID: "sb", IncarnationID: "inc", Version: 1, SealGeneration: 1}); err == nil {
		t.Fatal("invalid put identity")
	}
	if _, err := a.Get(ctx, secrets.FormatRef("missing", "inc", secrets.RefVersion)); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing get = %v", err)
	}
	if err := a.DeleteForSandbox(ctx, "sb"); err == nil {
		t.Fatal("delete without incarnation")
	}
	if _, err := a.NextSealGeneration(ctx, "sb"); err == nil {
		t.Fatal("next gen without incarnation")
	}
	inc := secrets.ContextWithIncarnationID(ctx, "inc-a")
	if err := a.DeleteForSandbox(inc, "missing"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	gen, err := a.NextSealGeneration(inc, "sb-next31")
	if err != nil || gen < 1 {
		t.Fatalf("next gen = %d %v", gen, err)
	}
	_ = st.Close()
	if _, err := a.Get(ctx, secrets.FormatRef("sb", "inc", secrets.RefVersion)); err == nil {
		t.Fatal("closed get succeeded")
	}
}
