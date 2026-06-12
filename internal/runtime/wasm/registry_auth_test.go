package wasm

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// authRecordingResolver records the per-tenant creds passed to ResolveWithAuth
// so the failover auth-threading (codex C4) can be asserted without a registry.
type authRecordingResolver struct {
	path      string
	digest    string
	gotAuth   *wasmmod.ModuleAuth
	withAuth  bool
	plainCall bool
}

func (r *authRecordingResolver) Resolve(_ context.Context, ref string) (*wasmmod.ResolvedModule, error) {
	r.plainCall = true
	return &wasmmod.ResolvedModule{Ref: ref, Path: r.path, Digest: r.digest, SizeBytes: 1}, nil
}

func (r *authRecordingResolver) ResolveWithAuth(_ context.Context, ref string, a *wasmmod.ModuleAuth) (*wasmmod.ResolvedModule, error) {
	r.withAuth = true
	r.gotAuth = a
	return &wasmmod.ResolvedModule{Ref: ref, Path: r.path, Digest: r.digest, SizeBytes: 1}, nil
}

// A sandbox carrying unsealed tenant creds resolves its module via
// ResolveWithAuth under those exact creds — so a failover peer pulls a private
// module as the tenant, not anonymously (codex C4).
func TestResolvePinnedThreadsTenantAuth(t *testing.T) {
	res := &authRecordingResolver{path: "/tmp/m.wasm", digest: "pinned123"}
	d := &Driver{resolver: res}

	sandbox := &models.Sandbox{
		ID:           "sb-priv",
		ModuleRef:    "oci://aocr.aerol.ai/tenant/app:latest",
		ModuleDigest: "pinned123",
		RegistryAuth: &models.RegistryAuth{Username: "tenant-bob", Password: "tenant-pat-xyz"},
	}

	_, err := d.resolvePinned(context.Background(), sandbox.ModuleRef, sandbox.ModuleDigest, moduleAuthFromSandbox(sandbox))
	if err != nil {
		t.Fatalf("resolvePinned: %v", err)
	}
	if !res.withAuth {
		t.Fatal("expected ResolveWithAuth to be used when sandbox carries tenant creds")
	}
	if res.gotAuth == nil || res.gotAuth.Username != "tenant-bob" || res.gotAuth.PAT != "tenant-pat-xyz" {
		t.Fatalf("tenant creds not threaded: %+v", res.gotAuth)
	}
}

// A sandbox with no creds resolves plainly (public/standard module, or the
// resolver's own system identity).
func TestResolvePinnedNoAuthFallsBackToPlain(t *testing.T) {
	res := &authRecordingResolver{path: "/tmp/m.wasm", digest: "d1"}
	d := &Driver{resolver: res}

	sandbox := &models.Sandbox{ID: "sb-pub", ModuleRef: "python", ModuleDigest: "d1"}
	if got := moduleAuthFromSandbox(sandbox); got != nil {
		t.Fatalf("expected nil auth for credential-less sandbox, got %+v", got)
	}
	if _, err := d.resolvePinned(context.Background(), sandbox.ModuleRef, sandbox.ModuleDigest, moduleAuthFromSandbox(sandbox)); err != nil {
		t.Fatal(err)
	}
	if res.withAuth {
		t.Fatal("must not call ResolveWithAuth without creds")
	}
	if !res.plainCall {
		t.Fatal("expected plain Resolve")
	}
}
