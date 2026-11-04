package service

import (
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A tenant must not be able to boot a sandbox from, or co-own, another tenant's
// JS bundle by naming its content digest; and deleting a bundle must not leak
// (or be blocked by) another tenant's sandbox.
func TestJSBundle_DigestOwnerScoping(t *testing.T) {
	svc := newBundleService(t)
	svc.SetIsolateRuntime(&recordingRuntime{})
	a, b := ownerScopedCtx("tenant-a"), ownerScopedCtx("tenant-b")

	created, err := svc.CreateJSBundle(a, models.CreateJSBundleRequest{Name: "secret", Source: jsBundleSrc})
	if err != nil {
		t.Fatalf("A create bundle: %v", err)
	}
	digest := created.Digest

	// B cannot create an isolate sandbox from A's digest.
	_, err = svc.CreateSandboxWithID(b, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "sha256:" + digest,
	}, "sb-b-steal")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("B create from A's digest = %v, want ErrNotFound", err)
	}
	// B did not become a co-owner.
	if _, err := svc.GetJSBundle(b, digest); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("B get A's bundle after failed create = %v, want ErrNotFound", err)
	}

	// Delete reference scan is owner-scoped: A's live sandbox using the bundle
	// must not surface to B, nor block B. Give A a sandbox pinning the digest,
	// then have B (who legitimately uploaded the same bytes) delete its own copy.
	now := time.Now().UTC()
	if err := svc.store.Create(a, &models.Sandbox{
		ID: "sb-a-live", OwnerRef: "tenant-a", Runtime: models.RuntimeIsolate,
		ModuleDigest: digest, Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed A sandbox: %v", err)
	}
	if _, err := svc.CreateJSBundle(b, models.CreateJSBundleRequest{Name: "mine", Source: jsBundleSrc}); err != nil {
		t.Fatalf("B upload identical bytes: %v", err)
	}
	// B deletes its own ownership: must succeed, not report A's sandbox id.
	if err := svc.DeleteJSBundle(b, digest); err != nil {
		t.Fatalf("B delete own bundle copy = %v, want success (A's usage is irrelevant and must not leak)", err)
	}
}
