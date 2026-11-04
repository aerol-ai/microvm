package service

import (
	"context"

	"testing"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// #7: a tenant that registers a snapshot named after a common/default image
// must not hijack an operator/no-Access create of that image onto the tenant's
// bytes. And a committed snapshot's local tag is owner-scoped, so two tenants'
// same-named commits do not collide on one local image (#5/#7 tag collision).
func TestSnapshotNamespace_UnscopedCreateDoesNotAdoptTenantSnapshot(t *testing.T) {
	svc, _, _ := newSnapshotOwnerService(t)

	// globex registers a snapshot named after a public base image, redirecting
	// it to globex's own image.
	if _, err := svc.RegisterSnapshot(userCtx("globex"), &models.SandboxSnapshot{
		Name:  "ubuntu:22.04",
		Image: "ghcr.io/globex/backdoor:latest",
	}); err != nil {
		t.Fatalf("globex register: %v", err)
	}

	normalize := func(ctx context.Context) (string, error) {
		req := models.CreateSandboxRequest{Image: "ubuntu:22.04"}
		err := svc.NormalizeCreateImageDistribution(ctx, &req)
		return req.Image, err
	}

	// Operator and no-Access creates of "ubuntu:22.04" must get the real base
	// image, NOT globex's redirect.
	for _, tc := range []struct {
		who string
		ctx context.Context
	}{{"operator", operatorCtx()}, {"internal/no-Access", context.Background()}} {
		img, err := normalize(tc.ctx)
		if err != nil {
			t.Fatalf("%s create: %v", tc.who, err)
		}
		if img == "ghcr.io/globex/backdoor:latest" {
			t.Fatalf("%s create hijacked onto globex's image: %q", tc.who, img)
		}
		if img != "ubuntu:22.04" {
			t.Fatalf("%s create image = %q, want the plain base image", tc.who, img)
		}
	}

	// A different tenant creating "ubuntu:22.04" also gets the base image, not
	// globex's snapshot.
	if img, err := normalize(userCtx("acme")); err != nil || img == "ghcr.io/globex/backdoor:latest" {
		t.Fatalf("acme create = %q, %v; want the base image", img, err)
	}

	// globex itself resolves its own snapshot.
	if img, err := normalize(userCtx("globex")); err != nil || img != "ghcr.io/globex/backdoor:latest" {
		t.Fatalf("globex create of own snapshot = %q, %v", img, err)
	}
}

// A committed snapshot's local tag is scoped to its owner, so two tenants'
// same-named commits would land on DIFFERENT local images. (They cannot both
// exist today — the store name is a global primary key — so this is the
// prerequisite that keeps the per-owner-name rebuild (#13) from letting one
// tenant boot or fail over onto another's committed bytes.)
func TestSnapshotNamespace_CommittedTagIsOwnerScoped(t *testing.T) {
	svc, _, _ := newSnapshotOwnerService(t)
	g, _, err := svc.CreateSnapshotWithOwnership(userCtx("globex"), "sb-globex", models.CreateSandboxSnapshotRequest{Name: "base"})
	if err != nil {
		t.Fatal(err)
	}
	if g.Image != docker.SnapshotImageTagForOwner("globex", "base") {
		t.Fatalf("committed tag = %q, want owner-scoped", g.Image)
	}
	// The owner-scoped tag differs from the legacy owner-agnostic tag and from
	// another owner's tag for the same name.
	if g.Image == docker.SnapshotImageTag("base") {
		t.Fatal("tag is still owner-agnostic")
	}
	if docker.SnapshotImageTagForOwner("globex", "base") == docker.SnapshotImageTagForOwner("acme", "base") {
		t.Fatal("two owners' tags for the same name collide")
	}
}
