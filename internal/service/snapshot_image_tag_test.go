package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A snapshot is committed under a tag of its own, not under its name. A
// tenant's snapshot called "python" leaves the python image alone: everyone
// else still gets python by that name, the owner gets the snapshot, and a
// retry under another spelling of the name is the same snapshot and commit.
func TestSnapshotCommitsUnderItsOwnTag(t *testing.T) {
	svc, _, rt := newSnapshotOwnerService(t)
	globex := userCtx("globex")
	tag := docker.SnapshotImageTag("python")
	snap, created, err := svc.CreateSnapshotWithOwnership(globex, "sb-globex", models.CreateSandboxSnapshotRequest{Name: "python"})
	if err != nil || !created || snap.Image != tag || rt.lastImg != tag {
		t.Fatalf("commit = %+v, %v, %v (runtime got %q); want image %q", snap, created, err, rt.lastImg, tag)
	}
	again, created, err := svc.CreateSnapshotWithOwnership(globex, "sb-globex", models.CreateSandboxSnapshotRequest{Name: "python:latest"})
	if err != nil || created || again.Name != "python" || rt.hits != 1 {
		t.Fatalf("retry = %+v, %v, %v after %d commits; want the first snapshot", again, created, err, rt.hits)
	}
	for _, tc := range []struct {
		who  string
		ctx  context.Context
		want string
	}{
		{"another tenant", userCtx("acme"), "python"},
		{"the owner", globex, tag},
		{"an operator", operatorCtx(), tag},
	} {
		req := models.CreateSandboxRequest{Image: "python"}
		if err := svc.NormalizeCreateImageDistribution(tc.ctx, &req); err != nil || req.Image != tc.want {
			t.Errorf("%s's python = %q, %v; want %q", tc.who, req.Image, err, tc.want)
		}
	}
}

// A snapshot's tag reaches its image only through the snapshot it was
// committed for, under every spelling of the tag: the owner and operators
// may name it (a resolved request is a fixed point), another tenant may not,
// and an alias someone else registered for it does not authorize it.
func TestSnapshotTagIsReachableOnlyThroughItsSnapshot(t *testing.T) {
	svc, st, _ := newSnapshotOwnerService(t)
	ctx := context.Background()
	if _, _, err := svc.CreateSnapshotWithOwnership(userCtx("globex"), "sb-globex", models.CreateSandboxSnapshotRequest{Name: "g-commit"}); err != nil {
		t.Fatal(err)
	}
	tag := docker.SnapshotImageTag("g-commit")
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "acme-points-at-g", Image: tag, OwnerRef: "acme", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	normalize := func(ctx context.Context, image string) (string, error) {
		req := models.CreateSandboxRequest{Image: image}
		err := svc.NormalizeCreateImageDistribution(ctx, &req)
		return req.Image, err
	}
	for _, image := range []string{tag, "docker.io/" + tag, "index.docker.io/" + tag, "acme-points-at-g"} {
		if _, err := normalize(userCtx("acme"), image); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("acme create from %q = %v; want not found", image, err)
		}
		if got, err := normalize(operatorCtx(), image); err != nil || got != tag {
			t.Errorf("operator create from %q = %q, %v; want %q", image, got, err, tag)
		}
	}
	if got, err := normalize(userCtx("globex"), "docker.io/"+tag); err != nil || got != tag {
		t.Fatalf("owner create from its tag = %q, %v", got, err)
	}
	if _, err := svc.RegisterSnapshot(userCtx("acme"), &models.SandboxSnapshot{Name: "acme-alias", Image: tag}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("acme registering globex's tag = %v; want not found", err)
	}
	if _, err := svc.RegisterSnapshot(userCtx("globex"), &models.SandboxSnapshot{Name: "g-alias", Image: tag}); err != nil {
		t.Fatalf("globex registering its own tag = %v", err)
	}
	// A tag no snapshot here holds: a tenant has no snapshot to be
	// authorized by, and an operator may start whatever is there.
	orphan := docker.SnapshotImageTag("gone")
	if _, err := normalize(userCtx("acme"), orphan); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant create from an unheld tag = %v; want not found", err)
	}
	if got, err := normalize(operatorCtx(), orphan); err != nil || got != orphan {
		t.Fatalf("operator create from an unheld tag = %q, %v", got, err)
	}
}

// Names in the namespace snapshot images live under are refused, in any
// spelling; the "snapshots/..." names callers already use are not.
func TestReservedSnapshotNamesAreRefused(t *testing.T) {
	svc, _, rt := newSnapshotOwnerService(t)
	for _, name := range []string{"aerolvm-snapshot/x", "docker.io/aerolvm-snapshot/x:latest"} {
		if _, _, err := svc.CreateSnapshotWithOwnership(userCtx("acme"), "sb-acme", models.CreateSandboxSnapshotRequest{Name: name}); !errors.Is(err, errReservedSnapshotName) {
			t.Errorf("create %q = %v; want refused", name, err)
		}
		if _, err := svc.RegisterSnapshot(userCtx("acme"), &models.SandboxSnapshot{Name: name, Image: "alpine:3.20"}); !errors.Is(err, errReservedSnapshotName) {
			t.Errorf("register %q = %v; want refused", name, err)
		}
	}
	if rt.hits != 0 {
		t.Fatalf("a reserved name reached the runtime %d times", rt.hits)
	}
	if snap, _, err := svc.CreateSnapshotWithOwnership(userCtx("acme"), "sb-acme", models.CreateSandboxSnapshotRequest{Name: "snapshots/demo:v1"}); err != nil || snap.Image != docker.SnapshotImageTag("snapshots/demo:v1") {
		t.Fatalf("snapshots/demo:v1 = %+v, %v", snap, err)
	}
}

// A pushed snapshot's image can be placed on any node: a node that holds
// the snapshot starts its local image, one that does not starts the
// registry copy. Without a registry copy the create stays where the image
// is.
func TestPushedSnapshotImageRunsAnywhere(t *testing.T) {
	tag := docker.SnapshotImageTag("snap")
	ref := snapshotAOCRRef("aocr.test", "c1", "acme", "snap", "")
	for _, tc := range []struct {
		name string
		req  models.CreateSandboxRequest
		want bool
	}{
		{"pushed snapshot image", models.CreateSandboxRequest{Image: tag, ImageDistributionMode: models.ImageDistributionAOCR, ImageRegistryRef: ref}, false},
		{"unpushed snapshot image", models.CreateSandboxRequest{Image: tag, ImageDistributionMode: models.ImageDistributionLocalOnly}, true},
		{"pushed, but pinned here", models.CreateSandboxRequest{Image: tag, ImageDistributionMode: models.ImageDistributionLocalOnly, ImageRegistryRef: ref}, true},
		{"aocr mode with no ref", models.CreateSandboxRequest{Image: tag, ImageDistributionMode: models.ImageDistributionAOCR}, true},
		{"built image", models.CreateSandboxRequest{Image: "aerolvm-build/x:latest", ImageDistributionMode: models.ImageDistributionAOCR, ImageRegistryRef: ref}, true},
		{"snapshots/ name", models.CreateSandboxRequest{Image: "snapshots/demo:v1"}, true},
		{"registry image", models.CreateSandboxRequest{Image: "python:3.12"}, false},
	} {
		if got := ImageRequiresLocalPlacement(tc.req); got != tc.want {
			t.Errorf("%s: ImageRequiresLocalPlacement = %v, want %v", tc.name, got, tc.want)
		}
	}

	svc, st, _ := newSnapshotOwnerService(t)
	pushed := func(ctx context.Context, image, registryRef string) (string, error) {
		req := models.CreateSandboxRequest{Image: image, ImageDistributionMode: models.ImageDistributionAOCR, ImageRegistryRef: registryRef}
		err := svc.NormalizeCreateImageDistribution(ctx, &req)
		return req.Image, err
	}
	// No row here: the registry copy, for the owner, an operator, or a
	// replay.
	for _, ctx := range []context.Context{userCtx("acme"), operatorCtx(), contextWithStoredSpecReplay(context.Background())} {
		if got, err := pushed(ctx, tag, ref); err != nil || got != ref {
			t.Errorf("pushed snapshot on another node = %q, %v; want %q", got, err, ref)
		}
	}
	// A tenant's registry ref is checked against its own namespace.
	if _, err := pushed(userCtx("globex"), tag, ref); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("globex with acme's registry ref = %v; want not found", err)
	}
	// Here, where the snapshot is held: its local image, for whoever may
	// see the snapshot — a forged registry ref does not open another
	// tenant's.
	if err := st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{Name: "snap", Image: tag, SourceSandboxID: "sb-acme", OwnerRef: "acme", ImageDistributionMode: models.ImageDistributionAOCR, ImageRegistryRef: ref, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if got, err := pushed(userCtx("acme"), tag, ref); err != nil || got != tag {
		t.Fatalf("pushed snapshot on its node = %q, %v; want the local image", got, err)
	}
	globexRef := snapshotAOCRRef("aocr.test", "c1", "globex", "snap", "")
	if _, err := pushed(userCtx("globex"), tag, globexRef); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("globex naming acme's image with its own registry ref = %v; want not found", err)
	}
}

// A failover recreate replays an image its first create already resolved.
// On the node it lands on, a name may belong to a snapshot the sandbox
// never asked for; it is not looked up again.
func TestFailoverReplayDoesNotResolveNames(t *testing.T) {
	svc, _, _ := newSnapshotOwnerService(t)
	if _, _, err := svc.CreateSnapshotWithOwnership(userCtx("globex"), "sb-globex", models.CreateSandboxSnapshotRequest{Name: "python"}); err != nil {
		t.Fatal(err)
	}
	replay := contextWithStoredSpecReplay(context.Background())
	for image, want := range map[string]string{
		"python":                          "python",
		docker.SnapshotImageTag("python"): docker.SnapshotImageTag("python"),
	} {
		req := models.CreateSandboxRequest{Image: image}
		if err := svc.NormalizeCreateImageDistribution(replay, &req); err != nil || req.Image != want {
			t.Errorf("replay of %q = %q, %v; want %q", image, req.Image, err, want)
		}
	}
	// Outside a replay an unscoped caller resolves the name, as before.
	req := models.CreateSandboxRequest{Image: "python"}
	if err := svc.NormalizeCreateImageDistribution(context.Background(), &req); err != nil || req.Image != docker.SnapshotImageTag("python") {
		t.Fatalf("internal create of python = %q, %v", req.Image, err)
	}
}

// A snapshot's image is removed with the last snapshot that holds it, and
// only when it is the snapshot's own: deleting a name registered for an
// image — another snapshot's, a registry image, a build — leaves the image.
func TestDeleteSnapshotKeepsAnImageAnotherSnapshotHolds(t *testing.T) {
	svc, _, rt := newSnapshotOwnerService(t)
	acme := userCtx("acme")
	snap, _, err := svc.CreateSnapshotWithOwnership(acme, "sb-acme", models.CreateSandboxSnapshotRequest{Name: "base"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterSnapshot(acme, &models.SandboxSnapshot{Name: "base-alias", Image: snap.Image}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteSnapshot(acme, "base-alias"); err != nil || rt.removeHits != 0 {
		t.Fatalf("delete alias = %v after %d image removals; want the image kept", err, rt.removeHits)
	}
	if err := svc.DeleteSnapshot(acme, "base"); err != nil || rt.removeHits != 1 || rt.lastRemoved != snap.Image {
		t.Fatalf("delete snapshot = %v, removed %q (%d times)", err, rt.lastRemoved, rt.removeHits)
	}
	for _, image := range []string{"python:3.12", docker.BuildTagForOwner("FROM alpine\nRUN true", nil, "", snapshotOwnerNamespace("acme"))} {
		if _, err := svc.RegisterSnapshot(acme, &models.SandboxSnapshot{Name: "points-at", Image: image}); err != nil {
			t.Fatal(err)
		}
		if err := svc.DeleteSnapshot(acme, "points-at"); err != nil || rt.removeHits != 1 {
			t.Fatalf("delete of a snapshot registered for %s = %v, %d removals; want the image left alone", image, err, rt.removeHits)
		}
	}
	// A snapshot committed under its name before tags of its own still
	// takes its image with it.
	if err := svc.DeleteSnapshot(acme, "snap-acme"); err != nil || rt.removeHits != 2 || rt.lastRemoved != "snap-acme" {
		t.Fatalf("delete of an older snapshot = %v, removed %q (%d times)", err, rt.lastRemoved, rt.removeHits)
	}
}

// Neither image janitor removes an image a snapshot holds, though no
// sandbox runs it: a destroyed sandbox started from a snapshot schedules
// the snapshot's image, and a Dockerfile-built snapshot's image ages like
// any other build.
func TestImageGCKeepsSnapshotImages(t *testing.T) {
	ctx := context.Background()
	held := func(st *store.Store, name, image string) {
		t.Helper()
		if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: name, Image: image, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}

	svc, st, removed, _ := newPendingImageGCHarness(t, time.Hour)
	tag := docker.SnapshotImageTag("snap")
	held(st, "snap", tag)
	seedPending(t, st, tag, time.Now().UTC().Add(-2*time.Hour))
	seedPending(t, st, "alpine:latest", time.Now().UTC().Add(-2*time.Hour))
	svc.runPendingImageGC(ctx)
	if len(*removed) != 1 || (*removed)[0] != "alpine:latest" {
		t.Fatalf("pending GC removed %v; want only alpine:latest", *removed)
	}

	svc, st, removed = newBuiltImageGCHarness(t, time.Hour)
	held(st, "built-snap", "aerolvm-build/kept:latest")
	old := time.Now().UTC().Add(-2 * time.Hour)
	svc.runBuiltImageGC(ctx, func(context.Context) ([]docker.BuiltImage, error) {
		return []docker.BuiltImage{{Tag: "aerolvm-build/kept:latest", LastTagTime: old}, {Tag: "aerolvm-build/stale:latest", LastTagTime: old}}, nil
	})
	if len(*removed) != 1 || (*removed)[0] != "aerolvm-build/stale:latest" {
		t.Fatalf("built-image GC removed %v; want only the stale build", *removed)
	}
}

// A snapshot tag whose holders cannot be read fails the create, whether the
// tag is named directly or reached through an alias: not being able to tell
// who holds an image never lets it through. An operator's alias for a tag
// no snapshot holds passes the tag on.
func TestSnapshotTagLookupFailsClosed(t *testing.T) {
	svc, st, _ := newSnapshotOwnerService(t)
	ctx := context.Background()
	now := time.Now().UTC()
	tag, gone := docker.SnapshotImageTag("broken"), docker.SnapshotImageTag("gone")
	for _, row := range []*models.SandboxSnapshot{
		{Name: "op-alias", Image: tag, CreatedAt: now},
		{Name: "op-orphan-alias", Image: gone, CreatedAt: now},
	} {
		if err := st.CreateSnapshot(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	normalize := func(ctx context.Context, image string) (string, error) {
		req := models.CreateSandboxRequest{Image: image}
		err := svc.NormalizeCreateImageDistribution(ctx, &req)
		return req.Image, err
	}
	if got, err := normalize(operatorCtx(), "op-orphan-alias"); err != nil || got != gone {
		t.Fatalf("operator alias for an unheld tag = %q, %v; want %q", got, err, gone)
	}

	coverage97Exec(t, st, `INSERT INTO sandbox_snapshots(name, image, source_sandbox_id, created_at, memory_mb) VALUES ('unreadable', '`+tag+`', 'sb-x', CURRENT_TIMESTAMP, 'lots')`)
	for _, tc := range []struct {
		ctx   context.Context
		image string
	}{
		{userCtx("acme"), tag},
		{operatorCtx(), tag},
		{operatorCtx(), "op-alias"},
		{contextWithStoredSpecReplay(ctx), tag},
	} {
		if _, err := normalize(tc.ctx, tc.image); err == nil || errors.Is(err, store.ErrNotFound) {
			t.Errorf("create from %q with its holders unreadable = %v; want the read error", tc.image, err)
		}
	}
}
