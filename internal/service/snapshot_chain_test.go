package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/distribution/reference"
)

// A registered snapshot's image may be another snapshot's name. What runs
// is the image at the end of that chain, so every snapshot on the way is
// authorized as the caller, at registration and again at create: a name
// registered before a private snapshot took its target name still cannot
// reach it.
func TestSnapshotChainIsAuthorizedThroughout(t *testing.T) {
	svc, st, _ := newSnapshotOwnerService(t)
	ctx := context.Background()
	acme := userCtx("acme")
	normalize := func(ctx context.Context, image string) (models.CreateSandboxRequest, error) {
		req := models.CreateSandboxRequest{Image: image}
		err := svc.NormalizeCreateImageDistribution(ctx, &req)
		return req, err
	}

	// Pointing at another tenant's snapshot, directly or through one's own
	// names, is refused when registering.
	if _, err := svc.RegisterSnapshot(acme, &models.SandboxSnapshot{Name: "acme-to-globex", Image: "snap-globex:latest"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("register over another tenant's snapshot = %v; want not found", err)
	}
	if _, err := svc.RegisterSnapshot(acme, &models.SandboxSnapshot{Name: "acme-later", Image: "not-yet"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterSnapshot(acme, &models.SandboxSnapshot{Name: "acme-outer", Image: "acme-later"}); err != nil {
		t.Fatal(err)
	}
	// Globex later commits a snapshot under the name the chain ends on, the
	// way snapshots were committed before they had tags of their own: the
	// local image under that name is now Globex's, so the chain no longer
	// resolves for acme, however many hops lead to it or how many times the
	// request is normalized.
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "not-yet", Image: "not-yet", SourceSandboxID: "sb-globex", OwnerRef: "globex", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{"acme-outer", "acme-later", "not-yet"} {
		if _, err := normalize(acme, image); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("acme create from %q = %v; want not found", image, err)
		}
	}
	// A snapshot committed now keeps its image under its own tag, so the
	// name stays an ordinary image to everyone else: acme's chain ends on
	// the name, never on Globex's image.
	if _, err := svc.RegisterSnapshot(acme, &models.SandboxSnapshot{Name: "acme-later-2", Image: "not-yet-2"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CreateSnapshotWithOwnership(userCtx("globex"), "sb-globex", models.CreateSandboxSnapshotRequest{Name: "not-yet-2"}); err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{"acme-later-2", "not-yet-2"} {
		if req, err := normalize(acme, image); err != nil || req.Image != "not-yet-2" {
			t.Fatalf("acme create from %q = %q, %v; want the ordinary image not-yet-2", image, req.Image, err)
		}
	}
	if req, err := normalize(userCtx("globex"), "not-yet-2"); err != nil || req.Image != docker.SnapshotImageTag("not-yet-2") {
		t.Fatalf("globex create from its snapshot = %q, %v", req.Image, err)
	}

	// A chain through one's own snapshots resolves to the committed image,
	// placed by that snapshot's distribution — local only — not by the
	// alias's, which registration classified as a registry image. Resolving
	// it again is a fixed point.
	if _, _, err := svc.CreateSnapshotWithOwnership(acme, "sb-acme", models.CreateSandboxSnapshotRequest{Name: "acme-commit"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterSnapshot(acme, &models.SandboxSnapshot{Name: "acme-alias", Image: "acme-commit"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterSnapshot(acme, &models.SandboxSnapshot{Name: "acme-alias-2", Image: "acme-alias"}); err != nil {
		t.Fatal(err)
	}
	req, err := normalize(acme, "acme-alias-2")
	if err != nil || req.Image != docker.SnapshotImageTag("acme-commit") || req.ImageDistributionMode != models.ImageDistributionLocalOnly {
		t.Fatalf("own chain = %+v, %v; want acme-commit's image, local only", req, err)
	}
	again := req
	if err := svc.NormalizeCreateImageDistribution(acme, &again); err != nil || again.Image != req.Image || again.ImageDistribution() != req.ImageDistribution() {
		t.Fatalf("second normalize = %+v, %v; want %+v", again, err, req)
	}
	// An operator may start anything, through any chain.
	if req, err := normalize(operatorCtx(), "acme-outer"); err != nil || req.Image != "not-yet" {
		t.Fatalf("operator chain = %+v, %v", req, err)
	}

	// Registration cannot close a loop, and a chain too long to follow
	// (which only rows written behind the service's back can build) is
	// refused rather than followed.
	if _, err := svc.RegisterSnapshot(acme, &models.SandboxSnapshot{Name: "acme-later-loop", Image: "acme-loop-back"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterSnapshot(acme, &models.SandboxSnapshot{Name: "acme-loop-back", Image: "acme-later-loop"}); !errors.Is(err, errSnapshotChain) {
		t.Fatalf("closing a loop = %v; want refused", err)
	}
	for i := range maxSnapshotChain + 1 {
		row := &models.SandboxSnapshot{Name: fmt.Sprintf("long-%d", i), Image: fmt.Sprintf("long-%d", i+1), OwnerRef: "acme", CreatedAt: time.Now().UTC()}
		if err := st.CreateSnapshot(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := normalize(acme, "long-0"); !errors.Is(err, errSnapshotChain) {
		t.Fatalf("over-long chain = %v; want refused", err)
	}
	if req, err := normalize(acme, "long-1"); err != nil || req.Image != fmt.Sprintf("long-%d", maxSnapshotChain+1) {
		t.Fatalf("chain at the bound = %+v, %v; want followed to its end", req, err)
	}

	// For a user token every image on the way passes the reference check
	// too, so a row pointing at an image id (written before registration
	// checked it) does not reach the image.
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "acme-by-id", Image: "sha256:globex", OwnerRef: "acme", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := normalize(acme, "acme-by-id"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("own row pointing at an image id = %v; want not found", err)
	}
	if _, err := svc.RegisterSnapshot(acme, &models.SandboxSnapshot{Name: "acme-id-2", Image: "sha256:globex"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("register an image id = %v; want not found", err)
	}
}

// When the catalog cannot be read, nothing is known about whether a name is
// a private snapshot, so the create fails instead of treating the name as a
// plain image — for every caller, since none can be authorized.
func TestSnapshotCatalogReadFailureFailsClosed(t *testing.T) {
	svc, st, _ := newSnapshotOwnerService(t)
	req := models.CreateSandboxRequest{Image: "snap-acme"}
	if err := svc.NormalizeCreateImageDistribution(userCtx("globex"), &req); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("control: another tenant's snapshot = %v", err)
	}
	_ = st.Close()
	for _, ctx := range []context.Context{userCtx("globex"), operatorCtx()} {
		req := models.CreateSandboxRequest{Image: "snap-acme"}
		err := svc.NormalizeCreateImageDistribution(ctx, &req)
		if err == nil || errors.Is(err, store.ErrNotFound) {
			t.Fatalf("normalize with an unreadable catalog = %v (image %q); want the read error", err, req.Image)
		}
	}
	if _, err := svc.RegisterSnapshot(userCtx("globex"), &models.SandboxSnapshot{Name: "g", Image: "snap-acme"}); err == nil {
		t.Fatal("register with an unreadable catalog succeeded")
	}
}

// The engine treats "snap" and "snap:latest" as one image, so they are one
// snapshot: another spelling of a taken name is a conflict when creating or
// registering, and reads and deletes find the snapshot under any spelling —
// never another tenant's.
func TestEquivalentSnapshotNamesAreOneSnapshot(t *testing.T) {
	svc, st, rt := newSnapshotOwnerService(t)
	acme, globex := userCtx("acme"), userCtx("globex")
	for _, name := range []string{"snap-globex:latest", "docker.io/library/snap-globex", "index.docker.io/library/snap-globex:latest"} {
		if _, _, err := svc.CreateSnapshotWithOwnership(acme, "sb-acme", models.CreateSandboxSnapshotRequest{Name: name}); !errors.Is(err, store.ErrSnapshotNameConflict) {
			t.Fatalf("acme snapshot %q = %v; want a conflict with globex's snap-globex", name, err)
		}
		if _, err := svc.RegisterSnapshot(acme, &models.SandboxSnapshot{Name: name, Image: "alpine:3.20"}); !errors.Is(err, store.ErrSnapshotNameConflict) {
			t.Fatalf("acme register %q = %v; want a conflict", name, err)
		}
	}
	if rt.hits != 0 {
		t.Fatalf("the runtime committed %d images over an equivalent tag", rt.hits)
	}
	// The owner's own retry under another spelling is the same snapshot.
	got, created, err := svc.CreateSnapshotWithOwnership(globex, "sb-globex", models.CreateSandboxSnapshotRequest{Name: "snap-globex:latest"})
	if err != nil || created || got.Name != "snap-globex" {
		t.Fatalf("owner retry = %+v, %v, %v; want the existing row", got, created, err)
	}
	if got, err := svc.GetSnapshot(globex, "docker.io/library/snap-globex"); err != nil || got.Name != "snap-globex" {
		t.Fatalf("owner read by another spelling = %+v, %v", got, err)
	}
	if _, err := svc.GetSnapshot(acme, "snap-globex:latest"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other tenant read by another spelling = %v; want not found", err)
	}
	if err := svc.DeleteSnapshot(acme, "snap-globex:latest"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other tenant delete by another spelling = %v; want not found", err)
	}
	if _, err := st.GetSnapshot(context.Background(), "snap-globex"); err != nil || rt.removeHits != 0 {
		t.Fatalf("globex's snapshot after acme's delete = %v (removes %d); want it intact", err, rt.removeHits)
	}
	if err := svc.DeleteSnapshot(globex, "snap-globex:latest"); err != nil {
		t.Fatalf("owner delete by another spelling = %v", err)
	}
}

// Every snapshot name gets a push destination the registry accepts, one
// repository per name. A plain name keeps the path earlier releases used;
// anything else (its own tag, upper case, a name long enough to overflow
// the ref) is pushed under a hash of the name, and no name can land in a
// path a hash or an owner namespace owns.
func TestSnapshotPushRefIsValidForEveryName(t *testing.T) {
	ref := func(owner, name string) string { return snapshotAOCRRef("aocr.test", "c1", owner, name, "--ttl-1h") }
	arch := archTagSuffix(snapshotRefArch())
	plain := map[[2]string]string{
		{"", "snap"}:                    "aocr.test/cluster/c1/snapshots/snap:latest" + arch + "--ttl-1h",
		{"", "snap:latest"}:             "aocr.test/cluster/c1/snapshots/snap:latest" + arch + "--ttl-1h",
		{"acme", "runloop/0123:latest"}: "aocr.test/cluster/c1/snapshots/" + snapshotOwnerNamespace("acme") + "/runloop/0123:latest" + arch + "--ttl-1h",
	}
	for in, want := range plain {
		if got := ref(in[0], in[1]); got != want {
			t.Errorf("ref(%q, %q) = %q; want %q", in[0], in[1], got, want)
		}
	}
	names := []string{"snap", "foo:v1", "foo:v2", "Foo", "foo", "hashed-abc", "tenant-x/y", "localhost:5000/x", strings.Repeat("a", 300)}
	seen := map[string]string{}
	for _, owner := range []string{"", "acme"} {
		for _, name := range names {
			got := ref(owner, name)
			if _, err := reference.ParseNormalizedNamed(got); err != nil {
				t.Errorf("ref(%q, %q) = %q: %v", owner, name, got, err)
			}
			if other, dup := seen[got]; dup {
				t.Errorf("%q and %q share %q", other, owner+"/"+name, got)
			}
			seen[got] = owner + "/" + name
			if namespace, ok := snapshotRefNamespace(got); !ok || namespace != snapshotOwnerNamespace(owner) {
				t.Errorf("ref(%q, %q) = %q sits in namespace %q", owner, name, got, namespace)
			}
		}
	}
	for _, name := range []string{"foo:v1", "Foo", "hashed-abc", "tenant-x/y"} {
		if got := ref("", name); !strings.Contains(got, "/snapshots/"+snapshotHashedRepoPrefix) {
			t.Errorf("ref(%q) = %q; want a hashed repository", name, got)
		}
	}
}
