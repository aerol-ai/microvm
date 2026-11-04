package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Where a cold boot reads its image from: a snapshot this node holds from
// the node's image store, anything else from its registry with the request's
// credential or, for the cluster registry, the cluster PAT.

// sourceRecordingRootfs records the source and credential each build used.
type sourceRecordingRootfs struct {
	fakeRootfs
	mu2     sync.Mutex
	sources []string
	auths   []*models.RegistryAuth
}

func (b *sourceRecordingRootfs) Build(ctx context.Context, req RootfsBuildRequest) (*RootfsResult, error) {
	b.mu2.Lock()
	b.sources = append(b.sources, req.ImageRef)
	b.auths = append(b.auths, req.Auth)
	b.mu2.Unlock()
	return b.fakeRootfs.Build(ctx, req)
}

func createWithSource(t *testing.T, f *driverFixture, id string, req models.CreateSandboxRequest) (*sourceRecordingRootfs, error) {
	t.Helper()
	rec := &sourceRecordingRootfs{}
	f.driver.SetRootfsBuilder(rec)
	req.CPU, req.MemoryMB = 1, 128
	_, err := f.driver.Create(context.Background(), req, id, "tok", nil)
	return rec, err
}

func TestColdBootReadsALocalSnapshotFromTheImageStore(t *testing.T) {
	f := newDriverFixture(t)
	store := &recordingImageStore{local: map[string]string{"aerolvm-snapshot/abc:latest": "docker-archive:/x/image-1.tar"}}
	f.driver.SetImageStore(store)
	rec, err := createWithSource(t, f, "sb-from-snap", models.CreateSandboxRequest{Image: "aerolvm-snapshot/abc:latest"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.sources[0] != "docker-archive:/x/image-1.tar" || rec.auths[0] != nil {
		t.Fatalf("built from %q auth %+v, want the local archive and no credential", rec.sources[0], rec.auths[0])
	}
	if store.released != 1 {
		t.Fatalf("the staged archive was released %d times, want 1", store.released)
	}
}

func TestColdBootPullsASnapshotThisNodeDoesNotHold(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.SetImageStore(&recordingImageStore{})
	rec, err := createWithSource(t, f, "sb-snap-remote", models.CreateSandboxRequest{Image: "aerolvm-snapshot/abc:latest"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.sources[0] != "docker://aerolvm-snapshot/abc:latest" {
		t.Fatalf("built from %q, want the registry", rec.sources[0])
	}
}

func TestColdBootFailsWhenTheImageStoreErrs(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.SetImageStore(&recordingImageStore{openErr: errors.New("engine down")})
	if _, err := createWithSource(t, f, "sb-store-err", models.CreateSandboxRequest{Image: "aerolvm-snapshot/abc:latest"}); err == nil || !strings.Contains(err.Error(), "rootfs source") {
		t.Fatalf("err = %v, want the store error", err)
	}
}

func TestColdBootUsesTheRequestCredential(t *testing.T) {
	f := newDriverFixture(t)
	auth := &models.RegistryAuth{Server: "ghcr.io", Username: "u", Password: "p"}
	rec, err := createWithSource(t, f, "sb-private", models.CreateSandboxRequest{Image: "ghcr.io/org/app:1", Registry: auth})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.sources[0] != "docker://ghcr.io/org/app:1" || rec.auths[0] != auth {
		t.Fatalf("built from %q auth %+v, want the request's credential", rec.sources[0], rec.auths[0])
	}
}

func TestColdBootUsesTheClusterPATForTheClusterRegistry(t *testing.T) {
	f := newDriverFixture(t)
	pat := filepath.Join(t.TempDir(), "cluster.pat")
	if err := os.WriteFile(pat, []byte("pat-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.driver.ConfigureAOCRPullAuth([]string{"aocr.example.com"}, "c1", pat)
	ref := "aocr.example.com/cluster/c1/snapshots/app:latest"
	rec, err := createWithSource(t, f, "sb-aocr", models.CreateSandboxRequest{Image: ref})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if a := rec.auths[0]; a == nil || a.Username != "c1" || a.Password != "pat-value" || a.Server != "aocr.example.com" {
		t.Fatalf("auth = %+v, want the cluster PAT for aocr.example.com", a)
	}
	// A repo outside cluster/ on the same host does not borrow it.
	rec, err = createWithSource(t, f, "sb-aocr-user", models.CreateSandboxRequest{Image: "aocr.example.com/someone/app:1"})
	if err != nil || rec.auths[0] != nil {
		t.Fatalf("non-cluster repo: err %v auth %+v, want anonymous", err, rec.auths[0])
	}
}

func TestColdBootPullsAnonymouslyWhenTheClusterPATIsUnreadable(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.ConfigureAOCRPullAuth([]string{"aocr.example.com"}, "c1", filepath.Join(t.TempDir(), "missing.pat"))
	rec, err := createWithSource(t, f, "sb-aocr-nopat", models.CreateSandboxRequest{Image: "aocr.example.com/cluster/c1/snapshots/app:latest"})
	if err != nil || rec.auths[0] != nil {
		t.Fatalf("err %v auth %+v, want an anonymous attempt", err, rec.auths[0])
	}
	// Without cluster settings, ConfigureAOCRPullAuth leaves pulls anonymous.
	f.driver.aocrPullAuth = nil
	f.driver.ConfigureAOCRPullAuth(nil, "", "")
	if f.driver.aocrPullAuth != nil {
		t.Fatal("empty cluster settings installed a credential")
	}
}

// An ordinary image never goes through the store, even when one is wired.
func TestColdBootPullsPlainImagesFromTheRegistry(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.SetImageStore(&recordingImageStore{openErr: errors.New("must not be asked")})
	rec, err := createWithSource(t, f, "sb-plain", models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil || rec.sources[0] != "docker://alpine:3.20" {
		t.Fatalf("err %v source %q", err, rec.sources)
	}
}

// A snapshot this node no longer holds is pulled from its pushed copy, with
// the cluster PAT, not looked up on Docker Hub under its local tag.
func TestColdBootFallsBackToThePushedCopyOfASnapshot(t *testing.T) {
	f := newDriverFixture(t)
	pat := filepath.Join(t.TempDir(), "cluster.pat")
	if err := os.WriteFile(pat, []byte("pat-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.driver.ConfigureAOCRPullAuth([]string{"aocr.example.com"}, "c1", pat)
	f.driver.SetImageStore(&recordingImageStore{})
	pushed := "aocr.example.com/cluster/c1/snapshots/abc:latest"
	rec, err := createWithSource(t, f, "sb-pushed", models.CreateSandboxRequest{
		Image: "aerolvm-snapshot/abc:latest", ImageDistributionMode: models.ImageDistributionAOCR, ImageRegistryRef: pushed,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.sources[0] != "docker://"+pushed || rec.auths[0] == nil || rec.auths[0].Username != "c1" {
		t.Fatalf("built from %q auth %+v, want the pushed copy with the cluster PAT", rec.sources[0], rec.auths[0])
	}
}
