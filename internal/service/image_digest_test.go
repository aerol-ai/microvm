package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/createpolicy"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

var (
	testDigestA = "sha256:" + strings.Repeat("a", 64)
	testDigestB = "sha256:" + strings.Repeat("b", 64)
)

func TestPinImageDigest(t *testing.T) {
	cases := []struct {
		name       string
		image      string
		digest     string
		mode       string
		wantImage  string
		wantDigest string
		wantErr    bool
	}{
		{name: "no digest leaves the image alone", image: "python:3.12", wantImage: "python:3.12"},
		{name: "short hub name is pinned", image: "python:3.12", digest: testDigestA, wantImage: "python@" + testDigestA, wantDigest: testDigestA},
		{name: "full hub name is pinned", image: "docker.io/library/python:3.12", digest: testDigestA, wantImage: "python@" + testDigestA, wantDigest: testDigestA},
		{name: "untagged name is pinned", image: "ghcr.io/acme/app", digest: testDigestA, wantImage: "ghcr.io/acme/app@" + testDigestA, wantDigest: testDigestA},
		{name: "registry with a port is pinned", image: "registry.bank.example:5000/team/app:1.4", digest: testDigestA, wantImage: "registry.bank.example:5000/team/app@" + testDigestA, wantDigest: testDigestA},
		{name: "digest is trimmed", image: "ghcr.io/acme/app:1", digest: "  " + testDigestA + " ", wantImage: "ghcr.io/acme/app@" + testDigestA, wantDigest: testDigestA},
		{name: "image already pinned to the same digest", image: "ghcr.io/acme/app@" + testDigestA, digest: testDigestA, wantImage: "ghcr.io/acme/app@" + testDigestA, wantDigest: testDigestA},
		{name: "image pinned to another digest is refused", image: "ghcr.io/acme/app@" + testDigestB, digest: testDigestA, wantErr: true},
		{name: "tag and another digest is refused", image: "ghcr.io/acme/app:1@" + testDigestB, digest: testDigestA, wantErr: true},
		{name: "not a digest is refused", image: "python:3.12", digest: "latest", wantErr: true},
		{name: "short hex is refused", image: "python:3.12", digest: "sha256:abc", wantErr: true},
		{name: "upper-case hex is refused", image: "python:3.12", digest: "sha256:" + strings.Repeat("A", 64), wantErr: true},
		{name: "image id is refused", image: testDigestB, digest: testDigestA, wantErr: true},
		{name: "unparseable image is refused", image: "Not/A/Valid:Image:Name", digest: testDigestA, wantErr: true},
		// Never pulled from a registry, so there is nothing to pin.
		{name: "built image is left alone", image: docker.BuiltImageNamespace + "/abc:latest", digest: testDigestA, wantImage: docker.BuiltImageNamespace + "/abc:latest", wantDigest: testDigestA},
		{name: "committed snapshot is left alone", image: docker.SnapshotImageTag("snap"), digest: testDigestA, wantImage: docker.SnapshotImageTag("snap"), wantDigest: testDigestA},
		{name: "empty image is left to validation", image: "", digest: testDigestA, wantImage: "", wantDigest: testDigestA},
		// A loaded image can carry a registry-looking name; pinning it would
		// send the runtime to that registry for an image it has locally.
		{name: "local_only create with a registry name is left alone", image: "alpine:3.20", digest: testDigestA, mode: models.ImageDistributionLocalOnly, wantImage: "alpine:3.20", wantDigest: testDigestA},
		{name: "digest of a local image is not looked at", image: docker.BuiltImageNamespace + "/abc:latest", digest: "nope", wantImage: docker.BuiltImageNamespace + "/abc:latest", wantDigest: "nope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := models.CreateSandboxRequest{Image: tc.image, ImageDigest: tc.digest, ImageDistributionMode: tc.mode}
			err := pinImageDigest(&req)
			if tc.wantErr {
				if !errors.Is(err, ErrImageDigest) {
					t.Fatalf("pinImageDigest() error = %v, want ErrImageDigest", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("pinImageDigest() error = %v", err)
			}
			if req.Image != tc.wantImage {
				t.Fatalf("Image = %q, want %q", req.Image, tc.wantImage)
			}
			if tc.digest != "" && req.ImageDigest != tc.wantDigest {
				t.Fatalf("ImageDigest = %q, want %q", req.ImageDigest, tc.wantDigest)
			}
			// A fixed point: normalization runs on the router, the owner
			// and in createSandbox, and must give the same answer each time.
			again := req
			if err := pinImageDigest(&again); err != nil || again.Image != req.Image {
				t.Fatalf("second pin = (%q, %v), want (%q, nil)", again.Image, err, req.Image)
			}
		})
	}
}

// The digest on a create used to be recorded and never checked (#83): the
// runtime pulled the tag, whatever it pointed at by then. Normalization now
// hands the runtime an image that names the digest.
func TestNormalizeCreateImageDistributionPinsTheDigest(t *testing.T) {
	ctx := context.Background()
	st := openImageDistributionStore(t)
	defer st.Close()
	svc := &Service{store: st}

	req := models.CreateSandboxRequest{Image: "ghcr.io/acme/app:1.4", ImageDigest: testDigestA}
	if err := svc.NormalizeCreateImageDistribution(ctx, &req); err != nil {
		t.Fatalf("NormalizeCreateImageDistribution() error = %v", err)
	}
	if want := "ghcr.io/acme/app@" + testDigestA; req.Image != want {
		t.Fatalf("Image = %q, want %q", req.Image, want)
	}
	// The caller's tagged name is kept as the registry ref (auto-import and
	// display read it), and the request is still placeable anywhere.
	if req.ImageRegistryRef != "ghcr.io/acme/app:1.4" {
		t.Fatalf("ImageRegistryRef = %q, want the tagged name", req.ImageRegistryRef)
	}
	if req.ImageDistributionMode != models.ImageDistributionExternalRegistry || ImageRequiresLocalPlacement(req) {
		t.Fatalf("mode = %q local = %v, want an external registry image placeable anywhere", req.ImageDistributionMode, ImageRequiresLocalPlacement(req))
	}
	again := req
	if err := svc.NormalizeCreateImageDistribution(ctx, &again); err != nil {
		t.Fatalf("second NormalizeCreateImageDistribution() error = %v", err)
	}
	if again.Image != req.Image || again.ImageRegistryRef != req.ImageRegistryRef || again.ImageDigest != req.ImageDigest {
		t.Fatalf("second pass changed the request: %+v -> %+v", req, again)
	}

	bad := models.CreateSandboxRequest{Image: "ghcr.io/acme/app@" + testDigestB, ImageDigest: testDigestA}
	if err := svc.NormalizeCreateImageDistribution(ctx, &bad); !errors.Is(err, ErrImageDigest) {
		t.Fatalf("contradicting digests: error = %v, want ErrImageDigest", err)
	}

	// A failover recreate replays a spec replicated before digests were
	// checked: a digest that cannot hold is a warning there, not a lost
	// sandbox, and the image starts as it first did.
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, replay := range []models.CreateSandboxRequest{
		{Image: "ghcr.io/acme/app:1.4", ImageDigest: "not-a-digest"},
		{Image: "ghcr.io/acme/app@" + testDigestB, ImageDigest: testDigestA},
	} {
		image := replay.Image
		if err := svc.NormalizeCreateImageDistribution(contextWithStoredSpecReplay(ctx), &replay); err != nil {
			t.Fatalf("replay of %q / %q: error = %v, want none", image, replay.ImageDigest, err)
		}
		if replay.Image != image {
			t.Fatalf("replay changed the image %q to %q", image, replay.Image)
		}
	}
	// A good digest is still pinned on a replay.
	good := models.CreateSandboxRequest{Image: "ghcr.io/acme/app:1.4", ImageDigest: testDigestA}
	if err := svc.NormalizeCreateImageDistribution(contextWithStoredSpecReplay(ctx), &good); err != nil || good.Image != "ghcr.io/acme/app@"+testDigestA {
		t.Fatalf("replay with a good digest = (%q, %v), want it pinned", good.Image, err)
	}
}

// A node that does not hold a pushed snapshot starts its registry copy (a
// create placed here, or a failover recreate). It must start the manifest
// the snapshot was pushed as, not whatever the copy's tag points at now.
func TestNormalizeCreateImageDistributionPinsAPushedSnapshotCopy(t *testing.T) {
	ctx := context.Background()
	st := openImageDistributionStore(t)
	defer st.Close()
	svc := &Service{store: st}

	// The copy's tag carries its architecture; the arch guard reads the
	// registry ref, which keeps the tag, so pinning the image cannot hide a
	// foreign-arch copy.
	copyRef := testHostAOCRRef("aocr.test/cluster/c1/snapshots/my-snap:latest")
	req := models.CreateSandboxRequest{
		Image:                 docker.SnapshotImageTag("my-snap"),
		ImageDistributionMode: models.ImageDistributionAOCR,
		ImageRegistryRef:      copyRef,
		ImageDigest:           testDigestA,
	}
	if err := svc.NormalizeCreateImageDistribution(ctx, &req); err != nil {
		t.Fatalf("NormalizeCreateImageDistribution() error = %v", err)
	}
	if want := "aocr.test/cluster/c1/snapshots/my-snap@" + testDigestA; req.Image != want {
		t.Fatalf("Image = %q, want %q", req.Image, want)
	}
	if req.ImageRegistryRef != copyRef {
		t.Fatalf("ImageRegistryRef = %q, want %q (the retirement worker matches it)", req.ImageRegistryRef, copyRef)
	}
	again := req
	if err := svc.NormalizeCreateImageDistribution(ctx, &again); err != nil || again.Image != req.Image {
		t.Fatalf("second pass = (%q, %v), want (%q, nil)", again.Image, err, req.Image)
	}

	// A foreign-arch copy is still refused with the digest set.
	foreign := snapshotArchARM64
	if hostSnapshotArch() == snapshotArchARM64 {
		foreign = snapshotArchAMD64
	}
	wrongArch := models.CreateSandboxRequest{
		Image:                 docker.SnapshotImageTag("my-snap"),
		ImageDistributionMode: models.ImageDistributionAOCR,
		ImageRegistryRef:      "aocr.test/cluster/c1/snapshots/my-snap:latest" + archTagSuffix(foreign),
		ImageDigest:           testDigestA,
	}
	if err := svc.NormalizeCreateImageDistribution(ctx, &wrongArch); err == nil {
		t.Fatalf("foreign-arch copy pinned to a digest was accepted as %q", wrongArch.Image)
	}
}

func TestClassifyImageDigestIsABadRequest(t *testing.T) {
	err := pinImageDigest(&models.CreateSandboxRequest{Image: "python:3.12", ImageDigest: "nope"})
	if !errors.Is(err, ErrImageDigest) {
		t.Fatalf("pinImageDigest() error = %v, want ErrImageDigest", err)
	}
	if !strings.Contains(err.Error(), "sha256:<64 hex digits>") {
		t.Fatalf("error %q should say what a digest looks like", err)
	}
}

// End to end through CreateSandbox: the runtime is handed the pinned image,
// so its pull fetches and checks that manifest; a create policy judges the
// content the digest names, so a tag pattern does not vouch for it; and a
// bad digest never reaches the runtime.
func TestCreateSandboxPullsThePinnedDigest(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	ctx := context.Background()

	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "acme/app:1", ImageDigest: testDigestA}); err != nil {
		t.Fatalf("CreateSandbox() error = %v", err)
	}
	if want := "acme/app@" + testDigestA; rt.lastCreateReq.Image != want {
		t.Fatalf("runtime got image %q, want %q", rt.lastCreateReq.Image, want)
	}

	calls := rt.createCalls
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "acme/app@" + testDigestB, ImageDigest: testDigestA}); !errors.Is(err, ErrImageDigest) {
		t.Fatalf("contradicting digest: error = %v, want ErrImageDigest", err)
	}
	if rt.createCalls != calls {
		t.Fatal("a refused digest must not reach the runtime")
	}

	svc.SetCreatePolicy(createPolicyWatcher(t, "version: 1\nimages:\n  allowed: [\"acme/app:1*\"]\n"))
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "acme/app:1", ImageDigest: testDigestA}); policyRule(err) != createpolicy.RuleImages {
		t.Fatalf("tag pattern with a pinned digest = %v, want the images rule", err)
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "acme/app:1"}); err != nil {
		t.Fatalf("tag pattern without a digest = %v", err)
	}
}
