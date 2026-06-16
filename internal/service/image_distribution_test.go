package service

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestNormalizeCreateImageDistributionResolvesSnapshotMetadata(t *testing.T) {
	ctx := context.Background()
	st := openImageDistributionStore(t)
	defer st.Close()

	snapshot := &models.SandboxSnapshot{
		Name:                  "e2b/sb-123:default",
		Image:                 "e2b/sb-123:default",
		SourceSandboxID:       "sb-123",
		CreatedAt:             time.Now().UTC(),
		ImageDistributionMode: models.ImageDistributionLocalOnly,
	}
	if err := st.CreateSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("CreateSnapshot() error = %v", err)
	}

	svc := &Service{store: st}
	req := models.CreateSandboxRequest{Image: snapshot.Name}
	if err := svc.NormalizeCreateImageDistribution(ctx, &req); err != nil {
		t.Fatalf("NormalizeCreateImageDistribution() error = %v", err)
	}
	if req.Image != snapshot.Image {
		t.Fatalf("req.Image = %q, want %q", req.Image, snapshot.Image)
	}
	if req.ImageDistributionMode != models.ImageDistributionLocalOnly {
		t.Fatalf("req.ImageDistributionMode = %q, want %q", req.ImageDistributionMode, models.ImageDistributionLocalOnly)
	}
	if !ImageRequiresLocalPlacement(req) {
		t.Fatal("snapshot-backed local image must require local placement")
	}
}

func TestRegisterSnapshotClassifiesImageDistribution(t *testing.T) {
	ctx := context.Background()
	st := openImageDistributionStore(t)
	defer st.Close()
	svc := &Service{store: st}

	aocrImage := "aocr.aerol.ai/team/app@sha256:abc"
	aocr, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{
		Name:      "aocr-template",
		Image:     aocrImage,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RegisterSnapshot(aocr) error = %v", err)
	}
	if aocr.ImageDistributionMode != models.ImageDistributionAOCR || aocr.ImageRegistryRef != aocrImage {
		t.Fatalf("aocr distribution = mode %q ref %q", aocr.ImageDistributionMode, aocr.ImageRegistryRef)
	}

	localImage := docker.BuiltImageNamespace + "/abc123:latest"
	local, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{
		Name:      "local-template",
		Image:     localImage,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RegisterSnapshot(local) error = %v", err)
	}
	if local.ImageDistributionMode != models.ImageDistributionLocalOnly {
		t.Fatalf("local distribution mode = %q, want %q", local.ImageDistributionMode, models.ImageDistributionLocalOnly)
	}
}

func TestNormalizeCreateFailover(t *testing.T) {
	req := models.CreateSandboxRequest{
		Image:                 "ubuntu:22.04",
		ImageDistributionMode: models.ImageDistributionExternalRegistry,
		Failover:              &models.Failover{Policy: "ReCreate"},
	}
	if err := NormalizeCreateFailover(&req); err != nil {
		t.Fatalf("NormalizeCreateFailover() error = %v", err)
	}
	if req.Failover == nil || req.Failover.Policy != models.FailoverPolicyRecreate {
		t.Fatalf("normalized failover = %+v, want recreate", req.Failover)
	}

	req = models.CreateSandboxRequest{
		Image:                 docker.BuiltImageNamespace + "/abc123:latest",
		ImageDistributionMode: models.ImageDistributionLocalOnly,
		Failover:              &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	if err := NormalizeCreateFailover(&req); err == nil {
		t.Fatal("expected local-only failover recreate to be rejected")
	}
}

func TestCreateSnapshotWithOwnershipMarksLocalOnly(t *testing.T) {
	ctx := context.Background()
	st := openImageDistributionStore(t)
	defer st.Close()

	sandbox := &models.Sandbox{
		ID:             "sb-snap-local",
		Image:          "ubuntu:22.04",
		Status:         models.SandboxStatusStarted,
		ContainerID:    "ctr-snap-local",
		ContainerIP:    "10.0.0.15",
		CPU:            1,
		MemoryMB:       1024,
		DiskGB:         10,
		OSUser:         "root",
		Env:            map[string]string{},
		ToolboxEnabled: true,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
		LastActiveAt:   time.Now().UTC(),
		Runtime:        models.RuntimeDocker,
	}
	if err := st.Create(ctx, sandbox); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	rt := &fakeSnapshotRuntime{imageID: "sha256:snapshot-local"}
	svc := &Service{store: st, docker: rt, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	snapshot, _, err := svc.CreateSnapshotWithOwnership(ctx, sandbox.ID, models.CreateSandboxSnapshotRequest{Name: "e2b/sb-snap-local:default"})
	if err != nil {
		t.Fatalf("CreateSnapshotWithOwnership() error = %v", err)
	}
	if snapshot.ImageDistributionMode != models.ImageDistributionLocalOnly {
		t.Fatalf("snapshot.ImageDistributionMode = %q, want %q", snapshot.ImageDistributionMode, models.ImageDistributionLocalOnly)
	}
}

func TestNormalizeCreateImageDistributionAOCRFallback(t *testing.T) {
	// When a peer node took a snapshot and pushed it under the
	// cluster's deterministic AOCR namespace, this node may receive a
	// create request naming a snapshot it has never seen locally.
	// Rather than wire snapshot rows through the FSM, the normalizer
	// rewrites the image to the canonical AOCR ref so the docker pull
	// acts as the existence check.
	ctx := context.Background()
	st := openImageDistributionStore(t)
	defer st.Close()

	patPath := writePATFile(t, "token")
	pusher, err := NewSnapshotPusher(SnapshotPushConfig{
		Enabled:   true,
		Host:      "aocr.test",
		ClusterID: "cluster-7",
		PATPath:   patPath,
	}, &fakeSnapshotPushDocker{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewSnapshotPusher: %v", err)
	}

	cases := []struct {
		name      string
		image     string
		pusher    *SnapshotPusher
		wantImage string
		wantMode  string
	}{
		{
			name:      "bare name with pusher rewrites to AOCR ref",
			image:     "my-snap",
			pusher:    pusher,
			wantImage: pusher.DestRefFor("my-snap"),
			wantMode:  models.ImageDistributionAOCR,
		},
		{
			name:      "bare name without pusher is left to classifier",
			image:     "my-snap",
			pusher:    nil,
			wantImage: "my-snap",
			wantMode:  models.ImageDistributionExternalRegistry,
		},
		{
			// Regression: a tagged base image (no registry host) must NOT be
			// mistaken for a cross-node snapshot. snapshotAOCRRef appends
			// `:latest`, which would yield the double-tagged, Docker-rejected
			// ref `snapshots/alpine:3.20:latest`. It must fall through to the
			// classifier as a normal external-registry pull.
			name:      "tagged base image is not treated as a snapshot",
			image:     "alpine:3.20",
			pusher:    pusher,
			wantImage: "alpine:3.20",
			wantMode:  models.ImageDistributionExternalRegistry,
		},
		{
			name:      "digest-pinned base image is not treated as a snapshot",
			image:     "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			pusher:    pusher,
			wantImage: "alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			wantMode:  models.ImageDistributionExternalRegistry,
		},
		{
			name:      "registry ref is left alone",
			image:     "ghcr.io/org/img:latest",
			pusher:    pusher,
			wantImage: "ghcr.io/org/img:latest",
			wantMode:  models.ImageDistributionExternalRegistry,
		},
		{
			name:      "local-only build tag is left alone",
			image:     docker.BuiltImageNamespace + "/abc123:latest",
			pusher:    pusher,
			wantImage: docker.BuiltImageNamespace + "/abc123:latest",
			wantMode:  models.ImageDistributionLocalOnly,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &Service{store: st, snapshotPusher: tc.pusher}
			req := models.CreateSandboxRequest{Image: tc.image}
			if err := svc.NormalizeCreateImageDistribution(ctx, &req); err != nil {
				t.Fatalf("NormalizeCreateImageDistribution: %v", err)
			}
			if req.Image != tc.wantImage {
				t.Fatalf("Image = %q, want %q", req.Image, tc.wantImage)
			}
			if req.ImageDistributionMode != tc.wantMode {
				t.Fatalf("ImageDistributionMode = %q, want %q", req.ImageDistributionMode, tc.wantMode)
			}
		})
	}
}

func TestNormalizeCreateImageDistribution_RejectsForeignArchSnapshot(t *testing.T) {
	host := hostSnapshotArch()
	foreign := snapshotArchAMD64
	if host == snapshotArchAMD64 {
		foreign = snapshotArchARM64
	}
	foreignRef := "aocr.test/cluster/c1/snapshots/snap:latest--arch-" + foreign

	svc := &Service{images: newDefaultImageDistributionProvider("aocr.test")}
	req := &models.CreateSandboxRequest{Image: foreignRef}
	req.ApplyImageDistribution(models.ImageDistributionMetadata{
		Mode:        models.ImageDistributionAOCR,
		RegistryRef: foreignRef,
	})
	if err := svc.NormalizeCreateImageDistribution(context.Background(), req); err == nil {
		t.Fatal("expected foreign-arch AOCR ref to be rejected")
	}
}

func TestImageDistributionHelperBranches(t *testing.T) {
	ctx := context.Background()

	p := newDefaultImageDistributionProvider("")
	if got, err := p.ClassifyImage(ctx, ""); err != nil || !got.IsZero() {
		t.Fatalf("ClassifyImage(empty) = (%+v, %v), want zero/nil", got, err)
	}
	if got, err := p.ClassifyImage(ctx, docker.BuiltImageNamespace+"/abc123:latest"); err != nil || got.Mode != models.ImageDistributionLocalOnly {
		t.Fatalf("ClassifyImage(local) = (%+v, %v), want local-only", got, err)
	}
	if got, err := p.ClassifyImage(ctx, "aocr.aerol.ai/team/app:latest"); err != nil || got.Mode != models.ImageDistributionAOCR || got.RegistryRef != "aocr.aerol.ai/team/app:latest" {
		t.Fatalf("ClassifyImage(aocr) = (%+v, %v), want AOCR with ref", got, err)
	}
	if got, err := p.ClassifyImage(ctx, "ghcr.io/org/app:latest"); err != nil || got.Mode != models.ImageDistributionExternalRegistry || got.RegistryRef != "ghcr.io/org/app:latest" {
		t.Fatalf("ClassifyImage(external) = (%+v, %v), want external with ref", got, err)
	}

	for _, tc := range []struct {
		image string
		want  string
	}{
		{"ghcr.io/org/app:latest", "ghcr.io"},
		{"localhost:5000/team/app:latest", "localhost:5000"},
		{"docker://aocr.aerol.ai/team/app:latest", "aocr.aerol.ai"},
		{"busybox", ""},
	} {
		if got := imageRegistryHost(tc.image); got != tc.want {
			t.Fatalf("imageRegistryHost(%q) = %q, want %q", tc.image, got, tc.want)
		}
	}

	normalized, err := normalizeImageDistributionMetadata("ghcr.io/org/app:latest", models.ImageDistributionMetadata{})
	if err != nil {
		t.Fatalf("normalizeImageDistributionMetadata: %v", err)
	}
	if normalized.Mode != models.ImageDistributionExternalRegistry || normalized.RegistryRef != "ghcr.io/org/app:latest" {
		t.Fatalf("normalized = %+v, want external registry ref", normalized)
	}

	svc := &Service{}
	snap := &models.SandboxSnapshot{Image: "  ghcr.io/org/app:latest  "}
	if err := svc.normalizeSnapshotImageDistribution(ctx, snap, true); err != nil {
		t.Fatalf("normalizeSnapshotImageDistribution(force local): %v", err)
	}
	if snap.ImageDistributionMode != models.ImageDistributionLocalOnly {
		t.Fatalf("forced snapshot mode = %q, want local-only", snap.ImageDistributionMode)
	}
}

func openImageDistributionStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return st
}
