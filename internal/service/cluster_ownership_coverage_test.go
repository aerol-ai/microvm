package service

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestReplayClusterOwnershipWave11(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = false
	svc.ReplayClusterOwnership(context.Background())
	svc.cfg.EnableCluster = true
	svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
	svc.ReplayClusterOwnership(context.Background())
}

func TestClusterOwnershipNeedsReplayWave16(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: "sb-own", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	_ = st.Create(context.Background(), sb)
	cl := &recordingOwnershipCluster{
		Noop:       cluster.NewNoop("self", "http://self", ""),
		placements: map[string]cluster.Placement{},
	}
	_ = svc.clusterOwnershipNeedsReplay(cl, sb)
	svc.AttachCluster(cl)
	_, _ = svc.ReplayClusterOwnership(context.Background())
	_, _ = svc.localSandboxStateForCluster(context.Background(), cl, sb)
}

func TestClusterOwnershipReplayGapsWave20(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	_ = st.Close()
	if _, err := svc.ReplayClusterOwnership(ctx); err == nil {
		t.Fatal("expected list failure")
	}

	svc2, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.cfg.EnableCluster = true
	svc2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc2.cipher = newTestCipher(t)
	c := &fakeOwnershipCluster{
		Noop: cluster.NewNoop("self", "http://self", "self.example.com"),
		placements: map[string]cluster.Placement{
			"sb-other": {
				SandboxID: "sb-other", OwnerNodeID: "other",
				State: cluster.PlacementStatePlaced,
				Spec:  &models.CreateSandboxRequest{Image: "a"},
			},
			"sb-nil-spec": {
				SandboxID: "sb-nil-spec", OwnerNodeID: "self",
				State: cluster.PlacementStatePlaced, Spec: nil,
			},
			"sb-tpl": {
				SandboxID: "sb-tpl", OwnerNodeID: "self",
				State: cluster.PlacementStatePlaced,
				Spec:  &models.CreateSandboxRequest{Image: "a", TemplateID: "old"},
			},
			"sb-orphan-other": {
				SandboxID: "sb-orphan-other", OwnerState: cluster.PlacementOwnerStateOrphaned,
				OrphanedOwnerNodeID: "other-node", State: cluster.PlacementStatePlaced,
			},
		},
	}
	svc2.cluster = c
	now := time.Now().UTC()
	for _, sb := range []*models.Sandbox{
		{ID: "sb-other", Image: "a", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now},
		{ID: "sb-nil-spec", Image: "a", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now},
		{ID: "sb-tpl", Image: "a", TemplateID: "new", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now},
		{ID: "sb-orphan-other", Image: "a", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now},
	} {
		_ = clusterOwnershipNeedsReplayCall(svc2, c, sb)
	}

	// localSandboxStateForCluster: PutClusterSecrets + loadMounts fail when store is closed; nil ctx.
	svc3, st3, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc3.cfg.EnableCluster = true
	svc3.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc3.cipher = newTestCipher(t)
	sealed, err := svc3.sealRegistry(&models.RegistryAuth{Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("sealRegistry: %v", err)
	}
	sb := &models.Sandbox{
		ID: "sb-sec", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 2, RegistryAuthSealed: sealed,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	_ = st3.Create(ctx, sb)
	c3 := &fakeOwnershipCluster{Noop: cluster.NewNoop("self", "http://self", "")}
	_ = st3.Close()
	_, _ = svc3.localSandboxStateForCluster(ctx, c3, sb)
	_, _ = svc3.specFromSandbox(nil, sb)
}

func clusterOwnershipNeedsReplayCall(svc *Service, c cluster.Client, sb *models.Sandbox) bool {
	return svc.clusterOwnershipNeedsReplay(c, sb)
}

func TestClusterOwnershipNilClusterWave21(t *testing.T) {
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: nil, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	n, err := svc.assertClusterOwnership(context.Background(), nil, nil)
	if n != 0 || err != nil {
		t.Fatalf("nil cluster = %d %v", n, err)
	}
}

func TestClusterOwnershipPortsMismatchWave24(t *testing.T) {
	svc := &Service{cfg: config.Config{EnableCluster: true}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c := &fakeOwnershipCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		placements: map[string]cluster.Placement{
			"sb-ports": {
				SandboxID: "sb-ports", OwnerNodeID: "self", State: cluster.PlacementStatePlaced,
				Spec: &models.CreateSandboxRequest{Image: "a"},
				ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
					8080: {Protocol: models.ExposedPortProtocolHTTP, HostPort: 1, PublicURL: "http://x"},
				},
			},
		},
	}
	sb := &models.Sandbox{
		ID: "sb-ports", Image: "a", Status: models.SandboxStatusStarted,
		ExposedPorts: []models.ExposedPort{{Port: 8080, Protocol: models.ExposedPortProtocolHTTP, HostPort: 2, PublicURL: "http://y"}},
	}
	if !svc.clusterOwnershipNeedsReplay(c, sb) {
		t.Fatal("port mismatch should need replay")
	}
}
