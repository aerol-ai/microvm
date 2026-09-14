package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

type fakeOwnershipCluster struct {
	*cluster.Noop
	placements map[string]cluster.Placement
	members    []cluster.Member
	asserted   []cluster.LocalSandboxState
	assertErr  error
}

func (c *fakeOwnershipCluster) PlacementOf(sandboxID string) (cluster.Placement, bool) {
	p, ok := c.placements[sandboxID]
	return p, ok
}

func (c *fakeOwnershipCluster) AssertOwnership(_ context.Context, local []cluster.LocalSandboxState) error {
	c.asserted = append(c.asserted, local...)
	return c.assertErr
}

func (c *fakeOwnershipCluster) LocalMembers() []cluster.Member {
	return append([]cluster.Member(nil), c.members...)
}

func (c *fakeOwnershipCluster) Members() []cluster.Member {
	return append([]cluster.Member(nil), c.members...)
}

func TestClusterOwnershipHelpers(t *testing.T) {
	svc := &Service{
		cfg:    config.Config{EnableCluster: true},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	c := &fakeOwnershipCluster{
		Noop:       cluster.NewNoop("self", "http://self", "self.example.com"),
		placements: map[string]cluster.Placement{},
	}
	svc.cluster = c

	now := time.Now().UTC()
	sandbox := &models.Sandbox{
		ID:         "sb-owned",
		Runtime:    models.RuntimeFirecracker,
		Status:     models.SandboxStatusStopped,
		Image:      "alpine:3.20",
		TemplateID: "tpl-1",
		CPU:        1,
		MemoryMB:   256,
		DiskGB:     2,
		Failover:   &models.Failover{Policy: models.FailoverPolicyRecreate},
		ExposedPorts: []models.ExposedPort{
			{Port: 8080, Protocol: models.ExposedPortProtocolHTTP, HostPort: 18080, PublicURL: "http://example"},
		},
		CustomDomains: []models.CustomDomain{
			{Hostname: "api.acme.com"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if got := svc.clusterOwnershipNeedsReplay(c, sandbox); !got {
		t.Fatal("missing placement should require replay")
	}

	orphanPlacement := cluster.Placement{
		SandboxID:           sandbox.ID,
		OwnerState:          cluster.PlacementOwnerStateOrphaned,
		OrphanedOwnerNodeID: "self",
		State:               cluster.PlacementStatePlaced,
	}
	if got := svc.clusterOwnershipNeedsReplay(&fakeOwnershipCluster{Noop: c.Noop, placements: map[string]cluster.Placement{sandbox.ID: orphanPlacement}}, sandbox); !got {
		t.Fatal("orphaned placement owned by self should require replay")
	}

	reservedPlacement := cluster.Placement{
		SandboxID:   sandbox.ID,
		OwnerNodeID: "self",
		State:       cluster.PlacementStateReserved,
	}
	if got := svc.clusterOwnershipNeedsReplay(&fakeOwnershipCluster{Noop: c.Noop, placements: map[string]cluster.Placement{sandbox.ID: reservedPlacement}}, sandbox); !got {
		t.Fatal("reserved placement should require replay")
	}

	matchingSpec := &models.CreateSandboxRequest{
		Image:         sandbox.Image,
		CPU:           sandbox.CPU,
		MemoryMB:      sandbox.MemoryMB,
		DiskGB:        sandbox.DiskGB,
		TemplateID:    sandbox.TemplateID,
		OverlaySizeGB: sandbox.OverlaySizeGB,
		Failover:      &models.Failover{Policy: models.FailoverPolicyNone},
	}
	matchPlacement := cluster.Placement{
		SandboxID:   sandbox.ID,
		OwnerNodeID: "self",
		Spec:        matchingSpec,
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			8080: {Protocol: models.ExposedPortProtocolHTTP, HostPort: 18080, PublicURL: "http://example"},
		},
		CustomHostnames: []string{"api.acme.com"},
	}
	fakeMatch := &fakeOwnershipCluster{Noop: c.Noop, placements: map[string]cluster.Placement{sandbox.ID: matchPlacement}}
	if got := svc.clusterOwnershipNeedsReplay(fakeMatch, sandbox); got {
		t.Fatal("matching placement should not require replay")
	}

	if got := placementMissingLocalPorts(matchPlacement, sandbox); got {
		t.Fatal("matching local ports should not be reported missing")
	}
	mismatchedPorts := matchPlacement
	mismatchedPorts.ExposedPortRoutes = map[int]cluster.ExposedPortRoute{8080: {Protocol: models.ExposedPortProtocolHTTP}}
	if got := placementMissingLocalPorts(mismatchedPorts, sandbox); !got {
		t.Fatal("missing route metadata should require replay")
	}
	if got := placementMissingLocalCustomHostnames(matchPlacement, sandbox); got {
		t.Fatal("matching custom hostnames should not be reported missing")
	}
	missingHostname := matchPlacement
	missingHostname.CustomHostnames = nil
	if got := placementMissingLocalCustomHostnames(missingHostname, sandbox); !got {
		t.Fatal("missing custom hostname should require replay")
	}

	svc.cipher = newTestCipher(t)
	badRegistry := *sandbox
	badRegistry.RegistryAuthSealed = []byte("bad-seal")
	if spec, err := svc.specFromSandbox(context.Background(), &badRegistry); err == nil || spec != nil {
		t.Fatalf("specFromSandbox invalid registry = %+v, %v; want fail-closed error", spec, err)
	}
	if spec, err := svc.specFromSandbox(context.Background(), nil); err != nil || spec != nil {
		t.Fatalf("specFromSandbox(nil) = %+v, %v; want nil", spec, err)
	}
}

func TestLocalSandboxStateForClusterIncludesStoredMounts(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.cipher = newTestCipher(t)

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:                 "sb-mounted",
		Runtime:            models.RuntimeDocker,
		Status:             models.SandboxStatusStarted,
		Image:              "alpine:3.20",
		CPU:                1,
		MemoryMB:           256,
		DiskGB:             2,
		AuditIncarnationID: "inc-sb-mounted",
		CreatedAt:          now,
		UpdatedAt:          now,
		LastActiveAt:       now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	mountSpec := models.MountSpec{Type: models.MountTypeNFS, Source: "nfs.example:/export", Target: "/data"}
	sealed, err := svc.sealMounts([]models.MountSpec{mountSpec})
	if err != nil {
		t.Fatalf("seal mounts: %v", err)
	}
	if err := st.PutMounts(ctx, sb.ID, sealed); err != nil {
		t.Fatalf("PutMounts: %v", err)
	}

	c := &fakeOwnershipCluster{
		Noop:       cluster.NewNoop("self", "http://self", "self.example.com"),
		placements: map[string]cluster.Placement{},
	}
	state, err := svc.localSandboxStateForCluster(ctx, c, sb)
	if err != nil {
		t.Fatal(err)
	}
	if state.Spec == nil || len(state.Spec.Mounts) != 1 || state.Spec.Mounts[0].Target != "/data" {
		t.Fatalf("localSandboxStateForCluster mounts = %+v", state.Spec)
	}
}

func TestLocalSandboxStateForClusterNeverReplicatesPlaintextWhenSealFails(t *testing.T) {
	svc := &Service{cfg: config.Config{EnableCluster: true}}
	c := &fakeOwnershipCluster{
		Noop:       cluster.NewNoop("self", "http://self", "self.example.com"),
		placements: map[string]cluster.Placement{},
	}
	sb := &models.Sandbox{
		ID:                 "sb-seal-fail",
		Image:              "alpine:3.20",
		Env:                map[string]string{"TOKEN": "must-not-enter-raft"},
		AuditIncarnationID: "inc-seal-fail",
	}
	state, err := svc.localSandboxStateForCluster(context.Background(), c, sb)
	if err == nil {
		t.Fatal("ownership replay accepted plaintext credentials without a secret provider")
	}
	if state.Spec != nil || state.Secrets.Ref != "" {
		t.Fatalf("failed replay returned publishable state: %+v", state)
	}
}

func TestLocalSandboxStateForClusterKeepsHAFanoutOnOwnershipReplay(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	c := &fakeOwnershipCluster{
		Noop:       cluster.NewNoop("self", "http://self", "self.example.com"),
		placements: map[string]cluster.Placement{},
		members: []cluster.Member{
			{NodeID: "self", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "node-b", Alive: true, Role: config.NodeRoleWorker},
			{NodeID: "node-c", Alive: true, Role: config.NodeRoleWorker},
		},
	}
	svc := &Service{
		cfg: config.Config{EnableCluster: true, SecretRecipientBackupCount: 2}, store: st, cipher: cipher,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)), cluster: c,
		testSecretPeerPusher: &fakePeerPusher{acked: []string{"node-b"}},
	}
	sb := &models.Sandbox{
		ID: "sb-ha-replay", Image: "alpine", Env: map[string]string{"TOKEN": "secret"},
		AuditIncarnationID: "inc-ha-replay", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	state, err := svc.localSandboxStateForCluster(ctx, c, sb)
	if err != nil {
		t.Fatal(err)
	}
	if got := secrets.NormalizeRecipients(state.Secrets.Recipients); len(got) != 3 || !sameStringSlice(got, []string{"node-b", "node-c", "self"}) {
		t.Fatalf("ownership replay recipients = %v, want owner plus two backups", state.Secrets.Recipients)
	}
}

func TestAssertClusterOwnershipSkipsUnsafeRowWithoutStarvingSafeRows(t *testing.T) {
	svc := &Service{cfg: config.Config{EnableCluster: true}}
	c := &fakeOwnershipCluster{
		Noop:       cluster.NewNoop("self", "http://self", "self.example.com"),
		placements: map[string]cluster.Placement{},
	}
	svc.cluster = c
	unsafe := &models.Sandbox{
		ID:                 "sb-unsafe",
		Image:              "alpine:3.20",
		Status:             models.SandboxStatusStarted,
		Env:                map[string]string{"TOKEN": "must-not-enter-raft"},
		AuditIncarnationID: "inc-unsafe",
	}
	safe := &models.Sandbox{
		ID:                 "sb-safe",
		Image:              "alpine:3.20",
		Status:             models.SandboxStatusStarted,
		AuditIncarnationID: "inc-safe",
	}
	count, err := svc.assertClusterOwnership(context.Background(), []*models.Sandbox{unsafe, safe}, nil)
	if err == nil {
		t.Fatal("unsafe ownership row failure was not reported")
	}
	if count != 1 || len(c.asserted) != 1 || c.asserted[0].ID != safe.ID {
		t.Fatalf("safe ownership rows were starved: count=%d asserted=%+v", count, c.asserted)
	}
}

func TestClusterOwnershipReplayAndReconcileErrors(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.cipher = newTestCipher(t)

	now := time.Now().UTC()
	sealedRegistry, err := svc.sealRegistry(&models.RegistryAuth{Server: "registry.example", Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("seal replay registry: %v", err)
	}
	replaySandbox := &models.Sandbox{
		ID:                 "sb-replay",
		Runtime:            models.RuntimeFirecracker,
		Status:             models.SandboxStatusStopped,
		Image:              "alpine:3.20",
		TemplateID:         "tpl-2",
		CPU:                1,
		MemoryMB:           256,
		DiskGB:             2,
		RegistryAuthSealed: sealedRegistry,
		ExposedPorts: []models.ExposedPort{
			{Port: 8080, Protocol: models.ExposedPortProtocolHTTP, HostPort: 18080, PublicURL: "http://example"},
		},
		CustomDomains: []models.CustomDomain{{Hostname: "api.acme.com"}},
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := st.Create(ctx, replaySandbox); err != nil {
		t.Fatalf("seed replay sandbox: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: replaySandbox.ID,
		Port:      8080,
		Protocol:  models.ExposedPortProtocolHTTP,
		HostPort:  18080,
		PublicURL: "http://example",
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertPort: %v", err)
	}
	if err := st.AddCustomDomain(ctx, replaySandbox.ID, "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}

	fakeReplay := &fakeOwnershipCluster{Noop: cluster.NewNoop("self", "http://self", "self.example.com"), placements: map[string]cluster.Placement{}}
	svc.cluster = fakeReplay

	count, err := svc.ReplayClusterOwnership(ctx)
	if err != nil {
		t.Fatalf("ReplayClusterOwnership: %v", err)
	}
	if count != 1 {
		t.Fatalf("ReplayClusterOwnership count = %d, want 1", count)
	}
	if len(fakeReplay.asserted) != 1 {
		t.Fatalf("AssertOwnership states = %d, want 1", len(fakeReplay.asserted))
	}
	if fakeReplay.asserted[0].Spec == nil || fakeReplay.asserted[0].Spec.Failover != nil {
		t.Fatalf("replayed spec should be redacted and failover-cleared: %+v", fakeReplay.asserted[0].Spec)
	}
	if fakeReplay.asserted[0].ExposedPorts[8080].HostPort != 18080 {
		t.Fatalf("replayed port metadata = %+v", fakeReplay.asserted[0].ExposedPorts)
	}
	if len(fakeReplay.asserted[0].CustomHostnames) != 1 || fakeReplay.asserted[0].CustomHostnames[0] != "api.acme.com" {
		t.Fatalf("replayed custom hostnames = %+v", fakeReplay.asserted[0].CustomHostnames)
	}

	svc.cluster = &fakeOwnershipCluster{
		Noop:       cluster.NewNoop("self", "http://self", "self.example.com"),
		placements: map[string]cluster.Placement{},
	}
	svc.cluster.(*fakeOwnershipCluster).placements[replaySandbox.ID] = cluster.Placement{}
	svc.cluster.(*fakeOwnershipCluster).assertErr = errors.New("replay failed")
	svc.reconcileLocalClusterOwnership(ctx, []*models.Sandbox{replaySandbox}, nil)
}

func TestClusterOwnershipAssertBranches(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true

	rec := &fakeOwnershipCluster{
		Noop:       cluster.NewNoop("self", "http://self", "self.example.com"),
		placements: map[string]cluster.Placement{},
	}
	svc.cluster = rec

	now := time.Now().UTC()
	running := &models.Sandbox{
		ID:           "sb-run",
		Runtime:      models.RuntimeDocker,
		Status:       models.SandboxStatusStarted,
		Image:        "alpine:3.20",
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}
	stopped := &models.Sandbox{
		ID:           "sb-stop",
		Runtime:      models.RuntimeFirecracker,
		Status:       models.SandboxStatusStopped,
		Image:        "alpine:3.20",
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}

	count, err := svc.assertClusterOwnership(ctx, []*models.Sandbox{
		nil,
		&models.Sandbox{},
		&models.Sandbox{ID: "sb-destroyed", Status: models.SandboxStatusDestroyed},
		running,
		stopped,
	}, map[string]*models.SandboxRuntimeState{})
	if err != nil {
		t.Fatalf("assertClusterOwnership: %v", err)
	}
	if count != 1 {
		t.Fatalf("assertClusterOwnership count = %d, want 1", count)
	}
	if len(rec.asserted) != 1 || rec.asserted[0].ID != "sb-stop" {
		t.Fatalf("asserted states = %+v, want only the stopped firecracker sandbox", rec.asserted)
	}

	count, err = svc.assertClusterOwnership(ctx, []*models.Sandbox{nil, &models.Sandbox{}}, nil)
	if err != nil {
		t.Fatalf("assertClusterOwnership empty = %v", err)
	}
	if count != 0 {
		t.Fatalf("assertClusterOwnership empty count = %d, want 0", count)
	}
}
