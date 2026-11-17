package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// rebuildCluster is a cluster that knows one placement, the one a rebuild
// asks about.
type rebuildCluster struct {
	*cluster.Noop
	p cluster.Placement
}

func (c rebuildCluster) PlacementOf(id string) (cluster.Placement, bool) {
	return c.p, id == c.p.SandboxID
}

func (c rebuildCluster) SpecOf(id string) *models.CreateSandboxRequest {
	if id != c.p.SandboxID {
		return nil
	}
	return c.p.Spec
}

// hostPathResolver says which bare module names are host files.
type hostPathResolver struct{ hostFiles map[string]bool }

func (hostPathResolver) Resolve(context.Context, string) (*wasmmod.ResolvedModule, error) {
	return nil, errors.New("not resolved in this test")
}

func (r hostPathResolver) HostPathRef(_ context.Context, ref string) bool { return r.hostFiles[ref] }

func rebuildService(t *testing.T, p cluster.Placement) *Service {
	t.Helper()
	svc := &Service{cfg: config.Config{
		EnableCluster:       true,
		OperatorVolumeScope: "op-main",
		PlatformVolumes: config.PlatformVolumesConfig{
			Enabled: true, Backend: config.PlatformVolumesBackendS3, S3Bucket: "vols", S3Prefix: "pfx", S3Region: "eu-west-1",
		},
	}}
	svc.AttachCluster(rebuildCluster{Noop: cluster.NewNoop("wkr-b", "http://wkr-b", ""), p: p})
	svc.SetWasmModuleResolver(hostPathResolver{hostFiles: map[string]bool{"staged.wasm": true}})
	return svc
}

// A node rebuilding a sandbox it never had takes the owner's platform
// volumes, as it builds them itself, and the cluster's hostnames for it;
// it refuses anything only a host-capable caller may set.
func TestRebuildSpecWithoutHostPowers(t *testing.T) {
	const owner = "team:payments"
	tenant := volumes.TenantForOwnerRef(owner)
	vol := models.MountSpec{Type: models.MountTypeS3, Source: "vols/pfx/" + tenant + "/data", Target: "/data", ReadOnly: true,
		Options: map[string]string{"endpoint": "http://elsewhere.example"}}
	for _, tc := range []struct {
		name    string
		owner   string
		spec    models.CreateSandboxRequest
		refused string
		check   func(t *testing.T, got models.CreateSandboxRequest)
	}{
		{name: "the owner's volume, built here", owner: owner, spec: models.CreateSandboxRequest{Image: "alpine", Mounts: []models.MountSpec{vol}},
			check: func(t *testing.T, got models.CreateSandboxRequest) {
				m := got.Mounts[0]
				if m.Source != vol.Source || m.Target != "/data" || !m.ReadOnly || m.Options["endpoint"] != "" || m.Options["region"] != "eu-west-1" {
					t.Fatalf("rebuilt mount %+v", m)
				}
			}},
		{name: "an operator sandbox's volume", owner: "", spec: models.CreateSandboxRequest{Image: "alpine",
			Mounts: []models.MountSpec{{Type: models.MountTypeS3, Source: "vols/pfx/op-main/data", Target: "/d"}}}},
		{name: "another team's volume", owner: owner, refused: "mounts", spec: models.CreateSandboxRequest{Image: "alpine",
			Mounts: []models.MountSpec{{Type: models.MountTypeS3, Source: "vols/pfx/" + volumes.TenantForOwnerRef("team:other") + "/data", Target: "/d"}}}},
		{name: "the owner's name in another bucket", owner: owner, refused: "mounts", spec: models.CreateSandboxRequest{Image: "alpine",
			Mounts: []models.MountSpec{{Type: models.MountTypeS3, Source: "other-bucket/pfx/" + tenant + "/data", Target: "/d"}}}},
		{name: "a raw mount", owner: owner, refused: "mounts", spec: models.CreateSandboxRequest{Image: "alpine",
			Mounts: []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://other-bucket", Target: "/d"}}}},
		{name: "a wasm module staged on the host", owner: owner, refused: "module_ref", spec: models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "staged.wasm"}},
		{name: "a wasm module from a file", owner: owner, refused: "module_ref", spec: models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "file:///etc/x.wasm"}},
		{name: "a wasm keyword", owner: owner, spec: models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "python"}},
		{name: "a js bundle from a file", owner: owner, refused: "module_ref", spec: models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "file:///srv/w.js"}},
		{name: "unresolved platform volumes", owner: owner, refused: "platform_volumes", spec: models.CreateSandboxRequest{Image: "alpine",
			PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/d"}}}},
		{name: "custom hostnames the cluster binds to it", owner: owner, spec: models.CreateSandboxRequest{Image: "alpine",
			CustomDomains: []string{"app.customer.com", "gone.customer.com"}},
			check: func(t *testing.T, got models.CreateSandboxRequest) {
				if strings.Join(got.CustomDomains, ",") != "app.customer.com" {
					t.Fatalf("custom domains %v", got.CustomDomains)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := tc.spec
			svc := rebuildService(t, cluster.Placement{SandboxID: "sb-r", OwnerRef: tc.owner, Spec: &spec, CustomHostnames: []string{"app.customer.com"}})
			got, err := svc.rebuildSpecWithoutHostPowers(context.Background(), "sb-r", tc.spec)
			if tc.refused != "" {
				if !errors.Is(err, cluster.ErrHostOnlySpec) || !strings.Contains(err.Error(), tc.refused) {
					t.Fatalf("err = %v, want a refusal naming %s", err, tc.refused)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
	// A node that serves no platform volumes takes none.
	spec := models.CreateSandboxRequest{Image: "alpine", Mounts: []models.MountSpec{vol}}
	svc := rebuildService(t, cluster.Placement{SandboxID: "sb-r", OwnerRef: owner, Spec: &spec})
	svc.cfg.PlatformVolumes.Enabled = false
	if _, err := svc.rebuildSpecWithoutHostPowers(context.Background(), "sb-r", spec); !errors.Is(err, cluster.ErrHostOnlySpec) {
		t.Fatalf("volumes off: %v", err)
	}
}

// The rebuild's create has no host powers: the mount gate refuses a raw
// mount under it, and lets through only the mounts the rebuild built.
func TestRebuildContextHasNoHostPowers(t *testing.T) {
	ctx := context.Background()
	if !hostCapable(ctx) || hostCapable(controlplane.ContextWithoutHostPowers(ctx)) || hostCapable(rebuildContext(ctx)) {
		t.Fatal("host powers under the rebuild markers")
	}
	if !wasmmod.HostPathsDenied(rebuildContext(ctx)) {
		t.Fatal("a rebuild may read a module from a host path")
	}
	svc := &Service{}
	mounts := []models.MountSpec{{Type: models.MountTypeS3, Source: "b/p", Target: "/data"}}
	if err := svc.validateCreateMounts(controlplane.ContextWithoutHostPowers(ctx), mounts, "sb"); !errors.Is(err, models.ErrMountOperatorOnly) {
		t.Fatalf("raw mount without host powers = %v", err)
	}
	if err := svc.validateCreateMounts(rebuildContext(ctx), mounts, "sb"); err != nil {
		t.Fatalf("rebuilt mounts = %v", err)
	}
}

// A failover recreate of a sandbox with a raw mount is refused before
// anything is created, with the error the owner watcher stops on.
func TestRecreateRefusesHostOnlySettings(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	spec := models.CreateSandboxRequest{Image: "alpine:3.20", Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
		Mounts: []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://other-bucket", Target: "/data"}}}
	err := svc.RecreateSandbox(ctx, "sb-host", spec, cluster.PlacementSecrets{}, nil)
	if !errors.Is(err, cluster.ErrHostOnlySpec) {
		t.Fatalf("recreate = %v, want ErrHostOnlySpec", err)
	}
	if rt.createCalls != 0 {
		t.Fatalf("runtime Create calls = %d", rt.createCalls)
	}
	if _, err := st.Get(ctx, "sb-host"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("row after a refused rebuild = %v", err)
	}
}

// A WASM sandbox whose module is a host file is neither migrated nor
// imported: the leader refuses the move up front, and a node asked to
// import it refuses too.
func TestWasmMigrationRefusesHostModule(t *testing.T) {
	spec := models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "/opt/modules/x.wasm"}
	svc := rebuildService(t, cluster.Placement{SandboxID: "sb-w", OwnerRef: "team:payments", Spec: &spec})
	if _, err := svc.MigrateWasmSandboxToNode(context.Background(), "sb-w", "wkr-c"); !errors.Is(err, cluster.ErrHostOnlySpec) {
		t.Fatalf("migrate = %v", err)
	}
	rt := &recordingRuntime{}
	imp, _, _ := newServiceRuntimeHarness(t, rt)
	imp.AttachCluster(rebuildCluster{Noop: cluster.NewNoop("wkr-c", "http://wkr-c", ""), p: cluster.Placement{SandboxID: "sb-w", OwnerRef: "team:payments", Spec: &spec}})
	if err := imp.ensureWasmSandboxRowForImport(context.Background(), "sb-w", wasmengine.SnapshotRestoreInput{}, "/tmp/ck", "g1"); !errors.Is(err, cluster.ErrHostOnlySpec) {
		t.Fatalf("import = %v", err)
	}
}

// A gateway routes a placement's customer hostnames to its owner, and none
// of the cluster's own names, whatever the placement holds.
func TestGatewaySkipsClusterHostnames(t *testing.T) {
	public := true
	svc := &Service{
		cfg:   config.Config{EnableCluster: true, NodeRole: config.NodeRoleIngress, Domain: "sb.example.com", PublicHost: "api.example.com", L4TLSListen: ":443"},
		caddy: caddy.New(config.Config{EnableCaddy: true, HTTPClientTimeout: time.Second}),
	}
	p := cluster.Placement{
		SandboxID: "sb-w", OwnerNodeID: "wkr-9", OwnerAPIURL: "http://10.0.0.9:21212", Version: 3,
		Spec:            &models.CreateSandboxRequest{Image: "alpine", AllowPublicTraffic: &public},
		CustomHostnames: []string{"api.sb.example.com", "sb-other.sb.example.com", "api.example.com", "app.customer.com"},
	}
	intents, _ := svc.buildClusterIngressIntents([]cluster.Placement{p}, "gw-1")
	var routed []string
	for _, host := range p.CustomHostnames {
		if _, ok := intents[ingressIntentKey(ingressSurfaceTLS, caddy.IngressCustomDomainSNIRouteID("sb-w", host))]; ok {
			routed = append(routed, host)
		}
	}
	if strings.Join(routed, ",") != "app.customer.com" {
		t.Fatalf("routed %v, want only the customer hostname", routed)
	}
}

// txtRecords is a DNS view: name → TXT values.
type txtRecords map[string][]string

func (r txtRecords) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := r[name]; ok {
		return v, nil
	}
	return nil, errors.New("no such host")
}

// A failover recreate's create runs without host powers, and its custom
// hostnames the cluster already binds to it need no new DNS proof.
func TestRecreateRunsWithoutHostPowers(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	if err := svc.RecreateSandbox(ctx, "sb-plain", models.CreateSandboxRequest{Image: "alpine:3.20"}, cluster.PlacementSecrets{}, nil); err != nil {
		t.Fatal(err)
	}
	if rt.createCalls != 1 || rt.lastCreateHostCapable {
		t.Fatalf("create calls %d, host powers %v", rt.createCalls, rt.lastCreateHostCapable)
	}

	svc.SetDNSResolver(txtRecords{})
	if err := svc.persistCustomDomainsOnCreate(controlplane.ContextWithoutHostPowers(ctx), "sb-plain", []string{"app.customer.com"}); err == nil {
		t.Fatal("no host powers, no proof: a hostname was taken")
	}
	if err := svc.persistCustomDomainsOnCreate(rebuildContext(ctx), "sb-plain", []string{"app.customer.com"}); err != nil {
		t.Fatalf("a rebuild's held hostname: %v", err)
	}
}

// A platform volume rebuilds from its record: a volume made before the
// operator changed the bucket mounts where it was made, and an operator's
// volume rebuilds on a node with no operator token or pinned scope. A
// mount no record of this sandbox's incarnation names falls back to this
// node's configuration; a record that cannot be read is retried, not
// refused.
func TestRebuildPlatformMountsFromRecords(t *testing.T) {
	const owner = "team:payments"
	tenant := volumes.TenantForOwnerRef(owner)
	old := "vols-old/p0/" + tenant + "/data"
	vol := models.Volume{ID: "v1", Tenant: tenant, Name: "data", Backend: config.PlatformVolumesBackendS3, Source: old}
	att := models.VolumeAttachment{Tenant: tenant, VolumeID: "v1", SandboxID: "sb-v", IncarnationID: "inc-v", Target: "/data", Source: old}
	oldMount := models.MountSpec{Type: models.MountTypeS3, Source: old, Target: "/data"}
	here := models.MountSpec{Type: models.MountTypeS3, Source: "vols/pfx/" + tenant + "/data", Target: "/data"}
	rebuild := func(t *testing.T, ownerRef string, meta *scriptedVolumeMeta, mounts ...models.MountSpec) (models.CreateSandboxRequest, error) {
		t.Helper()
		svc := rebuildService(t, cluster.Placement{SandboxID: "sb-v", IncarnationID: "inc-v", OwnerRef: ownerRef})
		svc.testVolumeMeta = meta
		return svc.rebuildSpecWithoutHostPowers(context.Background(), "sb-v", models.CreateSandboxRequest{Image: "alpine", Mounts: mounts})
	}
	got, err := rebuild(t, owner, &scriptedVolumeMeta{forSandbox: []models.VolumeAttachment{att}, byID: &vol}, oldMount)
	if err != nil || got.Mounts[0].Source != old || got.Mounts[0].Options["region"] != "eu-west-1" {
		t.Fatalf("a volume made before the bucket changed: %+v %v", got.Mounts, err)
	}

	opVol := models.Volume{ID: "v2", Tenant: "op-other", Name: "shared", Backend: config.PlatformVolumesBackendS3, Source: "vols/pfx/op-other/shared"}
	opAtt := models.VolumeAttachment{Tenant: "op-other", VolumeID: "v2", SandboxID: "sb-v", Target: "/shared", Source: opVol.Source}
	svc := rebuildService(t, cluster.Placement{SandboxID: "sb-v", IncarnationID: "inc-v"})
	svc.cfg.OperatorVolumeScope, svc.cfg.PATToken = "", ""
	svc.testVolumeMeta = &scriptedVolumeMeta{forSandbox: []models.VolumeAttachment{opAtt}, byID: &opVol}
	if _, err := svc.rebuildSpecWithoutHostPowers(context.Background(), "sb-v", models.CreateSandboxRequest{Image: "alpine",
		Mounts: []models.MountSpec{{Type: models.MountTypeS3, Source: opVol.Source, Target: "/shared"}}}); err != nil {
		t.Fatalf("an operator's volume on a node with no operator scope: %v", err)
	}

	otherInc := att
	otherInc.IncarnationID = "inc-earlier"
	for name, tc := range map[string]struct {
		meta    *scriptedVolumeMeta
		mount   models.MountSpec
		refused bool
	}{
		"another incarnation's record, the old location": {&scriptedVolumeMeta{forSandbox: []models.VolumeAttachment{otherInc}, byID: &vol}, oldMount, true},
		"no record, this node's location":                {&scriptedVolumeMeta{}, here, false},
		"no record, the old location":                    {&scriptedVolumeMeta{}, oldMount, true},
		"the volume is gone":                             {&scriptedVolumeMeta{forSandbox: []models.VolumeAttachment{att}, byIDErr: storepkg.ErrNotFound}, oldMount, true},
	} {
		_, err := rebuild(t, owner, tc.meta, tc.mount)
		if tc.refused != errors.Is(err, cluster.ErrHostOnlySpec) || !tc.refused && err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A record another team's sandbox holds is not this sandbox's.
	if _, err := rebuild(t, "team:other", &scriptedVolumeMeta{forSandbox: []models.VolumeAttachment{att}, byID: &vol}, oldMount); !errors.Is(err, cluster.ErrHostOnlySpec) {
		t.Fatalf("another team's volume = %v", err)
	}
	for name, meta := range map[string]*scriptedVolumeMeta{
		"attachments": {forSandboxErr: errors.New("control plane unreachable")},
		"the volume":  {forSandbox: []models.VolumeAttachment{att}, byIDErr: errors.New("control plane unreachable")},
	} {
		if _, err := rebuild(t, owner, meta, oldMount); err == nil || errors.Is(err, cluster.ErrHostOnlySpec) {
			t.Errorf("%s unreadable = %v, want a retryable error", name, err)
		}
	}
	// A node with no platform volumes rebuilds none.
	svc = rebuildService(t, cluster.Placement{SandboxID: "sb-v", IncarnationID: "inc-v", OwnerRef: owner})
	svc.cfg.PlatformVolumes.Enabled = false
	if _, err := svc.rebuildSpecWithoutHostPowers(context.Background(), "sb-v", models.CreateSandboxRequest{Image: "alpine", Mounts: []models.MountSpec{here}}); !errors.Is(err, cluster.ErrHostOnlySpec) {
		t.Fatalf("platform volumes off = %v", err)
	}
}
