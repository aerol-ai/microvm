package service

import (
	"context"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/runtime"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// envStartRuntime is a runtime whose start re-adopts a warm-pool container
// with the sandbox's env, as containerd's does for one adopted with env. It
// calls the loader the way the driver does, so a test sees what the
// re-adopt frame would carry.
type envStartRuntime struct {
	runtime.ContainerRuntime
	start                   func(context.Context, string) (*models.SandboxRuntimeState, error)
	gotRef, gotID, gotToken string
	loaded                  map[string]string
	loadErr                 error
	identityStarts          int
}

func (r *envStartRuntime) StartWithIdentityEnv(ctx context.Context, containerRef, sandboxID, toolboxToken string, loadEnv runtime.AdoptEnvLoader) (*models.SandboxRuntimeState, error) {
	r.gotRef, r.gotID, r.gotToken = containerRef, sandboxID, toolboxToken
	r.loaded, r.loadErr = loadEnv(ctx)
	if r.loadErr != nil {
		return nil, r.loadErr
	}
	return r.start(ctx, containerRef)
}

func (r *envStartRuntime) StartWithIdentity(ctx context.Context, containerRef, _, _ string) (*models.SandboxRuntimeState, error) {
	r.identityStarts++
	return r.start(ctx, containerRef)
}

// A start hands an env-carrying runtime the sandbox's identity and a loader
// for the env StartSandbox already decrypted from the sealed row, and uses
// that path over the env-less one.
func TestStartSandboxPassesTheLoadedEnvToTheRuntime(t *testing.T) {
	ctx := context.Background()
	base := &recordingRuntime{startState: &models.SandboxRuntimeState{
		SandboxID: "sb-envst", ContainerID: "park-envst", ContainerIP: "10.0.0.61", Status: models.SandboxStatusStarted,
	}}
	svc, st, _ := newServiceRuntimeHarness(t, base)
	rt := &envStartRuntime{ContainerRuntime: base, start: base.Start}
	svc.docker = rt

	now := time.Now().UTC()
	env := map[string]string{"API_KEY": envCanaryValue, "MODE": "prod"}
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-envst", Image: "alpine:3.20", Status: models.SandboxStatusStopped,
		ContainerID: "park-envst", ContainerIP: "10.0.0.60", Runtime: models.RuntimeDocker,
		ToolboxToken: "envst-token", CPU: 1, MemoryMB: 512, DiskGB: 10,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now, AuditIncarnationID: "inc-envst",
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	sealed, err := svc.sealEnv("sb-envst", "inc-envst", env)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnv(ctx, "sb-envst", sealed); err != nil {
		t.Fatal(err)
	}

	got, err := svc.StartSandbox(ctx, "sb-envst")
	if err != nil {
		t.Fatalf("StartSandbox: %v", err)
	}
	if rt.identityStarts != 0 {
		t.Fatal("the start took the env-less identity path")
	}
	if rt.gotRef != "park-envst" || rt.gotID != "sb-envst" || rt.gotToken != "envst-token" {
		t.Fatalf("StartWithIdentityEnv(%q, %q, %q)", rt.gotRef, rt.gotID, rt.gotToken)
	}
	if !maps.Equal(rt.loaded, env) {
		t.Fatalf("the loader returned %d keys, want the sealed env's %d", len(rt.loaded), len(env))
	}
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("started sandbox = %+v", got)
	}
}

// envCanaryValue stands in for a secret in these tests.
const envCanaryValue = "canary-service-env-71aa"

// A create that withholds a key (P3-2) hands the driver a placeholder for
// it; the re-adopt on start must carry the same placeholder, never the
// sealed value, so the env a restarted pool sandbox sees is the env it was
// created with.
func TestStartReAdoptEnvKeepsWithheldPlaceholders(t *testing.T) {
	svc, _, rt := newInspectHarness(t)
	ctx := ownerCtx("acct")
	envRT := &envStartRuntime{ContainerRuntime: rt, start: rt.Start}
	svc.docker = envRT

	env := map[string]string{"GITHUB_TOKEN": envCanaryValue, "APP": "1"}
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", Env: env, EgressWithheldEnv: []string{"GITHUB_TOKEN"}})
	if err != nil {
		t.Fatal(err)
	}
	created := maps.Clone(rt.lastCreateReq.Env)
	if created["GITHUB_TOKEN"] != egresspolicy.InjectPlaceholder("GITHUB_TOKEN") || created["APP"] != "1" {
		t.Fatalf("driver env at create = %v", created)
	}
	// No binds: this create is warm-pool shaped (the containerd driver
	// adopts it; its eligibility table is in internal/runtime/containerd).
	if len(rt.lastCreateMounts) != 0 {
		t.Fatalf("create binds = %+v", rt.lastCreateMounts)
	}
	if _, err := svc.StopSandbox(ctx, resp.ID); err != nil {
		t.Fatal(err)
	}
	rt.startState = &models.SandboxRuntimeState{SandboxID: resp.ID, ContainerID: "ctr-" + resp.ID, ContainerIP: policyIP, Status: models.SandboxStatusStarted}
	if _, err := svc.StartSandbox(ctx, resp.ID); err != nil {
		t.Fatalf("StartSandbox: %v", err)
	}
	if !maps.Equal(envRT.loaded, created) {
		t.Fatalf("re-adopt env differs from the create's driver env (keys %d vs %d)", len(envRT.loaded), len(created))
	}
	for k, v := range envRT.loaded {
		if strings.Contains(v, envCanaryValue) {
			t.Fatalf("re-adopt env carries the withheld value under %s", k)
		}
	}
}

func TestAdoptEnvLoader(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-ldr", Image: "alpine", Status: models.SandboxStatusStopped, Runtime: models.RuntimeDocker,
		CPU: 1, MemoryMB: 256, CreatedAt: now, UpdatedAt: now, LastActiveAt: now, AuditIncarnationID: "inc-ldr",
	}); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"A": "1", "B": envCanaryValue, "C": "3"}
	injectB := []models.EgressRule{{Host: "api.example.org", Inspect: true, Inject: &models.EgressInject{Header: "Authorization", SecretRef: "env:B"}}}

	// No egress state: the env as sealed.
	got, err := svc.adoptEnvLoader(&models.Sandbox{ID: "sb-ldr", Env: env})(ctx)
	if err != nil || !maps.Equal(got, env) {
		t.Fatalf("no egress state: %v, %v", got, err)
	}
	// A rule that injects B: B is a placeholder, the caller's map untouched.
	got, err = svc.adoptEnvLoader(&models.Sandbox{ID: "sb-ldr", Env: env, NetworkEgressRules: injectB})(ctx)
	if err != nil || got["B"] != egresspolicy.InjectPlaceholder("B") || got["A"] != "1" || env["B"] != envCanaryValue {
		t.Fatalf("inject rule: %v, %v", got, err)
	}
	// A key withheld at create stays withheld with no rule naming it.
	if err := st.SetSandboxEgressProfiles(ctx, "sb-ldr", storepkg.NetworkPolicyWrite{Withheld: []string{"C"}}); err != nil {
		t.Fatal(err)
	}
	got, err = svc.adoptEnvLoader(&models.Sandbox{ID: "sb-ldr", Env: env})(ctx)
	if err != nil || got["C"] != egresspolicy.InjectPlaceholder("C") || got["B"] != envCanaryValue {
		t.Fatalf("stored withheld key: %v, %v", got, err)
	}
	// A store that can't say which keys are withheld fails the start.
	_ = st.Close()
	if got, err := svc.adoptEnvLoader(&models.Sandbox{ID: "sb-ldr", Env: env})(ctx); err == nil || got != nil {
		t.Fatalf("closed store: %v, %v", got, err)
	}
}

// A failover recreate of a sandbox with env hands the driver the env and no
// binds: the shape the containerd warm pool now adopts (before this, env
// alone sent every such recreate cold).
func TestFailoverRecreateWithEnvIsWarmPoolShaped(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableCluster = true
	svc.cfg.NodeRole = config.NodeRoleWorker
	svc.AttachCluster(ownedHostPortReserveCluster{&hostPortReserveCluster{Noop: cluster.NewNoop("self", "http://self", "")}})

	env := map[string]string{"API_KEY": envCanaryValue, "MODE": "prod"}
	if err := svc.RecreateSandbox(ctx, "sb-fo-env", models.CreateSandboxRequest{Image: "alpine:3.20", Env: env}, cluster.PlacementSecrets{}, nil); err != nil {
		t.Fatalf("RecreateSandbox: %v", err)
	}
	if rt.createCalls != 1 || rt.lastCreateID != "sb-fo-env" {
		t.Fatalf("runtime Create calls = %d for %q", rt.createCalls, rt.lastCreateID)
	}
	if !maps.Equal(rt.lastCreateReq.Env, env) {
		t.Fatalf("driver env = %d keys, want the spec's %d", len(rt.lastCreateReq.Env), len(env))
	}
	if len(rt.lastCreateMounts) != 0 || len(rt.lastCreateReq.Mounts) != 0 || rt.lastCreateReq.Registry != nil ||
		len(rt.lastCreateReq.ContainerCommand) != 0 || rt.lastCreateReq.GPUs != nil {
		t.Fatalf("recreate request is not pool-shaped: binds %+v req %+v", rt.lastCreateMounts, rt.lastCreateReq)
	}
	// The sealed row a later start re-sends from holds the same env.
	row, err := st.Get(ctx, "sb-fo-env")
	if err != nil {
		t.Fatal(err)
	}
	sealedEnv, err := svc.loadEnv(ctx, row.ID, row.AuditIncarnationID)
	if err != nil || !maps.Equal(sealedEnv, env) {
		t.Fatalf("sealed env after recreate = %d keys, %v", len(sealedEnv), err)
	}
}
