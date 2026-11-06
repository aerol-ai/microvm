package service

import (
	"context"
	"errors"
	"expvar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/createpolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func createPolicyWatcher(t *testing.T, body string) *createpolicy.Watcher {
	t.Helper()
	path := filepath.Join(t.TempDir(), "create-policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return createpolicy.NewWatcher(path, nil)
}

func policyRule(err error) string {
	var pe *models.CreatePolicyError
	if errors.As(err, &pe) {
		return pe.Rule
	}
	return ""
}

func deniedCount(rule string) int64 {
	if v, ok := createPolicyDenied.Get(rule).(*expvar.Int); ok {
		return v.Value()
	}
	return 0
}

// TestCreatePolicyEmptyIsTodaysBehavior: no file, and a file with no rules,
// both leave creates exactly as they were.
func TestCreatePolicyEmptyIsTodaysBehavior(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	big := models.CreateSandboxRequest{Image: "nginx", CPU: 4, MemoryMB: 4096}
	if _, err := svc.CreateSandbox(context.Background(), big); err != nil {
		t.Fatalf("no policy: %v", err)
	}
	svc.SetCreatePolicy(createPolicyWatcher(t, "version: 1\n"))
	if _, err := svc.CreateSandbox(context.Background(), big); err != nil {
		t.Fatalf("empty policy: %v", err)
	}
	if rt.lastCreateReq.RequireNonRootUser {
		t.Fatal("no require_non_root rule, no runtime check")
	}
	if p, err := (*Service)(nil).createPolicy(); p != nil || err != nil {
		t.Fatal("a nil service has no policy")
	}
}

// TestCreatePolicyRefusesEachRule: every rule refuses a native create before
// the runtime is called, with a refusal that names the rule, and counts it.
func TestCreatePolicyRefusesEachRule(t *testing.T) {
	const policy = `version: 1
images:
  allowed_registries: [ghcr.io]
  allowed: ["alpine:*"]
runtimes: [docker]
limits:
  max_cpu: 2
  max_memory_mb: 2048
  max_disk_gb: 20
allow_gpu: false
`
	cases := []struct {
		name string
		req  models.CreateSandboxRequest
		rule string
	}{
		{"allowed", models.CreateSandboxRequest{Image: "alpine:3.20"}, ""},
		{"allowed by registry", models.CreateSandboxRequest{Image: "ghcr.io/acme/app:1"}, ""},
		{"image", models.CreateSandboxRequest{Image: "nginx:latest"}, createpolicy.RuleImages},
		{"image id", models.CreateSandboxRequest{Image: "sha256:" + strings.Repeat("a", 64)}, createpolicy.RuleImages},
		{"runtime", models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeWasm}, createpolicy.RuleRuntimes},
		{"cpu", models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 3}, createpolicy.RuleMaxCPU},
		{"memory", models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 4096}, createpolicy.RuleMaxMemoryMB},
		{"disk", models.CreateSandboxRequest{Image: "alpine:3.20", DiskGB: 40}, createpolicy.RuleMaxDiskGB},
		{"gpu", models.CreateSandboxRequest{Image: "alpine:3.20", GPUs: &models.GPURequest{Count: 1}}, createpolicy.RuleAllowGPU},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingRuntime{}
			svc, _, _ := newServiceRuntimeHarness(t, rt)
			svc.SetCreatePolicy(createPolicyWatcher(t, policy))
			before := deniedCount(tc.rule)
			_, err := svc.CreateSandbox(context.Background(), tc.req)
			if got := policyRule(err); got != tc.rule {
				t.Fatalf("rule = %q (err %v), want %q", got, err, tc.rule)
			}
			if tc.rule == "" {
				return
			}
			if !errors.Is(err, models.ErrCreatePolicyDenied) || !strings.Contains(err.Error(), `"`+tc.rule+`"`) {
				t.Fatalf("refusal must match ErrCreatePolicyDenied and name the rule: %v", err)
			}
			if rt.createCalls != 0 {
				t.Fatal("a refused create must not reach the runtime")
			}
			if deniedCount(tc.rule) != before+1 {
				t.Fatalf("aerolvm_create_policy_denied_total{%s} not counted", tc.rule)
			}
		})
	}
}

// TestCreatePolicySnapshotResolvedImage: a snapshot name cannot launder an
// image the policy refuses: the check sees the image the snapshot resolves
// to, not the name the caller wrote.
func TestCreatePolicySnapshotResolvedImage(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	ctx := context.Background()
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "friendly", Image: "nginx:latest", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "approved", Image: "alpine:3.20", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	svc.SetCreatePolicy(createPolicyWatcher(t, "version: 1\nimages:\n  allowed: [\"alpine:*\", \"friendly*\"]\n"))
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "friendly"}); policyRule(err) != createpolicy.RuleImages {
		t.Fatalf("snapshot of a refused image = %v, want the images rule", err)
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "approved"}); err != nil {
		t.Fatalf("snapshot of an allowed image = %v", err)
	}
	if rt.lastCreateReq.Image != "alpine:3.20" {
		t.Fatalf("runtime got %q, want the resolved image", rt.lastCreateReq.Image)
	}
}

// TestCreatePolicyRequireNonRoot: the rule reaches a container runtime as
// RequireNonRootUser; a refusal the runtime raises is counted under the rule
// and surfaces as the policy error.
func TestCreatePolicyRequireNonRoot(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.SetCreatePolicy(createPolicyWatcher(t, "version: 1\nrequire_non_root: true\n"))
	ctx := context.Background()
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "acme/app:1"}); err != nil {
		t.Fatal(err)
	}
	if !rt.lastCreateReq.RequireNonRootUser {
		t.Fatal("a docker create must carry RequireNonRootUser to the runtime")
	}

	before := deniedCount(createpolicy.RuleRequireNonRoot)
	rt.createErr = models.CheckImageUserNonRoot("acme/root:1", "")
	_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "acme/root:1"})
	if policyRule(err) != createpolicy.RuleRequireNonRoot {
		t.Fatalf("runtime refusal = %v, want the require_non_root rule", err)
	}
	if deniedCount(createpolicy.RuleRequireNonRoot) != before+1 {
		t.Fatal("the runtime's refusal must be counted once")
	}
	// Another runtime failure is not a policy refusal and is not counted.
	rt.createErr = errors.New("engine down")
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "acme/app:1"}); err == nil || policyRule(err) != "" {
		t.Fatalf("engine failure = %v", err)
	}
	if deniedCount(createpolicy.RuleRequireNonRoot) != before+1 {
		t.Fatal("a non-policy failure must not be counted")
	}
}

// TestApplyCreatePolicyPerRuntime pins what each runtime is held to: WASM and
// isolate skip the image rules and never get the non-root flag, Firecracker's
// overlay counts as disk, and an omitted WASM memory is not the default.
func TestApplyCreatePolicyPerRuntime(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.SetCreatePolicy(createPolicyWatcher(t, `version: 1
images:
  allowed: ["alpine:*"]
limits:
  max_memory_mb: 256
  max_disk_gb: 20
require_non_root: true
`))
	cases := []struct {
		name       string
		req        models.CreateSandboxRequest
		runtime    string
		memOmitted bool
		rule       string
		nonRoot    bool
	}{
		{"wasm skips image rules", models.CreateSandboxRequest{Image: "registry/mod.wasm", MemoryMB: 128, DiskGB: 1}, models.RuntimeWasm, false, "", false},
		{"wasm omitted memory is not the default", models.CreateSandboxRequest{Image: "m", MemoryMB: 512, DiskGB: 1}, models.RuntimeWasm, true, "", false},
		{"isolate skips image rules", models.CreateSandboxRequest{ModuleRef: "bundle", MemoryMB: 128, DiskGB: 1}, models.RuntimeIsolate, false, "", false},
		{"firecracker overlay counts", models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 128, DiskGB: 10, OverlaySizeGB: 11}, models.RuntimeFirecracker, false, createpolicy.RuleMaxDiskGB, false},
		{"firecracker is not a container", models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 128, DiskGB: 10}, models.RuntimeFirecracker, false, "", false},
		{"gvisor is a container", models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 128, DiskGB: 10}, models.RuntimeGvisor, false, "", true},
		{"docker memory over", models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 512, DiskGB: 10}, models.RuntimeDocker, true, createpolicy.RuleMaxMemoryMB, false},
	}
	for _, tc := range cases {
		req := tc.req
		err := svc.applyCreatePolicy(&req, tc.runtime, tc.memOmitted, false)
		if got := policyRule(err); got != tc.rule {
			t.Errorf("%s: rule = %q (%v), want %q", tc.name, got, err, tc.rule)
		}
		if req.RequireNonRootUser != tc.nonRoot {
			t.Errorf("%s: RequireNonRootUser = %v, want %v", tc.name, req.RequireNonRootUser, tc.nonRoot)
		}
	}
}

// TestCreatePolicyFailoverReplayExempt: a recreate replays the spec that was
// accepted at create; a policy tightened since must not strand it.
func TestCreatePolicyFailoverReplayExempt(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.SetCreatePolicy(createPolicyWatcher(t, "version: 1\nlimits:\n  max_cpu: 1\nrequire_non_root: true\n"))
	ctx := contextWithStoredSpecReplay(context.Background())
	if _, err := svc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 4}, "sb-0123456789abcdef"); err != nil {
		t.Fatalf("replay refused: %v", err)
	}
	if rt.lastCreateReq.RequireNonRootUser {
		t.Fatal("a replay is not re-checked, by the runtime either")
	}
}

// TestCreatePolicyInvalidFileRefusesCreatesAndResizes: a set file that did
// not load fails closed with the dedicated sentinel; the load failure is
// counted.
func TestCreatePolicyInvalidFileRefusesCreatesAndResizes(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	ctx := context.Background()
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"})
	if err != nil {
		t.Fatal(err)
	}
	w := createPolicyWatcher(t, "version: 1\nruntimes: [podman]\n")
	svc.SetCreatePolicy(w)
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}); !errors.Is(err, ErrCreatePolicyInvalid) {
		t.Fatalf("create = %v, want ErrCreatePolicyInvalid", err)
	}
	if _, err := svc.ResizeSandbox(ctx, resp.ID, models.ResizeSandboxRequest{CPU: 2}); !errors.Is(err, ErrCreatePolicyInvalid) {
		t.Fatalf("resize = %v, want ErrCreatePolicyInvalid", err)
	}
	if expvarFloat(t, "aerolvm_create_policy_load_failures_total") != float64(w.Failures()) || w.Failures() == 0 {
		t.Fatal("load failures metric must track the live watcher")
	}
	missing := createpolicy.NewWatcher(filepath.Join(t.TempDir(), "absent.yaml"), nil)
	svc.SetCreatePolicy(missing)
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}); !errors.Is(err, ErrCreatePolicyInvalid) {
		t.Fatalf("a set path with no file must fail closed, got %v", err)
	}
}

// TestCreatePolicyResize: the size limits hold for a resize, but only on the
// dimensions it changes.
func TestCreatePolicyResize(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), resizeOKRuntime{&recordingRuntime{}})
	ctx := context.Background()
	// Made before the limit existed.
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 4})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetCreatePolicy(createPolicyWatcher(t, "version: 1\nlimits:\n  max_cpu: 2\n  max_memory_mb: 4096\n"))
	if _, err := svc.ResizeSandbox(ctx, resp.ID, models.ResizeSandboxRequest{CPU: 3}); policyRule(err) != createpolicy.RuleMaxCPU {
		t.Fatalf("resize above the cpu limit = %v", err)
	}
	if _, err := svc.ResizeSandbox(ctx, resp.ID, models.ResizeSandboxRequest{MemoryMB: 8192}); policyRule(err) != createpolicy.RuleMaxMemoryMB {
		t.Fatalf("resize above the memory limit = %v", err)
	}
	// Only memory changes: the sandbox's cpu, already above the new limit,
	// is not what this resize asks for.
	if _, err := svc.ResizeSandbox(ctx, resp.ID, models.ResizeSandboxRequest{MemoryMB: 1024}); err != nil {
		t.Fatalf("memory-only resize = %v", err)
	}
	if _, err := svc.ResizeSandbox(ctx, resp.ID, models.ResizeSandboxRequest{CPU: 2}); err != nil {
		t.Fatalf("resize to the limit = %v", err)
	}
}

// TestCheckCreatePolicyMatchesTheCreate: the router's check (before
// placement) refuses exactly what the owner's create refuses, by the same
// rule, with the same defaults, and touches nothing.
func TestCheckCreatePolicyMatchesTheCreate(t *testing.T) {
	const policy = `version: 1
runtimes: [docker]
limits:
  max_cpu: 2
  max_memory_mb: 2048
`
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if err := svc.CheckCreatePolicy(models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 64}); err != nil {
		t.Fatalf("no policy: %v", err)
	}
	svc.SetCreatePolicy(createPolicyWatcher(t, policy))
	for _, tc := range []struct {
		req  models.CreateSandboxRequest
		rule string
	}{
		{models.CreateSandboxRequest{Image: "alpine:3.20"}, ""},
		{models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 3}, createpolicy.RuleMaxCPU},
		{models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 4096}, createpolicy.RuleMaxMemoryMB},
		{models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeWasm}, createpolicy.RuleRuntimes},
		{models.CreateSandboxRequest{Image: "alpine:3.20", TemplateID: "tpl-1"}, createpolicy.RuleRuntimes},
		// An invalid runtime is the owner's to report.
		{models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: "nope"}, ""},
	} {
		err := svc.CheckCreatePolicy(tc.req)
		if got := policyRule(err); got != tc.rule {
			t.Fatalf("%+v: rule %q (err %v), want %q", tc.req, got, err, tc.rule)
		}
	}
	var nilSvc *Service
	if nilSvc.CheckCreatePolicy(models.CreateSandboxRequest{}) != nil {
		t.Fatal("a nil service refused")
	}
}
