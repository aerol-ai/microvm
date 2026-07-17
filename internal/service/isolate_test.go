package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The isolate create gate mirrors firecracker/wasm: flag off and
// driver-not-registered are distinct operator-facing errors, both
// ErrRuntimeNotImplemented (plans/isolate-runtime.md Phase 1).
func TestCreateIsolateSandboxGate(t *testing.T) {
	ctx := context.Background()

	t.Run("flag_off_names_the_env_var", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			Runtime: models.RuntimeIsolate, ModuleRef: "handler.js",
		})
		if !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("err = %v, want ErrRuntimeNotImplemented", err)
		}
		if !strings.Contains(err.Error(), "SB_ENABLE_ISOLATE") {
			t.Fatalf("err %q should name SB_ENABLE_ISOLATE", err)
		}
	})

	t.Run("flag_on_driver_missing_is_a_wiring_bug", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableIsolate = true
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			Runtime: models.RuntimeIsolate, ModuleRef: "handler.js",
		})
		if !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("err = %v, want ErrRuntimeNotImplemented", err)
		}
		if !strings.Contains(err.Error(), "SetIsolateRuntime") {
			t.Fatalf("err %q should point at the missing SetIsolateRuntime wiring", err)
		}
	})

	t.Run("flag_on_dispatches_to_the_driver", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableIsolate = true
		driver := &recordingRuntime{createErr: errors.New("driver reached")}
		svc.SetIsolateRuntime(driver)
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			Runtime: models.RuntimeIsolate, ModuleRef: "handler.js",
		})
		if err == nil || !strings.Contains(err.Error(), "driver reached") {
			t.Fatalf("err = %v, want the driver's error", err)
		}
		if driver.createCalls != 1 {
			t.Fatalf("driver createCalls = %d, want 1", driver.createCalls)
		}
		if driver.lastCreateReq.Runtime != models.RuntimeIsolate {
			t.Fatalf("driver saw runtime %q", driver.lastCreateReq.Runtime)
		}
		if driver.lastCreateReq.ModuleRef != "handler.js" {
			t.Fatalf("driver saw module_ref %q, want the bundle ref", driver.lastCreateReq.ModuleRef)
		}
		if driver.lastCreateID == "" {
			t.Fatal("driver saw an empty sandbox id")
		}
	})

	t.Run("driver_without_resolver_rejects_not_implemented", func(t *testing.T) {
		// A driver with no bundle resolver wired (a daemon-wiring bug) rejects
		// with ErrRuntimeNotImplemented rather than panicking — the dispatch
		// chain reaches the driver, which reports the missing dependency.
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableIsolate = true
		svc.SetIsolateRuntime(isolateruntime.New(isolateruntime.Config{}, nil))
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			Runtime: models.RuntimeIsolate, ModuleRef: "handler.js",
		})
		if !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("err = %v, want ErrRuntimeNotImplemented for a resolver-less driver", err)
		}
	})
}

func TestCreateIsolateSandboxValidation(t *testing.T) {
	ctx := context.Background()
	newEnabled := func(t *testing.T) (*Service, *recordingRuntime) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableIsolate = true
		driver := &recordingRuntime{createErr: errors.New("driver reached")}
		svc.SetIsolateRuntime(driver)
		return svc, driver
	}

	tests := []struct {
		name    string
		req     models.CreateSandboxRequest
		wantMsg string
		wantNI  bool // errors.Is ErrRuntimeNotImplemented
	}{
		{
			name:    "gpus_rejected",
			req:     models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "b.js", GPUs: &models.GPURequest{Vendor: models.GPUVendorNVIDIA}},
			wantMsg: "GPUs",
			wantNI:  true,
		},
		{
			// Rejected upstream by createSandbox's template gate (template_id
			// forces the firecracker path); createIsolateSandbox keeps a
			// defensive twin for direct callers, mirroring createWasmSandbox.
			name:    "template_id_rejected",
			req:     models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "b.js", TemplateID: "tpl-1"},
			wantMsg: "template_id requires runtime",
		},
		{
			name:    "mounts_rejected_no_filesystem",
			req:     models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "b.js", Mounts: []models.MountSpec{{}}},
			wantMsg: "no filesystem",
		},
		{
			name:    "negative_byte_limits_rejected",
			req:     models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "b.js", NetworkBytesInLimit: -1},
			wantMsg: "network byte limits",
		},
		{
			// Fails createSandbox's shared image/module_ref presence check;
			// the helper's own message only fires for direct callers.
			name:    "bundle_ref_required",
			req:     models.CreateSandboxRequest{Runtime: models.RuntimeIsolate},
			wantMsg: "image is required",
		},
		{
			name:    "passivatable_durability_rejected",
			req:     models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "b.js", Durability: models.DurabilityPassivatable},
			wantMsg: "nothing to passivate",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, driver := newEnabled(t)
			_, err := svc.CreateSandbox(ctx, tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("err = %v, want message containing %q", err, tc.wantMsg)
			}
			if tc.wantNI && !errors.Is(err, models.ErrRuntimeNotImplemented) {
				t.Fatalf("err = %v, want ErrRuntimeNotImplemented", err)
			}
			if driver.createCalls != 0 {
				t.Fatalf("driver reached despite invalid request (%d calls)", driver.createCalls)
			}
		})
	}

	// Image falls back as the bundle ref, mirroring ModuleRefForCreate on wasm.
	t.Run("image_serves_as_bundle_ref", func(t *testing.T) {
		svc, driver := newEnabled(t)
		_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
			Runtime: models.RuntimeIsolate, Image: "bundles/webhook.js",
		})
		if err == nil || !strings.Contains(err.Error(), "driver reached") {
			t.Fatalf("err = %v, want the driver's error", err)
		}
		if driver.lastCreateReq.ModuleRef != "bundles/webhook.js" {
			t.Fatalf("bundle ref = %q, want the image fallback", driver.lastCreateReq.ModuleRef)
		}
	})
}

// SECURITY regression (plans/isolate-runtime.md §2.1): tenant_id is
// server-authorized. A user-scoped caller must never place a sandbox into
// another tenant's workerd process by naming that tenant's group key.
func TestAuthorizeIsolateTenantID(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})

	tests := []struct {
		name      string
		ctx       context.Context
		requested string
		want      string
		wantErr   string
	}{
		// Empty falls back to the authenticated identity at group-routing
		// time — allowed for every caller class, returns the null tenant.
		{name: "empty_unscoped", ctx: context.Background(), requested: "", want: ""},
		{name: "empty_operator", ctx: operatorCtx(), requested: "", want: ""},
		{name: "empty_scoped", ctx: userCtx("acme"), requested: "", want: ""},
		// Operator/PAT and internal callers partition tenants freely.
		{name: "operator_any_tenant", ctx: operatorCtx(), requested: "customer-7", want: "customer-7"},
		{name: "internal_any_tenant", ctx: context.Background(), requested: "customer-7", want: "customer-7"},
		// A scoped caller may name exactly its own identity.
		{name: "scoped_own_identity", ctx: userCtx("acme"), requested: "acme", want: "acme"},
		// The forced-co-residency case: scoped caller naming another tenant.
		{name: "scoped_foreign_tenant_rejected", ctx: userCtx("acme"), requested: "victim-corp", wantErr: "not authorized"},
		// Malformed keys are rejected before authorization — they become
		// chroot/cgroup names (jail spec's SanitizeGroupKey is the check).
		{name: "traversal_rejected", ctx: operatorCtx(), requested: "../../etc", wantErr: "invalid tenant_id"},
		{name: "whitespace_only_falls_back", ctx: userCtx("acme"), requested: "   ", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.authorizeIsolateTenantID(tc.ctx, tc.requested)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want message containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("tenant = %q, want %q", got, tc.want)
			}
		})
	}
}

// End-to-end shape of the regression: the authorized tenant reaches the
// driver on the request; the unauthorized one never gets that far.
func TestCreateIsolateTenantAuthorizationEndToEnd(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	driver := &recordingRuntime{createErr: errors.New("driver reached")}
	svc.SetIsolateRuntime(driver)

	_, err := svc.CreateSandbox(userCtx("acme"), models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "b.js", TenantID: "victim-corp",
	})
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("foreign tenant err = %v, want authorization rejection", err)
	}
	if driver.createCalls != 0 {
		t.Fatal("driver reached with an unauthorized tenant_id")
	}

	_, err = svc.CreateSandbox(userCtx("acme"), models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "b.js", TenantID: "acme",
	})
	if err == nil || !strings.Contains(err.Error(), "driver reached") {
		t.Fatalf("own tenant err = %v, want the driver's error", err)
	}
	if driver.lastCreateReq.TenantID != "acme" {
		t.Fatalf("driver saw tenant %q, want acme", driver.lastCreateReq.TenantID)
	}
}

func TestRuntimeDispatchIsolate(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	sb := &models.Sandbox{ID: "sb-iso", Runtime: models.RuntimeIsolate}

	if _, err := svc.runtimeForSandbox(sb); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("runtimeForSandbox(isolate without driver) = %v, want ErrRuntimeNotImplemented", err)
	}

	driver := isolateruntime.New(isolateruntime.Config{}, nil)
	svc.SetIsolateRuntime(driver)
	rt, err := svc.runtimeForSandbox(sb)
	if err != nil {
		t.Fatalf("runtimeForSandbox(isolate) = %v", err)
	}
	if rt != svc.isolate {
		t.Fatalf("runtimeForSandbox(isolate) = %T, want the isolate driver", rt)
	}

	// Host-mediated: the runtime ref is the sandbox ID, never a container ref.
	if ref := svc.runtimeRef(sb); ref != "sb-iso" {
		t.Fatalf("runtimeRef = %q, want sandbox ID", ref)
	}

	// And there is no container-network surface to reach (§4: Runtime only).
	if _, err := svc.containerRuntimeForSandbox(sb); err == nil || !strings.Contains(err.Error(), "does not support container network rules") {
		t.Fatalf("containerRuntimeForSandbox(isolate) = %v, want no-network-rules error", err)
	}
}

// Platform volumes are host bind-mounts; isolates have no filesystem
// (plans/isolate-runtime.md §3), so the pre-dispatch gate rejects them.
func TestResolvePlatformVolumesRejectsIsolate(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.PlatformVolumes.Enabled = true
	req := models.CreateSandboxRequest{
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/data"}},
	}
	_, err := svc.resolvePlatformVolumes(context.Background(), &req, models.RuntimeIsolate)
	if !errors.Is(err, models.ErrPlatformVolumesUnsupportedRuntime) {
		t.Fatalf("err = %v, want ErrPlatformVolumesUnsupportedRuntime", err)
	}
}
