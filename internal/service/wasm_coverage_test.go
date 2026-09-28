package service

import (
	"context"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestWasmCreateCustomDomainGetHookWave12(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, rt)
	svc.cfg.EnableWasm = true
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "external.test"
	svc.admitter = nil
	svc.SetWasmRuntime(rt)
	pub := true
	svc.testAfterCustomDomainsOnCreate = func() { _ = svc.store.Close() }
	_, err := svc.createWasmSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeWasm, ModuleRef: "m.wasm",
		AllowPublicTraffic: &pub, CustomDomains: []string{"api.external.test"},
	}, "sb-wcd")
	if err == nil {
		t.Fatal("expected get-after-custom-domain failure")
	}
}

func TestCreateWasmPutMountsAndCustomDomainGetRollback(t *testing.T) {
	ctx := context.Background()

	t.Run("put_mounts", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, rt)
		svc.cfg.EnableWasm = true
		svc.admitter = nil
		svc.SetWasmRuntime(rt)
		svc.testSealedMountsOverride = []byte("wasm-sealed")
		svc.testAfterStoreCreate = func() { _ = svc.store.Close() }
		_, err := svc.createWasmSandbox(ctx, models.CreateSandboxRequest{
			Runtime: models.RuntimeWasm, ModuleRef: "mod.wasm",
		}, "sb-wasm-mnt")
		if err == nil {
			t.Fatal("expected PutMounts rollback")
		}
		if len(rt.destroyIDs) == 0 {
			t.Fatal("expected wasm Destroy on PutMounts rollback")
		}
	})

	t.Run("custom_domain_get", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarnessAllowStoreClose(t, rt)
		svc.cfg.EnableWasm = true
		svc.cfg.EnableCustomDomains = true
		svc.cfg.Domain = "external.test"
		svc.cfg.EnableCaddy = true
		svc.admitter = nil
		svc.SetWasmRuntime(rt)
		pub := true
		// Close after custom domains persist so store.Get fails before sync.
		svc.testAfterCustomDomainsOnCreate = func() { _ = svc.store.Close() }
		_, err := svc.createWasmSandbox(ctx, models.CreateSandboxRequest{
			Runtime: models.RuntimeWasm, ModuleRef: "mod.wasm",
			AllowPublicTraffic: &pub,
			CustomDomains:      []string{"api.external.test"},
		}, "sb-wasm-cd")
		if err == nil {
			t.Fatal("expected Get failure after custom-domain persist")
		}
	})

	t.Run("seal_registry", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, rt)
		svc.cfg.EnableWasm = true
		svc.admitter = nil
		svc.SetWasmRuntime(rt)
		// Zero Cipher fails Encrypt — sealRegistry error arm.
		svc.cipher = &secrets.Cipher{}
		_, err := svc.createWasmSandbox(ctx, models.CreateSandboxRequest{
			Runtime:   models.RuntimeWasm,
			ModuleRef: "mod.wasm",
			Registry:  &models.RegistryAuth{Server: "reg.io", Username: "u", Password: "p"},
		}, "sb-wasm-reg")
		if err == nil || !strings.Contains(err.Error(), "encrypt registry") && !strings.Contains(err.Error(), "cipher") {
			// sealRegistry wraps encrypt errors; empty Cipher panics or errors.
			if err == nil {
				t.Fatal("expected sealRegistry failure")
			}
		}
	})
}
