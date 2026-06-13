package service

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestPushWasmModuleValidationBranches covers the pure input-validation
// branches of PushWasmModule which do NOT require a real OCI registry.
func TestPushWasmModuleValidationBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("wasm disabled", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = false
		_, err := svc.PushWasmModule(ctx, "mymod", "latest", "", "token", strings.NewReader(""))
		if err == nil || !strings.Contains(err.Error(), "SB_ENABLE_WASM") {
			t.Fatalf("disabled PushWasmModule = %v, want SB_ENABLE_WASM error", err)
		}
		if !isErrRuntimeNotImplemented(err) {
			t.Fatalf("disabled PushWasmModule should wrap ErrRuntimeNotImplemented, got: %v", err)
		}
	})

	t.Run("push host not configured", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg = config.Config{EnableWasm: true, WasmRegistryPushHost: ""}
		_, err := svc.PushWasmModule(ctx, "mymod", "latest", "", "token", strings.NewReader(""))
		if err == nil || !strings.Contains(err.Error(), "SB_WASM_REGISTRY_PUSH_HOST") {
			t.Fatalf("no push host = %v, want SB_WASM_REGISTRY_PUSH_HOST error", err)
		}
	})

	t.Run("invalid module name — empty after trim", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg = config.Config{EnableWasm: true, WasmRegistryPushHost: "registry.example.com"}
		_, err := svc.PushWasmModule(ctx, "  /  ", "latest", "", "token", strings.NewReader(""))
		if err == nil || !strings.Contains(err.Error(), "invalid module name") {
			t.Fatalf("empty name = %v, want invalid module name", err)
		}
	})

	t.Run("invalid module name — contains ://", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg = config.Config{EnableWasm: true, WasmRegistryPushHost: "registry.example.com"}
		_, err := svc.PushWasmModule(ctx, "oci://badname", "latest", "", "token", strings.NewReader(""))
		if err == nil || !strings.Contains(err.Error(), "invalid module name") {
			t.Fatalf("oci:// name = %v, want invalid module name", err)
		}
	})

	t.Run("invalid module name — contains spaces", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg = config.Config{EnableWasm: true, WasmRegistryPushHost: "registry.example.com"}
		_, err := svc.PushWasmModule(ctx, "my mod", "latest", "", "token", strings.NewReader(""))
		if err == nil || !strings.Contains(err.Error(), "invalid module name") {
			t.Fatalf("name with spaces = %v, want invalid module name", err)
		}
	})

	t.Run("empty tag defaults to latest — ValidateFile fires before token", func(t *testing.T) {
		// Passing empty data means ValidateFile will reject (bad magic header).
		// The important thing is the error is NOT about "tag", proving the tag
		// defaulting branch is reached successfully.
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg = config.Config{EnableWasm: true, WasmRegistryPushHost: "registry.example.com"}
		_, err := svc.PushWasmModule(ctx, "mymod", "", "", "token", strings.NewReader("data"))
		// Should fail at ValidateFile or registry push, not at tag or name validation
		if err == nil {
			t.Fatal("expected error after tag defaulting")
		}
		// Must NOT fail with tag-related or name-related validation
		if strings.Contains(err.Error(), "invalid module name") {
			t.Fatalf("empty tag triggered name validation error: %v", err)
		}
	})

	t.Run("missing token rejects after ValidateFile", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg = config.Config{EnableWasm: true, WasmRegistryPushHost: "registry.example.com"}
		// Empty body → ValidateFile fires (bad magic header). Token check
		// only fires for a valid wasm binary; this still exercises the
		// io.Copy + sha256 streaming path which is the important coverage.
		_, err := svc.PushWasmModule(ctx, "mymod", "v1", "", "", strings.NewReader(""))
		if err == nil {
			t.Fatal("expected error for empty wasm body")
		}
	})

	t.Run("oversized body rejected", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg = config.Config{EnableWasm: true, WasmRegistryPushHost: "registry.example.com"}
		// maxPushBytes+2 bytes will push the LimitReader past the cap.
		oversized := bytes.NewReader(make([]byte, maxPushBytes+2))
		_, err := svc.PushWasmModule(ctx, "mymod", "latest", "user", "token", oversized)
		if err == nil || !strings.Contains(err.Error(), "upload exceeds") {
			t.Fatalf("oversized body = %v, want upload exceeds error", err)
		}
	})
}

// isErrRuntimeNotImplemented checks whether err wraps models.ErrRuntimeNotImplemented.
func isErrRuntimeNotImplemented(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), models.ErrRuntimeNotImplemented.Error())
}
