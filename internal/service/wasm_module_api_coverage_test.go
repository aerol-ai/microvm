package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestPushWasmModuleValidBytesBranches(t *testing.T) {
	ctx := context.Background()
	raw, err := hex.DecodeString(wasmmod.MinimalWasmHex)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("missing_token_after_validate", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.cfg.WasmRegistryPushHost = "registry.example.com/wasm"
		_, err := svc.PushWasmModule(ctx, "mymod", "v1", "user", "", bytes.NewReader(raw))
		if err == nil || !strings.Contains(err.Error(), "registry credentials required") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("push_artifact_fails", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		// Unreachable host — ValidateFile succeeds, PushModuleArtifact fails.
		svc.cfg.WasmRegistryPushHost = "127.0.0.1:1"
		_, err := svc.PushWasmModule(ctx, "mymod", "v1", "user", "tok", bytes.NewReader(raw))
		if err == nil {
			t.Fatal("expected PushModuleArtifact failure")
		}
	})

	t.Run("copy_error", func(t *testing.T) {
		svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.EnableWasm = true
		svc.cfg.WasmRegistryPushHost = "registry.example.com/wasm"
		_, err := svc.PushWasmModule(ctx, "mymod", "v1", "user", "tok", errReader{})
		if err == nil {
			t.Fatal("expected copy error")
		}
	})
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }
