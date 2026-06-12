//go:build integration

// Live-registry integration test for the BYO module push/pull round-trip.
// Gated behind the `integration` build tag so the default `go test` stays
// hermetic; CI runs it with `go test -tags integration` when AOCR creds are
// present. Validates the two things mocks can't: real token auth and that the
// .wasm artifact mediaType round-trips through the registry (plan §7.2).
//
// Required env:
//
//	AEROL_WASM_IT_REF       full registry ref, e.g. aocr.aerol.ai/tenant/it-test:latest
//	AEROL_WASM_IT_USERNAME  registry login
//	AEROL_WASM_IT_TOKEN     registry PAT (inline)
package wasmmod

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestIntegrationModulePushPullRoundTrip(t *testing.T) {
	ref := os.Getenv("AEROL_WASM_IT_REF")
	username := os.Getenv("AEROL_WASM_IT_USERNAME")
	token := os.Getenv("AEROL_WASM_IT_TOKEN")
	if ref == "" || token == "" {
		t.Skip("set AEROL_WASM_IT_REF + AEROL_WASM_IT_TOKEN to run the live-AOCR integration test")
	}
	ctx := context.Background()
	auth := ModuleAuth{Username: username, PAT: token}

	// Push a minimal valid core-wasip1 module.
	srcDir := t.TempDir()
	src := WriteMinimalWasm(t, srcDir, "it.wasm")
	wantDigestBytes, _, err := fileDigest(src)
	if err != nil {
		t.Fatalf("digest source: %v", err)
	}

	if _, err := PushModuleArtifact(ctx, auth, src, ref); err != nil {
		t.Fatalf("push: %v", err)
	}

	// Pull it back and assert the bytes are identical (digest round-trips).
	dstDir := t.TempDir()
	got, err := PullModuleArtifact(ctx, auth, ref, dstDir, maxModuleBytes)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if err := ValidateFile(got); err != nil {
		t.Fatalf("pulled artifact failed validation: %v", err)
	}
	gotDigest, _, err := fileDigest(got)
	if err != nil {
		t.Fatalf("digest pulled: %v", err)
	}
	if gotDigest != wantDigestBytes {
		t.Fatalf("round-trip digest mismatch: pushed %s pulled %s", wantDigestBytes, gotDigest)
	}
	if filepath.Base(got) != moduleLayerName {
		t.Fatalf("unexpected unpacked layer name %q", filepath.Base(got))
	}
	// Sanity: digest is hex sha256.
	if _, err := hex.DecodeString(gotDigest); err != nil || len(gotDigest) != 64 {
		t.Fatalf("digest not sha256 hex: %q", gotDigest)
	}
}
