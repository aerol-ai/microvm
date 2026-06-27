//go:build integration

package suite

import (
	"os"
	"strings"
	"testing"
)

const defaultStagedWasmModule = "python"

func stagedWasmModuleRef(t testing.TB) string {
	t.Helper()
	ref := strings.TrimSpace(os.Getenv("AEROL_WASM_MODULE_REF"))
	if ref == "" {
		return ""
	}
	if staleSnapshotModuleRef(ref) {
		t.Logf("ignoring stale snapshot image ref in AEROL_WASM_MODULE_REF=%q; using staged wasm module alias %q", ref, defaultStagedWasmModule)
		return defaultStagedWasmModule
	}
	return ref
}

func stagedWasmModuleRefOrDefault(t testing.TB) string {
	t.Helper()
	if ref := stagedWasmModuleRef(t); ref != "" {
		return ref
	}
	return defaultStagedWasmModule
}

func staleSnapshotModuleRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	return (strings.Contains(ref, "/cluster/") || strings.HasPrefix(ref, "cluster/")) &&
		strings.Contains(ref, "/snapshots")
}

func TestStaleSnapshotModuleRef(t *testing.T) {
	cases := []string{
		"aocr.aerol.ai/cluster/prod-aerolvm-us-east-1/snapshots/python:latest--ttl-1h",
		"oci://aocr.aerol.ai/cluster/prod-aerolvm-us-east-1/snapshots/python:latest--ttl-1h",
		"cluster/prod-aerolvm-us-east-1/snapshots/python:latest--ttl-1h",
	}
	for _, ref := range cases {
		if !staleSnapshotModuleRef(ref) {
			t.Fatalf("staleSnapshotModuleRef(%q) = false, want true", ref)
		}
	}

	for _, ref := range []string{"python", "aocr.aerol.ai/wasm/std/python:3.12"} {
		if staleSnapshotModuleRef(ref) {
			t.Fatalf("staleSnapshotModuleRef(%q) = true, want false", ref)
		}
	}
}
