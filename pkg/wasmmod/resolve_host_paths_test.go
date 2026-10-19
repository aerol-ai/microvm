package wasmmod

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// SECURITY (issue #537): a caller marked WithHostPathsDenied (a scoped tenant)
// must not be able to resolve a module from a raw host path — an absolute path,
// a file:// URL, or a bare operator-staged filename under ModulesDir. Every such
// ref returns ErrModuleNotFound, so the daemon never reads a host file on the
// tenant's behalf. Reserved keywords, oci:// and owned catalogue ids are
// unaffected, so a tenant keeps every legitimate ref.
func TestResolveHostPathsDeniedForTenant(t *testing.T) {
	mr := newTestModuleResolver(t)
	WriteMinimalWasm(t, mr.file.ModulesDir, "python.wasm")
	WriteMinimalWasm(t, mr.file.ModulesDir, "staged.wasm")
	mr.Reserved = map[string]string{"python": "python.wasm"}
	outside := WriteMinimalWasm(t, t.TempDir(), "elsewhere.wasm")

	denied := WithHostPathsDenied(context.Background())

	// Every raw host-path form is refused with the generic not-found.
	for _, ref := range []string{
		outside,             // absolute path to a real .wasm
		"file://" + outside, // file:// URL
		"staged.wasm",       // bare operator-staged filename under ModulesDir
		"/etc/hosts",        // absolute path outside ModulesDir
	} {
		if _, err := mr.Resolve(denied, ref); !errors.Is(err, ErrModuleNotFound) {
			t.Fatalf("denied ref %q: want ErrModuleNotFound, got %v", ref, err)
		}
	}

	// A reserved keyword still resolves for a denied caller: it is the
	// operator-sanctioned way to use a standard module.
	if got, err := mr.Resolve(denied, "python"); err != nil {
		t.Fatalf("denied reserved keyword: %v", err)
	} else if filepath.Base(got.Path) != "python.wasm" {
		t.Fatalf("keyword resolved to %q", got.Path)
	}

	// An oci:// ref is still handled by the allowlist, not the host-path branch:
	// a denied caller sees the allowlist refusal, never a host read.
	if _, err := mr.Resolve(denied, "oci://attacker.example.com/x:1"); !errors.Is(err, ErrRegistryNotAllowed) {
		t.Fatalf("denied oci ref: want ErrRegistryNotAllowed, got %v", err)
	}
}

// A denied caller cannot use the per-ref error to learn which host files exist:
// a real non-wasm file and a missing file both resolve to ErrModuleNotFound.
func TestResolveHostPathsDeniedIsNotAnExistenceOracle(t *testing.T) {
	mr := newTestModuleResolver(t)
	denied := WithHostPathsDenied(context.Background())

	realFile := filepath.Join(t.TempDir(), "real.bin")
	if err := os.WriteFile(realFile, []byte("not a wasm module"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing.bin")

	_, errReal := mr.Resolve(denied, realFile)
	_, errMissing := mr.Resolve(denied, missing)
	if !errors.Is(errReal, ErrModuleNotFound) || !errors.Is(errMissing, ErrModuleNotFound) {
		t.Fatalf("existence oracle: real=%v missing=%v, want both ErrModuleNotFound", errReal, errMissing)
	}
}

// An operator / internal caller (ctx NOT marked denied) keeps host-path
// resolution: absolute paths and file:// URLs resolve as before, so a stored
// operator path still boots on a failover replay.
func TestResolveHostPathsAllowedForOperator(t *testing.T) {
	mr := newTestModuleResolver(t)
	outside := WriteMinimalWasm(t, t.TempDir(), "op.wasm")

	for _, ref := range []string{outside, "file://" + outside} {
		got, err := mr.Resolve(context.Background(), ref)
		if err != nil {
			t.Fatalf("operator ref %q: %v", ref, err)
		}
		if got.Digest == "" {
			t.Fatalf("operator ref %q: empty digest", ref)
		}
	}
}
