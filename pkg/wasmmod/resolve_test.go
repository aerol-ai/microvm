package wasmmod

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func newTestModuleResolver(t *testing.T) *ModuleResolver {
	t.Helper()
	modulesDir := t.TempDir()
	cacheDir := t.TempDir()
	mr := NewModuleResolver(modulesDir, cacheDir)
	return mr
}

// Reserved keyword resolves to its staged filename under ModulesDir.
func TestResolveReservedKeyword(t *testing.T) {
	mr := newTestModuleResolver(t)
	WriteMinimalWasm(t, mr.file.ModulesDir, "python.wasm")
	mr.Reserved = map[string]string{"python": "python.wasm"}

	got, err := mr.Resolve(context.Background(), "python")
	if err != nil {
		t.Fatalf("resolve reserved: %v", err)
	}
	if got.Path != filepath.Join(mr.file.ModulesDir, "python.wasm") || got.Digest == "" {
		t.Fatalf("unexpected: %+v", got)
	}
}

// A reserved keyword must win over a same-named bare file on disk (codex C3).
func TestResolveReservedKeywordBeatsBareFile(t *testing.T) {
	mr := newTestModuleResolver(t)
	// Stray file literally named "python" (no .wasm) sitting in modules dir.
	WriteMinimalWasm(t, mr.file.ModulesDir, "python")
	// The staged standard runtime.
	WriteMinimalWasm(t, mr.file.ModulesDir, "python.wasm")
	mr.Reserved = map[string]string{"python": "python.wasm"}

	got, err := mr.Resolve(context.Background(), "python")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got.Path) != "python.wasm" {
		t.Fatalf("reserved keyword shadowed by bare file: %q", got.Path)
	}
}

// SECURITY: an oci:// host not on the allowlist is rejected before any network
// call. This is the SSRF guard.
func TestResolveOCIRejectsNonAllowlistedHost(t *testing.T) {
	mr := newTestModuleResolver(t)
	mr.Allowlist = map[string]struct{}{"aocr.aerol.ai": {}}

	for _, ref := range []string{
		"oci://169.254.169.254/tenant/app:latest",
		"oci://attacker.example.com/x:1",
		"oci://localhost:5000/y:1",
	} {
		_, err := mr.Resolve(context.Background(), ref)
		if !errors.Is(err, ErrRegistryNotAllowed) {
			t.Fatalf("ref %q: want ErrRegistryNotAllowed, got %v", ref, err)
		}
	}
}

// An empty allowlist denies all remote pulls (safe default).
func TestResolveOCIEmptyAllowlistDeniesAll(t *testing.T) {
	mr := newTestModuleResolver(t)
	_, err := mr.Resolve(context.Background(), "oci://aocr.aerol.ai/t/app:latest")
	if !errors.Is(err, ErrRegistryNotAllowed) {
		t.Fatalf("want ErrRegistryNotAllowed, got %v", err)
	}
}

// Bare filename under ModulesDir still resolves (legacy path preserved).
func TestResolveBareFile(t *testing.T) {
	mr := newTestModuleResolver(t)
	WriteMinimalWasm(t, mr.file.ModulesDir, "agent.wasm")
	got, err := mr.Resolve(context.Background(), "agent.wasm")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got.Path) != "agent.wasm" {
		t.Fatalf("path = %q", got.Path)
	}
}

// A ref that matches nothing yields the typed not-found.
func TestResolveNotFound(t *testing.T) {
	mr := newTestModuleResolver(t)
	_, err := mr.Resolve(context.Background(), "nope.wasm")
	if !errors.Is(err, ErrModuleNotFound) {
		t.Fatalf("want ErrModuleNotFound, got %v", err)
	}
}

// BYO catalogue id resolves through CatalogueLookup to a local path.
func TestResolveCatalogueID(t *testing.T) {
	mr := newTestModuleResolver(t)
	path := WriteMinimalWasm(t, mr.file.ModulesDir, "byo.wasm")
	mr.CatalogueLookup = func(_ context.Context, id string) (string, string, bool) {
		if id == "sha256abc" {
			return path, "sha256abc", true
		}
		return "", "", false
	}
	got, err := mr.Resolve(context.Background(), "sha256abc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != path || got.Digest != "sha256abc" {
		t.Fatalf("unexpected: %+v", got)
	}
}

// The catalogue owner pinned on ctx reaches CatalogueLookup unchanged
// (trimmed), and an unpinned ctx reports no owner rather than "".
func TestCatalogueOwnerContext(t *testing.T) {
	tests := []struct {
		name      string
		ctx       context.Context
		wantOwner string
		wantOK    bool
	}{
		{name: "unpinned", ctx: context.Background(), wantOwner: "", wantOK: false},
		{name: "operator namespace", ctx: WithCatalogueOwner(context.Background(), ""), wantOwner: "", wantOK: true},
		{name: "tenant trimmed", ctx: WithCatalogueOwner(context.Background(), " acct-a "), wantOwner: "acct-a", wantOK: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			owner, ok := CatalogueOwner(tc.ctx)
			if owner != tc.wantOwner || ok != tc.wantOK {
				t.Fatalf("CatalogueOwner = (%q, %v), want (%q, %v)", owner, ok, tc.wantOwner, tc.wantOK)
			}
		})
	}

	mr := newTestModuleResolver(t)
	path := WriteMinimalWasm(t, mr.file.ModulesDir, "owned.wasm")
	mr.CatalogueLookup = func(ctx context.Context, id string) (string, string, bool) {
		if owner, _ := CatalogueOwner(ctx); owner == "acct-a" && id == "mod" {
			return path, "d-a", true
		}
		return "", "", false
	}
	if got, err := mr.Resolve(WithCatalogueOwner(context.Background(), "acct-a"), "mod"); err != nil || got.Digest != "d-a" {
		t.Fatalf("pinned resolve = %+v, %v; want digest d-a", got, err)
	}
	if _, err := mr.Resolve(WithCatalogueOwner(context.Background(), "acct-b"), "mod"); !errors.Is(err, ErrModuleNotFound) {
		t.Fatalf("other owner resolve = %v, want ErrModuleNotFound", err)
	}
}

// classifyRegistryErr maps auth-ish failures to terminal, others to retryable.
func TestClassifyRegistryErr(t *testing.T) {
	if err := classifyRegistryErr(errors.New("401 unauthorized")); !errors.Is(err, ErrRegistryAuth) {
		t.Fatalf("want ErrRegistryAuth, got %v", err)
	}
	if err := classifyRegistryErr(errors.New("connection refused")); !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("want ErrRegistryUnavailable, got %v", err)
	}
	if err := classifyRegistryErr(nil); err != nil {
		t.Fatalf("nil should stay nil, got %v", err)
	}
}
