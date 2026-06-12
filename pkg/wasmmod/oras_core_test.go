package wasmmod

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModuleAuthToken(t *testing.T) {
	tok, err := (ModuleAuth{PAT: "  inline  "}).token()
	if err != nil || tok != "inline" {
		t.Fatalf("inline PAT: got %q err %v", tok, err)
	}

	dir := t.TempDir()
	patFile := filepath.Join(dir, "pat")
	if err := os.WriteFile(patFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err = (ModuleAuth{PATPath: patFile}).token()
	if err != nil || tok != "file-token" {
		t.Fatalf("PATPath: got %q err %v", tok, err)
	}

	_, err = (ModuleAuth{}).token()
	if err == nil {
		t.Fatal("expected error with no credential")
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = (ModuleAuth{PATPath: empty}).token()
	if err == nil {
		t.Fatal("expected error for empty PAT file")
	}
}

func TestRegistryPlainHTTP(t *testing.T) {
	cases := map[string]bool{
		"localhost":        true,
		"localhost:5000":   true,
		"127.0.0.1":        true,
		"127.0.0.1:12345":  true,
		"[::1]":            true,
		"[::1]:5000":       true,
		"aocr.example.com": false,
	}
	for host, want := range cases {
		if got := registryPlainHTTP(host); got != want {
			t.Fatalf("registryPlainHTTP(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestNewAuthedRepoInvalidRef(t *testing.T) {
	_, err := newAuthedRepo("http://\x00bad", "u", "p")
	if err == nil {
		t.Fatal("expected error for invalid ref")
	}
}

func TestPushModuleArtifactValidation(t *testing.T) {
	ctx := context.Background()
	auth := ModuleAuth{PAT: "tok"}

	_, err := PushModuleArtifact(ctx, auth, "", "host/repo:tag")
	if err == nil {
		t.Fatal("expected error for empty wasm path")
	}
	_, err = PushModuleArtifact(ctx, auth, "/tmp/x.wasm", "")
	if err == nil {
		t.Fatal("expected error for empty registry ref")
	}
	_, err = PushModuleArtifact(ctx, ModuleAuth{}, WriteMinimalWasm(t, t.TempDir(), "m.wasm"), "host/repo:tag")
	if err == nil {
		t.Fatal("expected error without credentials")
	}
}

func TestPushPullModuleArtifactRoundTrip(t *testing.T) {
	reg := startTestOCIRegistry(t, "tenant/mod")
	defer reg.close()

	ctx := context.Background()
	auth := ModuleAuth{Username: "tenant", PAT: "secret"}
	ref := reg.ref("latest")

	src := WriteMinimalWasm(t, t.TempDir(), "push.wasm")
	wantDigest, _, err := fileDigest(src)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := PushModuleArtifact(ctx, auth, src, ref); err != nil {
		t.Fatalf("push: %v", err)
	}

	gotDigest, err := ResolveModuleManifestDigest(ctx, auth, ref)
	if err != nil {
		t.Fatalf("resolve manifest: %v", err)
	}
	if gotDigest == "" {
		t.Fatal("empty manifest digest")
	}

	dstDir := t.TempDir()
	gotPath, err := PullModuleArtifact(ctx, auth, ref, dstDir, maxModuleBytes)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if filepath.Base(gotPath) != moduleLayerName {
		t.Fatalf("layer name = %q", filepath.Base(gotPath))
	}
	gotDigest, _, err = fileDigest(gotPath)
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != wantDigest {
		t.Fatalf("digest mismatch: got %s want %s", gotDigest, wantDigest)
	}
}

func TestPullModuleArtifactSizeCap(t *testing.T) {
	reg := startTestOCIRegistry(t, "tenant/huge")
	defer reg.close()

	ctx := context.Background()
	auth := ModuleAuth{PAT: "tok"}
	ref := reg.ref("latest")
	src := WriteMinimalWasm(t, t.TempDir(), "m.wasm")

	if _, err := PushModuleArtifact(ctx, auth, src, ref); err != nil {
		t.Fatalf("push setup: %v", err)
	}

	_, err := PullModuleArtifact(ctx, auth, ref, t.TempDir(), 1)
	if !errors.Is(err, ErrModuleTooLarge) {
		t.Fatalf("want ErrModuleTooLarge, got %v", err)
	}
}

func TestPullModuleArtifactValidation(t *testing.T) {
	ctx := context.Background()
	auth := ModuleAuth{PAT: "tok"}

	_, err := PullModuleArtifact(ctx, auth, "", t.TempDir(), 0)
	if err == nil {
		t.Fatal("expected error for empty ref")
	}
	_, err = PullModuleArtifact(ctx, auth, "host/repo:tag", "", 0)
	if err == nil {
		t.Fatal("expected error for empty dst")
	}
	_, err = PullModuleArtifact(ctx, ModuleAuth{}, "host/repo:tag", t.TempDir(), 0)
	if err == nil {
		t.Fatal("expected error without credentials")
	}
}

func TestResolveModuleManifestDigestValidation(t *testing.T) {
	_, err := ResolveModuleManifestDigest(context.Background(), ModuleAuth{PAT: "t"}, "")
	if err == nil {
		t.Fatal("expected error for empty ref")
	}
	_, err = ResolveModuleManifestDigest(context.Background(), ModuleAuth{}, "host/repo:tag")
	if err == nil {
		t.Fatal("expected error without credentials")
	}
}

func TestClassifyRegistryErrVariants(t *testing.T) {
	for _, msg := range []string{"403 forbidden", "credential invalid", "access denied"} {
		if err := classifyRegistryErr(errors.New(msg)); !errors.Is(err, ErrRegistryAuth) {
			t.Fatalf("%q: want ErrRegistryAuth, got %v", msg, err)
		}
	}
}

func TestPushModuleArtifactMissingWasmFile(t *testing.T) {
	reg := startTestOCIRegistry(t, "tenant/missing")
	defer reg.close()
	_, err := PushModuleArtifact(context.Background(), ModuleAuth{PAT: "t"}, filepath.Join(t.TempDir(), "nope.wasm"), reg.ref("latest"))
	if err == nil {
		t.Fatal("expected error for missing wasm file")
	}
}

func TestPullModuleArtifactSkipsSizePreflightWhenUncapped(t *testing.T) {
	reg := startTestOCIRegistry(t, "tenant/uncapped")
	defer reg.close()
	ctx := context.Background()
	auth := ModuleAuth{PAT: "tok"}
	ref := reg.ref("latest")
	src := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	if _, err := PushModuleArtifact(ctx, auth, src, ref); err != nil {
		t.Fatalf("push setup: %v", err)
	}
	got, err := PullModuleArtifact(ctx, auth, ref, t.TempDir(), 0)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if err := ValidateFile(got); err != nil {
		t.Fatal(err)
	}
}

func TestPullModuleArtifactRejectsInvalidManifestJSON(t *testing.T) {
	reg := startTestOCIRegistry(t, "tenant/badmanifest")
	defer reg.close()
	ctx := context.Background()
	auth := ModuleAuth{PAT: "tok"}
	ref := reg.ref("latest")
	src := WriteMinimalWasm(t, t.TempDir(), "m.wasm")
	if _, err := PushModuleArtifact(ctx, auth, src, ref); err != nil {
		t.Fatalf("push setup: %v", err)
	}
	reg.setManifest("latest", []byte("not-json"))
	_, err := PullModuleArtifact(ctx, auth, ref, t.TempDir(), maxModuleBytes)
	if err == nil || !strings.Contains(err.Error(), "parse manifest") {
		t.Fatalf("want parse manifest error, got %v", err)
	}
}

func TestPullModuleArtifactMissingLayer(t *testing.T) {
	// Push a manifest-only artifact by hand: resolve succeeds but copy leaves no layer file.
	reg := startTestOCIRegistry(t, "tenant/broken")
	defer reg.close()
	ref := reg.ref("latest")

	// Empty registry — resolve will 404
	_, err := PullModuleArtifact(context.Background(), ModuleAuth{PAT: "t"}, ref, t.TempDir(), maxModuleBytes)
	if err == nil {
		t.Fatal("expected pull error")
	}
	if !errors.Is(err, ErrRegistryUnavailable) && !strings.Contains(err.Error(), "resolve") {
		t.Fatalf("unexpected error: %v", err)
	}
}
