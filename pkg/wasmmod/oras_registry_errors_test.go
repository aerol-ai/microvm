package wasmmod

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

func startUnauthorizedRegistry(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Www-Authenticate", `Bearer realm="test"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	t.Cleanup(ts.Close)
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host + "/denied/repo:latest"
}

func TestPushModuleArtifactRegistryAuthFailure(t *testing.T) {
	ref := startUnauthorizedRegistry(t)
	_, err := PushModuleArtifact(context.Background(), ModuleAuth{PAT: "bad"}, WriteMinimalWasm(t, t.TempDir(), "m.wasm"), ref)
	if err == nil {
		t.Fatal("expected push failure")
	}
	if !errors.Is(err, ErrRegistryAuth) {
		t.Fatalf("want ErrRegistryAuth, got %v", err)
	}
}

func TestPullSnapshotArtifactRegistryAuthFailure(t *testing.T) {
	ref := startUnauthorizedRegistry(t)
	patFile := t.TempDir() + "/pat"
	if err := os.WriteFile(patFile, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPullConfig{Host: "h", ClusterID: "c", PATPath: patFile}
	err := PullSnapshotArtifact(context.Background(), cfg, ref, t.TempDir())
	if err == nil {
		t.Fatal("expected pull failure")
	}
}

func TestResolveModuleManifestRegistryAuthFailure(t *testing.T) {
	ref := startUnauthorizedRegistry(t)
	_, err := ResolveModuleManifestDigest(context.Background(), ModuleAuth{PAT: "bad"}, ref)
	if !errors.Is(err, ErrRegistryAuth) {
		t.Fatalf("want ErrRegistryAuth, got %v", err)
	}
}
