package wasmmod

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func writeTestSnapshotDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := `{"schema_version":1}`
	for name, body := range map[string]string{
		"config.json":     cfg,
		"memory.zstd":     "mem",
		"globals.cbor":    "globals",
		"wasi-state.cbor": "wasi",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestPushSnapshotArtifactMissingLayerFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPushConfig{Host: "h", ClusterID: "c", PATPath: patFile}
	_, err := PushSnapshotArtifact(context.Background(), cfg, dir, "127.0.0.1:1/repo:tag", "inc-test")
	if err == nil {
		t.Fatal("expected error for missing layer file")
	}
}

func TestPushPullSnapshotArtifactRoundTrip(t *testing.T) {
	reg := startTestOCIRegistry(t, "cluster/wasm-checkpoints/sb-1")
	defer reg.close()

	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("cluster-pat"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPushConfig{
		Host:      "ignored",
		ClusterID: "cluster-1",
		PATPath:   patFile,
	}
	pullCfg := ORASPullConfig{
		Host:      "ignored",
		ClusterID: "cluster-1",
		PATPath:   patFile,
	}

	snapDir := writeTestSnapshotDir(t)
	ref := reg.ref("latest")
	ctx := context.Background()

	digest, err := PushSnapshotArtifact(ctx, cfg, snapDir, ref, "inc-test")
	if err != nil {
		t.Fatalf("push snapshot: %v", err)
	}
	if digest == "" {
		t.Fatal("expected manifest digest")
	}

	dstDir := t.TempDir()
	if err := PullSnapshotArtifact(ctx, pullCfg, ref, "inc-test", dstDir); err != nil {
		t.Fatalf("pull snapshot: %v", err)
	}
	for _, name := range []string{"config.json", "memory.zstd", "globals.cbor", "wasi-state.cbor"} {
		if _, err := os.Stat(filepath.Join(dstDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
}

// TestDeleteSnapshotRefMissingManifest pins the documented contract: a ref that
// is already absent is the success state for a delete. This is load-bearing for
// the no-vacuum checkpoint cleanup — the caller drops its tracking row only when
// DeleteRef returns nil, so an already-gone manifest must NOT look like a
// failure (otherwise the row would be retained and retried forever).
func TestDeleteSnapshotRefMissingManifest(t *testing.T) {
	reg := startTestOCIRegistry(t, "cluster/wasm-checkpoints/missing")
	defer reg.close()
	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("cluster-pat"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPushConfig{Host: "h", ClusterID: "c1", PATPath: patFile}
	if err := DeleteSnapshotRef(context.Background(), cfg, reg.ref("latest")); err != nil {
		t.Fatalf("missing manifest must be treated as success, got: %v", err)
	}
}

// TestDeleteSnapshotRefResolveError covers the non-not-found resolve branch: a
// transport-level failure (registry unreachable) must surface as an error, NOT
// be swallowed like not-found — otherwise the caller would wrongly drop a
// tracking row for a manifest that may still exist.
func TestDeleteSnapshotRefResolveError(t *testing.T) {
	reg := startTestOCIRegistry(t, "cluster/wasm-checkpoints/unreachable")
	ref := reg.ref("latest")
	reg.close() // server down → Resolve gets a connection error, not a 404

	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("cluster-pat"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPushConfig{Host: "h", ClusterID: "c1", PATPath: patFile}
	if err := DeleteSnapshotRef(context.Background(), cfg, ref); err == nil {
		t.Fatal("a transport error must not be treated as success")
	}
}

func TestDeleteSnapshotRefRoundTrip(t *testing.T) {
	reg := startTestOCIRegistry(t, "cluster/wasm-checkpoints/sb-del")
	defer reg.close()

	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("cluster-pat"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ORASPushConfig{
		Host:      "ignored",
		ClusterID: "cluster-1",
		PATPath:   patFile,
	}
	ref := reg.ref("latest")
	ctx := context.Background()

	if _, err := PushSnapshotArtifact(ctx, cfg, writeTestSnapshotDir(t), ref, "inc-test"); err != nil {
		t.Fatalf("push: %v", err)
	}
	if err := DeleteSnapshotRef(ctx, cfg, ref); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestReadPATFileErrors(t *testing.T) {
	if _, err := readPATFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected read error")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPATFile(empty); err == nil {
		t.Fatal("expected empty PAT error")
	}
}

func TestWasmCheckpointDigestTagEdgeCases(t *testing.T) {
	if got := WasmCheckpointDigestTag(""); got != "latest" {
		t.Fatalf("empty digest tag = %q", got)
	}
	long := strings.Repeat("a", 70)
	if got := WasmCheckpointDigestTag(long); len(got) != 64 {
		t.Fatalf("truncated tag len = %d", len(got))
	}
}

// The registry is where the lifetime boundary has to hold: a metadata fence
// applied after a mutable registry write cannot undo that write. These run
// against a real in-process OCI registry.
func TestCheckpointArtifactsAreBoundToTheirLifetime(t *testing.T) {
	reg := startTestOCIRegistry(t, "cluster/wasm-checkpoints/sb-1")
	defer reg.close()
	patFile := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(patFile, []byte("cluster-pat"), 0o600); err != nil {
		t.Fatal(err)
	}
	pushCfg := ORASPushConfig{Host: "ignored", ClusterID: "cluster-1", PATPath: patFile}
	pullCfg := ORASPullConfig{Host: "ignored", ClusterID: "cluster-1", PATPath: patFile}
	ctx := context.Background()
	snap := writeTestSnapshotDir(t)

	// A pull restoring lifetime B must refuse what lifetime A published, even
	// through a ref it was handed directly.
	ref := reg.ref(WasmCheckpointLatestTag("inc-a"))
	if _, err := PushSnapshotArtifact(ctx, pushCfg, snap, ref, "inc-a"); err != nil {
		t.Fatal(err)
	}
	if err := PullSnapshotArtifact(ctx, pullCfg, ref, "inc-b", t.TempDir()); !errors.Is(err, ErrCheckpointLifetimeMismatch) {
		t.Fatalf("restoring lifetime inc-b from inc-a's checkpoint returned %v; that hands the new sandbox the old lifetime's memory", err)
	}
	if err := PullSnapshotArtifact(ctx, pullCfg, ref, "inc-a", t.TempDir()); err != nil {
		t.Fatalf("the publishing lifetime could not restore its own checkpoint: %v", err)
	}

	// Identical snapshot bytes, pushed twice, must still be two manifests.
	// Deleting a ref deletes its MANIFEST, so a shared one would let deleting
	// one push's tag remove the other's.
	first, err := PushSnapshotArtifact(ctx, pushCfg, snap, reg.ref("dup-1"), "inc-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := PushSnapshotArtifact(ctx, pushCfg, snap, reg.ref("dup-2"), "inc-a")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("two pushes of identical content share manifest %s; deleting either push's tag deletes both", first)
	}
	other, err := PushSnapshotArtifact(ctx, pushCfg, snap, reg.ref("dup-3"), "inc-b")
	if err != nil {
		t.Fatal(err)
	}
	if other == first || other == second {
		t.Fatal("two lifetimes published the same manifest")
	}

	if _, err := PushSnapshotArtifact(ctx, pushCfg, snap, reg.ref("unbound"), ""); err == nil {
		t.Fatal("a checkpoint with no lifetime was published; it could be restored into any lifetime of the sandbox")
	}
}

// Lifetime tags have to stay inside the OCI tag grammar and length, and differ
// per lifetime while staying stable for one.
func TestCheckpointLifetimeTags(t *testing.T) {
	inc := strings.Repeat("f", 64) // incarnation ids are 64 hex characters
	digest := "sha256:" + strings.Repeat("a", 64)
	tagGrammar := regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	for _, tag := range []string{WasmCheckpointLatestTag(inc), WasmCheckpointLifetimeDigestTag(inc, digest)} {
		if !tagGrammar.MatchString(tag) {
			t.Fatalf("tag %q (len %d) is not a valid OCI tag", tag, len(tag))
		}
	}
	if WasmCheckpointLatestTag("inc-a") == WasmCheckpointLatestTag("inc-b") {
		t.Fatal("two lifetimes share a rolling tag; one can re-point the other's")
	}
	if WasmCheckpointLatestTag("inc-a") != WasmCheckpointLatestTag(" inc-a ") {
		t.Fatal("one lifetime's tag is not stable")
	}
	if WasmCheckpointLifetimeDigestTag("inc-a", digest) == WasmCheckpointLifetimeDigestTag("inc-b", digest) {
		t.Fatal("two lifetimes share a digest tag")
	}
}
