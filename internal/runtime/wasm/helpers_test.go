package wasm

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestWasmExecArgsAndMergeEnv(t *testing.T) {
	if got := wasmExecArgs("", []string{"a", "b"}); len(got) != 2 || got[0] != "a" {
		t.Fatalf("fallback args = %#v", got)
	}
	if got := wasmExecArgs("  ls -la ", nil); len(got) != 2 || got[0] != "ls" {
		t.Fatalf("parsed args = %#v", got)
	}
	if got := wasmExecArgs("   ", []string{"x"}); len(got) != 1 || got[0] != "x" {
		t.Fatalf("whitespace command = %#v", got)
	}
	if mergeEnv(nil, nil) != nil {
		t.Fatal("mergeEnv empty should be nil")
	}
	merged := mergeEnv(map[string]string{"A": "1"}, map[string]string{"B": "2"})
	if merged["A"] != "1" || merged["B"] != "2" {
		t.Fatalf("merged = %#v", merged)
	}
}

func TestCopyStringMapAndWasmArgs(t *testing.T) {
	if copyStringMap(nil) != nil {
		t.Fatal("copyStringMap(nil) should be nil")
	}
	out := copyStringMap(map[string]string{"k": "v"})
	if out["k"] != "v" {
		t.Fatalf("copy = %#v", out)
	}
	if got := wasmArgs(models.CreateSandboxRequest{}); len(got) != 1 || got[0] != "wasm" {
		t.Fatalf("default wasm args = %#v", got)
	}
	if got := wasmArgs(models.CreateSandboxRequest{ContainerCommand: []string{"only"}}); got[0] != "only" {
		t.Fatalf("single arg = %#v", got)
	}
	if got := wasmArgs(models.CreateSandboxRequest{ContainerCommand: []string{"a", "b"}}); len(got) != 2 {
		t.Fatalf("multi arg = %#v", got)
	}
}

func TestModuleRefAndEntryExportHelpers(t *testing.T) {
	req := models.CreateSandboxRequest{Image: "demo.wasm"}
	if moduleRefFromRequest(req) == "" {
		t.Fatal("expected module ref from image")
	}
	if entryExportFromRequest(req) != "_start" {
		t.Fatalf("entry export = %q", entryExportFromRequest(req))
	}
}

func TestDurabilityOfAndModuleSize(t *testing.T) {
	sb := &models.Sandbox{Durability: models.DurabilityDurable}
	inst := &sandboxInstance{durability: models.DurabilityPassivatable}
	if got := durabilityOf(sb, inst); got != models.DurabilityDurable {
		t.Fatalf("sandbox durability = %q", got)
	}
	if got := durabilityOf(nil, inst); got != models.DurabilityPassivatable {
		t.Fatalf("instance durability = %q", got)
	}
	if got := durabilityOf(nil, nil); got != models.DurabilityPassivatable {
		t.Fatalf("default durability = %q", got)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "mod.wasm")
	if err := os.WriteFile(path, []byte("wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	if moduleSize(path) != 4 {
		t.Fatalf("module size = %d", moduleSize(path))
	}
	if moduleSize(filepath.Join(dir, "missing")) != 0 {
		t.Fatal("missing module size should be 0")
	}
}

func TestWasip1ListenPort(t *testing.T) {
	if got := wasip1ListenPort(nil); got != wasmengine.WASIListenPortDisabled {
		t.Fatalf("no ports = %d", got)
	}
	if got := wasip1ListenPort([]int{8080}); got != 0 {
		t.Fatalf("exposed ports = %d", got)
	}
}

func TestPathHelpers(t *testing.T) {
	d := New(Config{RunDir: "/run/wasm"}, nil)
	if got := d.sandboxDir("sb-1"); got != filepath.Join("/run/wasm", "sb-1") {
		t.Fatalf("sandboxDir = %q", got)
	}
	if got := d.socketPath("sb-1"); !filepath.IsAbs(got) || filepath.Base(got) != "aerol-wasm-sb-1.sock" {
		t.Fatalf("socketPath = %q", got)
	}
}

func TestFromDaemonConfig(t *testing.T) {
	cfg := FromDaemonConfig(config.Config{
		WasmRunDir:          "/run",
		WasmModulesDir:      "/mods",
		WasmDefaultMemoryMB: 128,
		WasmDefaultTimeout:  time.Minute,
		WasmDrainTimeout:    30 * time.Second,
	})
	if cfg.RunDir != "/run" || cfg.ModulesDir != "/mods" || cfg.DefaultMemoryMB != 128 {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestCtxHelpers(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancel()
	if ctxDeadline(ctx).IsZero() {
		t.Fatal("expected deadline")
	}
	if ctxDeadline(context.Background()).Before(time.Now()) {
		t.Fatal("expected future default deadline")
	}
	if !ctxDone(context.Background(), time.Now().Add(-time.Second)) {
		t.Fatal("past deadline should be done")
	}
	if ctxDone(context.Background(), time.Now().Add(time.Hour)) {
		t.Fatal("future deadline should not be done")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !ctxDone(canceled, time.Now().Add(time.Hour)) {
		t.Fatal("canceled ctx should be done")
	}
	sleepBrief(context.Background())
}

func TestAsPortGateway(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	pg, ok := AsPortGateway(d)
	if !ok || pg == nil {
		t.Fatal("driver should implement PortGateway")
	}
	if _, ok := AsPortGateway(struct{}{}); ok {
		t.Fatal("non-gateway should not match")
	}
}

func TestCopyDirRoundTrip(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "copy")
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(src, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b.txt"), []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyDir(src, dst); err != nil {
		t.Fatalf("copyDir: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "sub", "b.txt"))
	if err != nil || string(got) != "world" {
		t.Fatalf("nested copy = %q err=%v", got, err)
	}
}

func TestCopyFileRoundTrip(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src.txt")
	dst := filepath.Join(t.TempDir(), "dst.txt")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "payload" {
		t.Fatalf("dst = %q err=%v", got, err)
	}
}

func TestCopyDirErrors(t *testing.T) {
	if err := copyDir(t.TempDir()+"/missing", t.TempDir()); err == nil {
		t.Fatal("expected stat error")
	}
	file := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyDir(file, t.TempDir()); err == nil {
		t.Fatal("expected not-a-directory error")
	}
	if err := copyFile(filepath.Join(t.TempDir(), "missing"), t.TempDir()); err == nil {
		t.Fatal("expected copyFile open error")
	}
}

func TestLooksLikeDigestAndPathUnderDir(t *testing.T) {
	if !looksLikeDigest(stringsRepeat("a", 64)) {
		t.Fatal("expected valid digest")
	}
	if looksLikeDigest("short") || looksLikeDigest(stringsRepeat("g", 64)) {
		t.Fatal("expected invalid digest")
	}
	root := t.TempDir()
	inside := filepath.Join(root, "child", "mod.wasm")
	if !pathUnderDir(root, inside) {
		t.Fatalf("%q should be under %q", inside, root)
	}
	if pathUnderDir(root, filepath.Join(os.TempDir(), "elsewhere")) {
		t.Fatal("outside path should not match")
	}
	if pathUnderDir("", inside) || pathUnderDir(root, "") {
		t.Fatal("empty root/path should be false")
	}
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}

func TestPreopensFromBindsSkipsEmpty(t *testing.T) {
	pre := preopensFromBinds("/work", []mounts.ContainerBind{
		{HostPath: "", ContainerPath: "/skip"},
		{HostPath: "/host", ContainerPath: ""},
		{HostPath: "/real", ContainerPath: "/mnt"},
	})
	if len(pre) != 2 {
		t.Fatalf("preopens = %#v", pre)
	}
}

func TestWasmArgsFromSandbox(t *testing.T) {
	if got := wasmArgsFromSandbox(nil); len(got) != 1 || got[0] != "wasm" {
		t.Fatalf("nil sandbox = %#v", got)
	}
	if got := wasmArgsFromSandbox(&models.Sandbox{ContainerCommand: []string{"run"}}); got[0] != "run" {
		t.Fatalf("sandbox args = %#v", got)
	}
}

func TestBumpRunGeneration(t *testing.T) {
	inst := &sandboxInstance{}
	if inst.bumpRunGeneration() != 1 {
		t.Fatal("first gen should be 1")
	}
	if inst.bumpRunGeneration() != 2 {
		t.Fatal("second gen should be 2")
	}
}

func TestWaitGuestListenReadyOnOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	if err := d.waitGuestListenReady("127.0.0.1", port); err != nil {
		t.Fatalf("waitGuestListenReady: %v", err)
	}
}

func TestRehydrateGateReturnsSameMutex(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	m1 := d.rehydrateGate("sb")
	m2 := d.rehydrateGate("sb")
	if m1 != m2 {
		t.Fatal("expected same gate mutex")
	}
}
