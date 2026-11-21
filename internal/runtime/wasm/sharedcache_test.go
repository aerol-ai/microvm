package wasm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// fakePrecompile stands in for the trusted compile: it writes one entry the
// way wazero does (0600, renamed from a temp name) and leaves a temp file.
func fakePrecompile(calls *atomic.Int32, gate chan struct{}) precompileFunc {
	return func(_ context.Context, dir, path string) error {
		calls.Add(1)
		if gate != nil {
			<-gate
		}
		vdir := filepath.Join(dir, "wazero-test")
		if err := os.MkdirAll(vdir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(vdir, "entry-"+filepath.Base(path)), []byte("native code"), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "stray"), nil, 0o600); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(vdir, "left.1.tmp"), nil, 0o600)
	}
}

func TestSharedCompileCache(t *testing.T) {
	root := t.TempDir()
	d := New(Config{CompileCacheDir: root, Worker: selfWorker()}, nil)
	var calls atomic.Int32
	gate := make(chan struct{})
	d.precompile = fakePrecompile(&calls, gate)
	op := &wasmmod.ResolvedModule{Path: "/modules/python.wasm", Digest: "d1", Operator: true}

	// Concurrent creates compile once.
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); d.ensureSharedCompiled(context.Background(), op) }()
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("compiled %d times, want once", calls.Load())
	}
	shared := filepath.Join(root, sharedCacheName)
	entry := filepath.Join(shared, "wazero-test", "entry-python.wasm")
	st, err := os.Stat(entry)
	if err != nil || st.Mode().Perm() != 0o444 {
		t.Fatalf("shared entry = %v, %v: want 0444", st, err)
	}
	for _, dir := range []string{shared, filepath.Join(shared, "wazero-test")} {
		if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode = %v, want 0700", dir, st.Mode().Perm())
		}
	}
	for _, left := range []string{filepath.Join(shared, "wazero-test", "left.1.tmp"), filepath.Join(shared, "stray")} {
		if _, err := os.Stat(left); !os.IsNotExist(err) {
			t.Fatalf("%s kept", left)
		}
	}
	// Done once: later creates do not compile again.
	d.ensureSharedCompiled(context.Background(), op)
	if calls.Load() != 1 {
		t.Fatal("compiled again")
	}

	// An owner's cache sees the entry as a link to the same read-only file;
	// a name the owner's worker already wrote stays its own.
	ownerDir := filepath.Join(root, "owners", "owner-"+shortHash("acme"))
	if err := os.MkdirAll(ownerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ownerDir, "wazero-test"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ownerDir, "wazero-test", "entry-own"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := d.compileCacheFor("acme"); got != ownerDir {
		t.Fatalf("owner cache = %q", got)
	}
	linked, err := os.Stat(filepath.Join(ownerDir, "wazero-test", "entry-python.wasm"))
	if err != nil || !os.SameFile(linked, mustStat(t, entry)) || linked.Mode().Perm() != 0o444 {
		t.Fatalf("owner link = %v, %v", linked, err)
	}
	d.compileCacheFor("acme") // linking again is harmless
	// A new owner gets the version folder made for it.
	fresh := d.compileCacheFor("fresh")
	if _, err := os.Stat(filepath.Join(fresh, "wazero-test", "entry-python.wasm")); err != nil {
		t.Fatalf("new owner's link: %v", err)
	}
	// A version folder the worker swapped for a link is not followed: no
	// link lands where it points.
	elsewhere := t.TempDir()
	evil := d.compileCacheFor("evil")
	if err := os.RemoveAll(filepath.Join(evil, "wazero-test")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(evil, "wazero-test")); err != nil {
		t.Fatal(err)
	}
	d.compileCacheFor("evil")
	if got, _ := os.ReadDir(elsewhere); len(got) != 0 {
		t.Fatalf("a link was made through the worker's symlink: %v", got)
	}
	// A warm-pool slot gets a cache of its own, on the cache root's device
	// (the run dir is often a tmpfs, where a link to a shared entry fails),
	// with the shared entries linked in.
	slotDir := filepath.Join(t.TempDir(), "pool", "abc", "pool-1")
	if err := os.MkdirAll(slotDir, 0o700); err != nil {
		t.Fatal(err)
	}
	slotCache := d.SlotCompileCache(slotDir)
	if slotCache != filepath.Join(root, slotCachesName, shortHash(slotDir), "cache") || slotCache == d.SlotCompileCache(t.TempDir()) {
		t.Fatalf("slot cache = %q", slotCache)
	}
	if linked := mustStat(t, filepath.Join(slotCache, "wazero-test", "entry-python.wasm")); !os.SameFile(linked, mustStat(t, entry)) {
		t.Fatal("slot cache does not see the shared entry")
	}
	if New(Config{}, nil).SlotCompileCache(slotDir) != "" || d.SlotCompileCache("") != "" {
		t.Fatal("a slot cache without a cache root")
	}

	// Not the operator's module, or no digest: never compiled for everyone.
	for _, m := range []*wasmmod.ResolvedModule{
		{Path: "/cache/x.wasm", Digest: "d2"},
		{Path: "/modules/y.wasm", Operator: true},
		nil,
	} {
		d.ensureSharedCompiled(context.Background(), m)
	}
	if calls.Load() != 1 {
		t.Fatal("a module that is not the operator's was compiled into the shared cache")
	}

	// A failed compile is retried by the next create.
	fails := 0
	d.precompile = func(context.Context, string, string) error { fails++; return errors.New("boom") }
	bad := &wasmmod.ResolvedModule{Path: "/modules/bad.wasm", Digest: "d3", Operator: true}
	d.ensureSharedCompiled(context.Background(), bad)
	d.ensureSharedCompiled(context.Background(), bad)
	if fails != 2 {
		t.Fatalf("failed compile tried %d times, want a retry", fails)
	}
	// A create that gives up does not wait for a compile in flight.
	slow := make(chan struct{})
	d.precompile = func(context.Context, string, string) error { <-slow; return nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.ensureSharedCompiled(ctx, &wasmmod.ResolvedModule{Path: "/modules/slow.wasm", Digest: "d4", Operator: true})
	d.sharedMu.Lock()
	inFlight := d.sharedState["d4"]
	d.sharedMu.Unlock()
	close(slow)
	<-inFlight.done // it still finishes, and must before the test's folders go

	// No cache root, or no compile step: nothing to do.
	New(Config{}, nil).ensureSharedCompiled(context.Background(), op)
	if err := sealShared(filepath.Join(root, "missing")); err == nil {
		t.Fatal("sealed a missing folder")
	}
	New(Config{}, nil).linkShared(ownerDir)
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// The standard modules are compiled for everyone at boot.
func TestPrecompileModules(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "std.wasm")
	d := New(Config{CompileCacheDir: t.TempDir()}, nil)
	var calls atomic.Int32
	d.precompile = fakePrecompile(&calls, nil)
	d.SetModuleResolver(operatorResolver{fakeResolver{path: modPath, digest: "std"}})
	d.PrecompileModules(context.Background(), []string{"python", "python"})
	if calls.Load() != 1 {
		t.Fatalf("precompiled %d times", calls.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.PrecompileModules(ctx, []string{"other"})
	New(Config{}, nil).PrecompileModules(context.Background(), []string{"python"})
	d.SetModuleResolver(failingResolver{})
	d.PrecompileModules(context.Background(), []string{"python"})
}

type operatorResolver struct{ fakeResolver }

func (r operatorResolver) Resolve(ctx context.Context, ref string) (*wasmmod.ResolvedModule, error) {
	m, err := r.fakeResolver.Resolve(ctx, ref)
	if m != nil {
		m.Operator = true
	}
	return m, err
}

type failingResolver struct{}

func (failingResolver) Resolve(context.Context, string) (*wasmmod.ResolvedModule, error) {
	return nil, errors.New("no")
}

// Item 2: a sandbox whose s3/rclone mount was started for root before the
// upgrade keeps a root worker (said once, counted), and never goes to a
// shared resident host.
func TestLegacyRootMounts(t *testing.T) {
	legacy := []mounts.ContainerBind{{HostPath: "/m/0", ContainerPath: "/data", RootOnly: true}}
	fresh := []mounts.ContainerBind{{HostPath: "/m/0", ContainerPath: "/data"}}
	if New(Config{}, nil).legacyRoot("sb", legacy) {
		t.Fatal("legacy root without workers that drop")
	}
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	sup := &ctxSupervisor{}
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir, Worker: selfWorker(), ResidentHostEnabled: true}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(sup)
	d.SetResidentHostSupervisor(sup)
	client := &recordingWorkerClient{}
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	if d.legacyRoot("sb-fresh", fresh) {
		t.Fatal("a mount started for the worker counted as legacy")
	}
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-legacy", "tok", legacy); err != nil {
		t.Fatal(err)
	}
	if len(sup.roots) != 1 || !sup.roots[0] {
		t.Fatalf("worker roots = %v: want one per-sandbox root worker", sup.roots)
	}
	d.mu.Lock()
	inst := d.byID["sb-legacy"]
	d.mu.Unlock()
	if inst == nil || inst.fromResidentHost || !inst.legacyRoot {
		t.Fatalf("instance = %+v: want its own root worker", inst)
	}
	if d.LegacyRootWorkers() != 1 {
		t.Fatalf("legacy root gauge = %d", d.LegacyRootWorkers())
	}
	// Said once per sandbox.
	if _, said := d.legacyLogged.Load("sb-legacy"); !said {
		t.Fatal("not logged")
	}
	if !d.legacyRoot("sb-legacy", legacy) {
		t.Fatal("legacy lost on a second look")
	}
	// A restored sandbox with such a mount goes to its own worker too.
	if _, err := d.RestoreSandbox(context.Background(), &models.Sandbox{ID: "sb-restore", ModuleRef: "demo.wasm"}, legacy); err != nil {
		t.Fatal(err)
	}
	if !sup.roots[len(sup.roots)-1] {
		t.Fatal("restored legacy sandbox not kept root")
	}
	// Destroying it forgets it.
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-legacy"}); err != nil {
		t.Fatal(err)
	}
	if _, said := d.legacyLogged.Load("sb-legacy"); said {
		t.Fatal("a destroyed sandbox stays in the legacy log set")
	}
}

// Different modules compile at the same time, each in its own staging
// folder; creates of one module still share its one compile.
func TestSharedCompilesRunInParallel(t *testing.T) {
	root := t.TempDir()
	// A crashed run's staging folder is cleared by the first compile.
	leftover := filepath.Join(root, sharedStageName, "c-old")
	if err := os.MkdirAll(leftover, 0o700); err != nil {
		t.Fatal(err)
	}
	d := New(Config{CompileCacheDir: root}, nil)
	var calls, running, peak atomic.Int32
	gate := make(chan struct{})
	inner := fakePrecompile(&calls, nil)
	d.precompile = func(ctx context.Context, dir, path string) error {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-gate
		defer running.Add(-1)
		return inner(ctx, dir, path)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		m := &wasmmod.ResolvedModule{Path: "/modules/m" + string(rune('a'+i%4)) + ".wasm", Digest: "d" + string(rune('a'+i%4)), Operator: true}
		wg.Add(1)
		go func() { defer wg.Done(); d.ensureSharedCompiled(context.Background(), m) }()
	}
	deadline := time.Now().Add(5 * time.Second)
	for peak.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(gate)
	wg.Wait()
	if peak.Load() != 4 || calls.Load() != 4 {
		t.Fatalf("peak %d compiles at once, %d in all: want 4 and 4", peak.Load(), calls.Load())
	}
	for _, m := range []string{"a", "b", "c", "d"} {
		if st, err := os.Stat(filepath.Join(root, sharedCacheName, "wazero-test", "entry-m"+m+".wasm")); err != nil || st.Mode().Perm() != 0o444 {
			t.Fatalf("entry m%s = %v, %v", m, st, err)
		}
	}
	if got, _ := os.ReadDir(filepath.Join(root, sharedStageName)); len(got) != 0 {
		t.Fatalf("staging left behind: %v", got)
	}
}

func TestPublishSharedErrors(t *testing.T) {
	if err := publishShared(filepath.Join(t.TempDir(), "missing"), t.TempDir()); err == nil {
		t.Fatal("published a missing stage")
	}
	stage, shared := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(stage, "v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "v1", "entry"), nil, 0o444); err != nil {
		t.Fatal(err)
	}
	// The version's name is taken by a file in the shared cache.
	if err := os.WriteFile(filepath.Join(shared, "v1"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishShared(stage, shared); err == nil {
		t.Fatal("published into a file")
	}
	// The cache root is a file: no staging folder can be made.
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := New(Config{CompileCacheDir: file}, nil).compileShared(context.Background(), "/m.wasm", "dm"); err == nil {
		t.Fatal("compiled under a file")
	}
}

// A slot's cache goes once its folder does (the slot was taken and its
// sandbox destroyed, or dropped); a live slot's stays, and a sweep runs at
// most once a minute.
func TestSweepSlotCaches(t *testing.T) {
	root := t.TempDir()
	d := New(Config{CompileCacheDir: root}, nil)
	live := filepath.Join(t.TempDir(), "live")
	gone := filepath.Join(t.TempDir(), "gone")
	for _, dir := range []string{live, gone} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if d.SlotCompileCache(dir) == "" {
			t.Fatal("no slot cache")
		}
	}
	// A cache whose owner file never got written: kept while young.
	young := filepath.Join(root, slotCachesName, "young")
	old := filepath.Join(root, slotCachesName, "old")
	for _, dir := range []string{young, old} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-2 * slotCacheOrphanAge)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}
	d.sweepSlotCaches() // within the minute: nothing
	if _, err := os.Stat(filepath.Join(root, slotCachesName, shortHash(gone))); err != nil {
		t.Fatal("swept within the interval")
	}
	d.slotSweepAt = time.Time{}
	d.sweepSlotCaches()
	for dir, want := range map[string]bool{
		filepath.Join(root, slotCachesName, shortHash(live)): true,
		filepath.Join(root, slotCachesName, shortHash(gone)): false,
		young: true,
		old:   false,
	} {
		if _, err := os.Stat(dir); (err == nil) != want {
			t.Errorf("%s kept=%v, want %v", dir, err == nil, want)
		}
	}
	// No slot caches yet, or a cache root that cannot be made.
	New(Config{CompileCacheDir: t.TempDir()}, nil).sweepSlotCaches()
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if New(Config{CompileCacheDir: file}, nil).SlotCompileCache(live) != "" {
		t.Fatal("a slot cache under a file")
	}
}
