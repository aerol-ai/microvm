package wasm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// A restarted sandboxd reads back the operator modules the one before it
// compiled into the shared cache: it does not compile them again.
func TestSharedCompileSurvivesRestart(t *testing.T) {
	root := t.TempDir()
	op := &wasmmod.ResolvedModule{Path: "/modules/python.wasm", Digest: "d1", Operator: true}
	var first atomic.Int32
	before := New(Config{CompileCacheDir: root}, nil)
	before.precompile = fakePrecompile(&first, nil)
	before.ensureSharedCompiled(context.Background(), op)
	if first.Load() != 1 {
		t.Fatalf("compiled %d times before the restart", first.Load())
	}
	var again atomic.Int32
	after := New(Config{CompileCacheDir: root}, nil)
	after.precompile = fakePrecompile(&again, nil)
	after.ensureSharedCompiled(context.Background(), op)
	if again.Load() != 0 {
		t.Fatalf("the restarted sandboxd compiled the module again (%d)", again.Load())
	}
}

// A create in a bucket whose host is up never waits for a shared compile:
// the host has the module loaded already. Here the compile state is gone
// (as after a restart, with nothing on disk) and the compile would hang.
func TestResidentCreateOnLiveHostSkipsSharedCompile(t *testing.T) {
	d, _, resident, client := residentTestDriver(t, true)
	root := t.TempDir()
	d.cfg.CompileCacheDir = root
	d.SetModuleResolver(operatorResolver{fakeResolver{path: wasmmod.WriteMinimalWasm(t, t.TempDir(), "demo.wasm"), digest: "deadbeef"}})
	var calls atomic.Int32
	d.precompile = fakePrecompile(&calls, nil)
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-up", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || resident.ensureCalls != 1 {
		t.Fatalf("first create: %d compiles, %d host starts", calls.Load(), resident.ensureCalls)
	}

	d.sharedMu.Lock()
	d.sharedState = nil
	d.sharedMu.Unlock()
	if err := os.RemoveAll(filepath.Join(root, sharedCacheName)); err != nil {
		t.Fatal(err)
	}
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	var hung atomic.Int32
	d.precompile = func(context.Context, string, string) error { hung.Add(1); <-hang; return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-same", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > time.Second || hung.Load() != 0 {
		t.Fatalf("a create onto the live host took %v and started %d compiles", took, hung.Load())
	}
	if resident.ensureCalls != 1 || len(client.instantiateCaps) != 2 {
		t.Fatalf("host starts %d, instantiates %d", resident.ensureCalls, len(client.instantiateCaps))
	}
}

// Only a marker root alone could have written, naming entries that are
// there and sealed, spares the compile; anything else compiles again.
func TestSharedMarkerChecks(t *testing.T) {
	op := &wasmmod.ResolvedModule{Path: "/modules/python.wasm", Digest: "d1", Operator: true}
	compiled := func(t *testing.T) (string, string) {
		t.Helper()
		root := t.TempDir()
		var calls atomic.Int32
		d := New(Config{CompileCacheDir: root}, nil)
		d.precompile = fakePrecompile(&calls, nil)
		d.ensureSharedCompiled(context.Background(), op)
		shared := filepath.Join(root, sharedCacheName)
		return root, filepath.Join(shared, sharedMarkerName("d1"))
	}
	recompiles := func(t *testing.T, root string) bool {
		t.Helper()
		var calls atomic.Int32
		d := New(Config{CompileCacheDir: root}, nil)
		d.precompile = fakePrecompile(&calls, nil)
		d.ensureSharedCompiled(context.Background(), op)
		return calls.Load() == 1
	}
	for name, spoil := range map[string]func(t *testing.T, root, marker string){
		"marker gone": func(t *testing.T, _, marker string) { mustDo(t, os.Remove(marker)) },
		"marker is a link": func(t *testing.T, _, marker string) {
			mustDo(t, os.Rename(marker, marker+".real"))
			mustDo(t, os.Symlink(marker+".real", marker))
		},
		"marker has two names":    func(t *testing.T, _, marker string) { mustDo(t, os.Link(marker, marker+".twin")) },
		"marker others may write": func(t *testing.T, _, marker string) { mustDo(t, os.Chmod(marker, 0o620)) },
		"marker for another compiler": func(t *testing.T, _, marker string) {
			mustDo(t, os.WriteFile(marker, []byte(sharedMarkerHeader+"\ndigest d1\ncompiler wazero-old\nentry wazero-test/entry-python.wasm\n"), 0o600))
		},
		"marker names a path outside": func(t *testing.T, _, marker string) {
			mustDo(t, os.WriteFile(marker, []byte(sharedMarkerText("d1", []string{"../x"})), 0o600))
		},
		"marker names no entry": func(t *testing.T, _, marker string) {
			mustDo(t, os.WriteFile(marker, []byte(sharedMarkerText("d1", nil)), 0o600))
		},
		"entry gone": func(t *testing.T, root, _ string) {
			mustDo(t, os.Remove(filepath.Join(root, sharedCacheName, "wazero-test", "entry-python.wasm")))
		},
		"entry unsealed": func(t *testing.T, root, _ string) {
			mustDo(t, os.Chmod(filepath.Join(root, sharedCacheName, "wazero-test", "entry-python.wasm"), 0o644))
		},
		"version folder is a link": func(t *testing.T, root, _ string) {
			v := filepath.Join(root, sharedCacheName, "wazero-test")
			mustDo(t, os.Rename(v, v+".real"))
			mustDo(t, os.Symlink(v+".real", v))
		},
		"shared folder opened up": func(t *testing.T, root, _ string) {
			mustDo(t, os.Chmod(filepath.Join(root, sharedCacheName), 0o755))
		},
	} {
		t.Run(name, func(t *testing.T) {
			root, marker := compiled(t)
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("no marker after a compile: %v", err)
			}
			if recompiles(t, root) {
				t.Fatal("a sound marker did not spare the compile")
			}
			spoil(t, root, marker)
			if !recompiles(t, root) {
				t.Fatal("compile spared on a marker that does not hold")
			}
		})
	}
	// A crash's half-written marker is swept by the next compile.
	root, _ := compiled(t)
	half := filepath.Join(root, sharedCacheName, ".marker-1.tmp")
	mustDo(t, os.WriteFile(half, nil, 0o600))
	var calls atomic.Int32
	d := New(Config{CompileCacheDir: root}, nil)
	d.precompile = fakePrecompile(&calls, nil)
	d.ensureSharedCompiled(context.Background(), &wasmmod.ResolvedModule{Path: "/modules/other.wasm", Digest: "d2", Operator: true})
	if _, err := os.Stat(half); !os.IsNotExist(err) || calls.Load() != 1 {
		t.Fatalf("half-written marker kept (%v), %d compiles", err, calls.Load())
	}
	if New(Config{}, nil).sharedCompiled("d1") || d.sharedCompiled("") {
		t.Fatal("a marker without a cache or a digest")
	}
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// A compile that published nothing writes no marker, and a marker that
// cannot be written fails the compile (its entries stay, unvouched).
func TestSharedMarkerWrites(t *testing.T) {
	root := t.TempDir()
	d := New(Config{CompileCacheDir: root}, nil)
	d.precompile = func(context.Context, string, string) error { return nil }
	if err := d.compileShared(context.Background(), "/m.wasm", "empty"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, sharedCacheName, sharedMarkerName("empty"))); !os.IsNotExist(err) {
		t.Fatal("a marker for a compile that wrote nothing")
	}
	if err := writeSharedMarker(filepath.Join(root, "missing"), "x", []string{"v/e"}); err == nil {
		t.Fatal("marker written into a missing folder")
	}
	if _, err := sharedEntries(filepath.Join(root, "missing")); err == nil {
		t.Fatal("listed a missing stage")
	}
	if _, ok := parseSharedMarker("junk", "x"); ok {
		t.Fatal("parsed junk")
	}
}

// The compiler a marker names: wazero's version folder and the CPU.
func TestSharedCompilerID(t *testing.T) {
	if v := wazeroVersion(); v == "" {
		t.Fatal("no wazero version")
	}
	prev := cpuInfoPath
	t.Cleanup(func() { cpuInfoPath = prev })
	info := filepath.Join(t.TempDir(), "cpuinfo")
	mustDo(t, os.WriteFile(info, []byte("processor : 0\nflags : fpu sse2 avx2\n\nprocessor : 1\nflags : other\n"), 0o600))
	cpuInfoPath = info
	a := cpuFeatures()
	mustDo(t, os.WriteFile(info, []byte("processor : 0\nFeatures : fp asimd\n"), 0o600))
	b := cpuFeatures()
	mustDo(t, os.WriteFile(info, []byte("processor : 0\n\nflags : late\n"), 0o600))
	if a == "" || b == "" || a == b || cpuFeatures() != "" {
		t.Fatalf("cpu features %q %q", a, b)
	}
	cpuInfoPath = filepath.Join(t.TempDir(), "none")
	if cpuFeatures() != "" {
		t.Fatal("features from a missing file")
	}
	if id := sharedCompilerID(); !strings.HasPrefix(id, "wazero-") {
		t.Fatalf("compiler id %q", id)
	}
}

// Under wasmtime the shared cache (wazero's compiled code) is not filled,
// so no create waits for it.
func TestSharedCompileSkippedForWasmtime(t *testing.T) {
	for engine, want := range map[string]int32{"wasmtime": 0, "": 1, "wazero": 1, " WAZERO ": 1} {
		var calls atomic.Int32
		d := New(Config{CompileCacheDir: t.TempDir(), Engine: engine}, nil)
		d.precompile = fakePrecompile(&calls, nil)
		d.ensureSharedCompiled(context.Background(), &wasmmod.ResolvedModule{Path: "/modules/p.wasm", Digest: "d", Operator: true})
		if calls.Load() != want {
			t.Errorf("engine %q: %d compiles, want %d", engine, calls.Load(), want)
		}
	}
}

// refResolver resolves each ref to a module of its own.
type refResolver struct{ dir string }

func (r refResolver) Resolve(_ context.Context, ref string) (*wasmmod.ResolvedModule, error) {
	if ref == "bad" {
		return nil, os.ErrNotExist
	}
	return &wasmmod.ResolvedModule{Ref: ref, Path: filepath.Join(r.dir, ref+".wasm"), Digest: "dg-" + ref, Operator: true, SizeBytes: 1}, nil
}

// At daemon start each standard module's resident host comes up right
// after its own compile: a slow compile of one holds back no other.
func TestPrepareStandardModulesPipelines(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	resident := &countingSupervisor{}
	d.SetResidentHostSupervisor(resident)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &recordingWorkerClient{} })
	d.cfg.CompileCacheDir = t.TempDir()
	d.SetModuleResolver(refResolver{dir: t.TempDir()})
	slow := make(chan struct{})
	var calls atomic.Int32
	fast := fakePrecompile(&calls, nil)
	d.precompile = func(ctx context.Context, dir, path string) error {
		if filepath.Base(path) == "slow.wasm" {
			<-slow
		}
		return fast(ctx, dir, path)
	}
	done := make(chan struct{})
	go func() {
		d.PrepareStandardModules(context.Background(), []string{"slow", "quick", "quick", "bad"}, true)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if bucketHasReadyHost(d, residentBucketID("", "dg-quick", d.cfg.DefaultMemoryMB)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the quick module's host waited for the slow module's compile")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("returned before the slow module was ready")
	default:
	}
	close(slow)
	<-done
	if resident.ensures.Load() != 2 || calls.Load() != 2 {
		t.Fatalf("%d hosts, %d compiles: want 2 and 2", resident.ensures.Load(), calls.Load())
	}
	// A cancelled start does nothing; no resolver, nothing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d.PrepareStandardModules(ctx, []string{"other"}, true)
	New(Config{}, nil).PrepareStandardModules(context.Background(), []string{"x"}, true)
}

// countingSupervisor is a fakeSupervisor for concurrent callers.
type countingSupervisor struct{ ensures, stops atomic.Int32 }

func (s *countingSupervisor) Ensure(context.Context, string, string) error {
	s.ensures.Add(1)
	return nil
}

func (s *countingSupervisor) Stop(string) error {
	s.stops.Add(1)
	return nil
}

// bucketHasReadyHost reports whether bucket id has a host up.
func bucketHasReadyHost(d *Driver, id string) bool {
	d.residentMu.Lock()
	b := d.residentBuckets[id]
	d.residentMu.Unlock()
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, h := range b.hosts {
		if h.ready {
			return true
		}
	}
	return false
}
