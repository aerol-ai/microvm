package wasm

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// The shared compile cache. Each owner's workers write a cache of their own
// (compileCacheFor): one tenant's worker must never write compiled code
// another tenant's worker loads. But a new owner's first create would then
// compile every standard module from scratch, where a node-wide cache made
// it a cache read. So there is one more cache, shared by every owner:
//
//   - Only a trusted step writes it: sandboxd's --wasm-precompile process,
//     which compiles and runs nothing else. It compiles only operator
//     modules (wasmmod.ResolvedModule.Operator: reserved keywords and files
//     the operator staged), decided from where the resolver found the
//     module, never from the request. Pulled and catalogue modules stay in
//     their owner's cache: a crafted module and a compiler bug must not land
//     in everyone's.
//   - Workers only read it. Its folder is root's (0700) and every entry is
//     made 0444 before any worker can see it. A worker sees an entry through
//     a hard link in its own owner cache (linkShared), so a miss still
//     writes there: wazero fails a compile whose cache write fails, so a
//     cache a worker could only read would break every miss.
//
// wazero keys an entry by the module's bytes, its runtime configuration
// and the CPU, so an entry compiled from the operator's file serves any
// worker that compiles the same bytes, whoever's sandbox it is.
//
// A compile is done once per node, not once per sandboxd: its last step
// writes a marker beside the entries (sharedMarkerName), and a sandboxd
// that finds a sound marker for a module, the one before a restart
// having compiled it, reads the entries back instead of compiling again.
// The marker names the compiler (wazero's version folder) and the CPU, so
// an upgrade or another CPU compiles again.

// sharedCacheName is the shared cache's folder under the cache root.
const sharedCacheName = "shared"

// sharedStageName is where each trusted compile writes before its entries
// join the shared cache: under the cache root, root's (0700), so on the
// shared cache's device and out of every worker's reach.
const sharedStageName = ".shared-stage"

// sharedCompileTimeout bounds one trusted compile.
const sharedCompileTimeout = 10 * time.Minute

// sharedMarkerPrefix starts a compile's marker in the shared cache, and
// sharedMarkerTemp the name it is written under before its rename.
// linkShared only links version folders, so neither reaches a worker.
const (
	sharedMarkerPrefix = ".compiled-"
	sharedMarkerTemp   = ".marker-*.tmp"
	sharedMarkerHeader = "aerolvm shared compile v1"
	// sharedMarkerMax bounds what a marker check reads.
	sharedMarkerMax = 64 << 10
)

// sharedMarkerName is the marker of module digest compiled by this build
// on this CPU.
func sharedMarkerName(digest string) string {
	sum := sha256.Sum256([]byte(digest + "\x00" + sharedCompilerID()))
	return sharedMarkerPrefix + hex.EncodeToString(sum[:16])
}

// sharedCompilerID is what a shared entry depends on besides the module:
// wazero's version folder, as wazero names it from the build, and the
// CPU features it keys entries by.
var sharedCompilerID = sync.OnceValue(func() string {
	return "wazero-" + wazeroVersion() + "-" + runtime.GOARCH + "-" + runtime.GOOS + " cpu=" + cpuFeatures()
})

// wazeroVersion is wazero's version as wazero reads it for its cache
// folder: the module's version in the build, "dev" when there is none.
func wazeroVersion() string {
	v := ""
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if strings.Contains(dep.Path, "github.com/tetratelabs/wazero") {
				v = dep.Version
			}
		}
	}
	if v == "" || v == "(devel)" {
		return "dev"
	}
	return v
}

// cpuInfoPath is where cpuFeatures reads the CPU's features (tests point
// it elsewhere).
var cpuInfoPath = "/proc/cpuinfo"

// cpuFeatures hashes the first CPU's feature line in cpuInfoPath ("flags"
// on x86, "Features" on arm64); "" where there is none.
func cpuFeatures() string {
	f, err := os.Open(cpuInfoPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 16<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			break // the end of the first CPU's block
		}
		key, val, ok := strings.Cut(line, ":")
		if key = strings.TrimSpace(key); ok && (key == "flags" || key == "Features") {
			sum := sha256.Sum256([]byte(strings.TrimSpace(val)))
			return hex.EncodeToString(sum[:8])
		}
	}
	return ""
}

// sharedMarkerText is what a marker holds: the module, the compiler, and
// each entry ("<version folder>/<name>") the compile published.
func sharedMarkerText(digest string, entries []string) string {
	var b strings.Builder
	b.WriteString(sharedMarkerHeader + "\n")
	b.WriteString("digest " + digest + "\n")
	b.WriteString("compiler " + sharedCompilerID() + "\n")
	for _, e := range entries {
		b.WriteString("entry " + e + "\n")
	}
	return b.String()
}

// parseSharedMarker returns the entries of a marker written for digest by
// this compiler, and false for anything else.
func parseSharedMarker(text, digest string) ([]string, bool) {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 4 || lines[0] != sharedMarkerHeader || lines[1] != "digest "+digest || lines[2] != "compiler "+sharedCompilerID() {
		return nil, false
	}
	var entries []string
	for _, line := range lines[3:] {
		e, ok := strings.CutPrefix(line, "entry ")
		version, name, ok2 := strings.Cut(e, "/")
		if !ok || !ok2 || !plainName(version) || !plainName(name) {
			return nil, false
		}
		entries = append(entries, e)
	}
	return entries, true
}

// plainName is one path element that names something in its folder.
func plainName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00")
}

// sharedEntries lists a sealed staging folder's entries as
// "<version folder>/<name>".
func sharedEntries(stage string) ([]string, error) {
	versions, err := os.ReadDir(stage)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range versions {
		if !v.IsDir() {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(stage, v.Name()))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.Type().IsRegular() {
				out = append(out, v.Name()+"/"+e.Name())
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// writeSharedMarker writes digest's marker into shared, last, once its
// entries are in: written under a temporary name, synced, then renamed, so
// a marker is whole or absent.
func writeSharedMarker(shared, digest string, entries []string) error {
	f, err := os.CreateTemp(shared, sharedMarkerTemp)
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.WriteString(sharedMarkerText(digest, entries))
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, filepath.Join(shared, sharedMarkerName(digest)))
	}
	if werr != nil {
		_ = os.Remove(tmp)
	}
	return werr
}

type sharedCompile struct {
	done chan struct{}
	err  error
}

func (d *Driver) sharedCacheDir() string {
	if d.cfg.CompileCacheDir == "" {
		return ""
	}
	return filepath.Join(d.cfg.CompileCacheDir, sharedCacheName)
}

// ensureSharedCompiled compiles an operator module into the shared cache
// once per sandboxd, before the worker that loads it starts, so that
// worker reads it back instead of compiling it. Concurrent callers for the
// same module wait for the one compile. A failure is logged and costs only
// the cache: the worker then compiles into its owner's cache, as it would
// for any other module.
func (d *Driver) ensureSharedCompiled(ctx context.Context, resolved *wasmmod.ResolvedModule) {
	if d.sharedCacheDir() == "" || d.precompile == nil || !d.wazeroEngine() || resolved == nil || !resolved.Operator || resolved.Digest == "" || resolved.Path == "" {
		return
	}
	d.sharedMu.Lock()
	if d.sharedState == nil {
		d.sharedState = map[string]*sharedCompile{}
	}
	st := d.sharedState[resolved.Digest]
	first := st == nil
	if first {
		st = &sharedCompile{done: make(chan struct{})}
		d.sharedState[resolved.Digest] = st
	}
	d.sharedMu.Unlock()
	if first {
		// Not the request's context: a create given up on must not leave
		// the compile half done for the next one.
		go d.runSharedCompile(st, resolved)
	}
	select {
	case <-st.done:
	case <-ctx.Done():
	}
}

// wazeroEngine reports whether workers run wazero, whose compiled code the
// shared cache holds: under wasmtime a create would wait for a compile no
// worker reads.
func (d *Driver) wazeroEngine() bool {
	e := strings.ToLower(strings.TrimSpace(d.cfg.Engine))
	return e == "" || e == "wazero"
}

func (d *Driver) runSharedCompile(st *sharedCompile, resolved *wasmmod.ResolvedModule) {
	defer close(st.done)
	// A sandboxd before this one compiled it: nothing to wait for.
	if d.sharedCompiled(resolved.Digest) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), sharedCompileTimeout)
	defer cancel()
	err := d.compileShared(ctx, resolved.Path, resolved.Digest)
	st.err = err
	if err != nil {
		// Let a later create try again.
		d.sharedMu.Lock()
		delete(d.sharedState, resolved.Digest)
		d.sharedMu.Unlock()
		if d.logger != nil {
			d.logger.Warn("wasm shared compile failed; workers compile this module into their owner's cache", "digest", resolved.Digest, "error", err)
		}
	}
}

// compileShared compiles one module into a staging folder of its own,
// seals it there and moves its entries into the shared cache, then writes
// the module's marker. Each compile has its own folder, so different
// modules compile at the same time (a first create of one never waits on
// another's compile) and sealing one never sees another's half-written
// files. A rename is atomic, so linkShared only ever finds whole, sealed
// entries, and a marker only ever names entries already there.
func (d *Driver) compileShared(ctx context.Context, modulePath, digest string) error {
	shared := d.sharedCacheDir()
	stageRoot := filepath.Join(d.cfg.CompileCacheDir, sharedStageName)
	d.stageSweep.Do(func() {
		_ = os.RemoveAll(stageRoot)
		// Markers a crash left half written.
		left, _ := filepath.Glob(filepath.Join(shared, sharedMarkerTemp))
		for _, p := range left {
			_ = os.Remove(p)
		}
	})
	for _, dir := range []string{shared, stageRoot} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	stage, err := os.MkdirTemp(stageRoot, "c-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := d.precompile(ctx, stage, modulePath); err != nil {
		return err
	}
	if err := sealShared(stage); err != nil {
		return err
	}
	entries, err := sharedEntries(stage)
	if err != nil {
		return err
	}
	if err := publishShared(stage, shared); err != nil {
		return err
	}
	if digest == "" || len(entries) == 0 {
		// Nothing to vouch for: the next sandboxd compiles it again.
		return nil
	}
	return writeSharedMarker(shared, digest, entries)
}

// publishShared moves each sealed entry of stage into the same version
// folder of shared. An entry that is there already (the same bytes compiled
// for another module name) is replaced by an identical one; links a worker
// cache already holds keep the old inode.
func publishShared(stage, shared string) error {
	versions, err := os.ReadDir(stage)
	if err != nil {
		return err
	}
	var errs []error
	for _, v := range versions {
		if !v.IsDir() {
			continue
		}
		dst := filepath.Join(shared, v.Name())
		if err := os.Mkdir(dst, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			errs = append(errs, err)
			continue
		}
		entries, err := os.ReadDir(filepath.Join(stage, v.Name()))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, e := range entries {
			errs = append(errs, os.Rename(filepath.Join(stage, v.Name(), e.Name()), filepath.Join(dst, e.Name())))
		}
	}
	return errors.Join(errs...)
}

// sealShared makes a compile's staging folder read-only to everyone but
// root before its entries join the shared cache. wazero keeps its entries
// in a folder per version ("wazero-<version>-<arch>-<os>") under the cache
// folder: those folders become 0700, their entries 0444, and anything an
// interrupted write left is removed. A worker only ever sees sealed
// entries (publishShared moves them in whole, linkShared runs after).
func sealShared(dir string) error {
	versions, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, v := range versions {
		vdir := filepath.Join(dir, v.Name())
		if !v.IsDir() {
			errs = append(errs, os.RemoveAll(vdir))
			continue
		}
		errs = append(errs, os.Chmod(vdir, 0o700))
		entries, err := os.ReadDir(vdir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, e := range entries {
			path := filepath.Join(vdir, e.Name())
			if strings.HasSuffix(e.Name(), ".tmp") || !e.Type().IsRegular() {
				errs = append(errs, os.RemoveAll(path))
				continue
			}
			info, err := e.Info()
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if info.Mode().Perm() != 0o444 {
				errs = append(errs, os.Chmod(path, 0o444))
			}
		}
	}
	return errors.Join(errs...)
}

// linkShared puts every sealed shared entry into an owner's cache as a hard
// link in the same version folder: the worker reads it there but cannot
// change it (it is root's and 0444), and a name the worker already wrote
// stays its own. The owner's version folder is the worker's to write, so it
// is reached by descriptor, never by a path the worker could turn into a
// link elsewhere (sharedLinkInto).
func (d *Driver) linkShared(ownerDir string) {
	dir := d.sharedCacheDir()
	if dir == "" {
		return
	}
	versions, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, v := range versions {
		if !v.IsDir() {
			continue
		}
		if err := d.sharedLinkInto(filepath.Join(dir, v.Name()), ownerDir, v.Name()); err != nil && d.logger != nil {
			d.logger.Debug("wasm shared cache not linked", "dir", ownerDir, "version", v.Name(), "error", err)
		}
	}
}

// PrecompileModules compiles the operator modules refs name into the
// shared cache (PrepareStandardModules without the prewarm).
func (d *Driver) PrecompileModules(ctx context.Context, refs []string) {
	d.PrepareStandardModules(ctx, refs, false)
}

// startupPrepares is how many standard modules PrepareStandardModules
// readies at once: a node's first boot compiles each, and running every
// compile together would starve the creates that come meanwhile.
const startupPrepares = 2

// PrepareStandardModules readies the operator modules refs name at daemon
// start, in the background: each is compiled into the shared cache (a
// cache read when a sandboxd before this one compiled it) and, with
// prewarm, its resident host is brought up right after its own compile,
// not after every module's. It returns when all are done.
func (d *Driver) PrepareStandardModules(ctx context.Context, refs []string, prewarm bool) {
	if d.resolver == nil {
		return
	}
	queue := make(chan string, len(refs))
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		if !seen[ref] {
			seen[ref] = true
			queue <- ref
		}
	}
	close(queue)
	var wg sync.WaitGroup
	for range min(startupPrepares, len(seen)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ref := range queue {
				if ctx.Err() != nil {
					return
				}
				resolved, err := d.resolver.Resolve(ctx, ref)
				if err != nil || resolved == nil {
					if prewarm && d.logger != nil {
						d.logger.Warn("resident prewarm skipped: ref did not resolve", "ref", ref, "error", err)
					}
					continue
				}
				d.ensureSharedCompiled(ctx, resolved)
				if prewarm {
					d.prewarmResolved(ctx, ref, resolved)
				}
			}
		}()
	}
	wg.Wait()
}

// precompileFunc runs the trusted compile step (worker.Precompile).
type precompileFunc func(ctx context.Context, cacheDir, modulePath string) error
