package wasm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// sharedCacheName is the shared cache's folder under the cache root.
const sharedCacheName = "shared"

// sharedCompileTimeout bounds one trusted compile.
const sharedCompileTimeout = 10 * time.Minute

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
	if d.sharedCacheDir() == "" || d.precompile == nil || resolved == nil || !resolved.Operator || resolved.Digest == "" || resolved.Path == "" {
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

func (d *Driver) runSharedCompile(st *sharedCompile, resolved *wasmmod.ResolvedModule) {
	defer close(st.done)
	ctx, cancel := context.WithTimeout(context.Background(), sharedCompileTimeout)
	defer cancel()
	// One compile at a time: sealing reads the whole folder.
	d.precompileMu.Lock()
	defer d.precompileMu.Unlock()
	dir := d.sharedCacheDir()
	err := os.MkdirAll(dir, 0o700)
	if err == nil {
		err = os.Chmod(dir, 0o700)
	}
	if err == nil {
		err = d.precompile(ctx, dir, resolved.Path)
	}
	if serr := sealShared(dir); err == nil {
		err = serr
	}
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

// sealShared makes the shared cache read-only to everyone but root. wazero
// keeps its entries in a folder per version ("wazero-<version>-<arch>-<os>")
// under the cache folder: those folders become 0700, their entries 0444,
// and anything an interrupted compile left is removed. A worker only ever
// sees sealed entries (linkShared runs after).
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
// shared cache. Meant to run in the background at daemon start, before
// the resident prewarm, so neither a prewarm nor a first create compiles
// them.
func (d *Driver) PrecompileModules(ctx context.Context, refs []string) {
	if d.resolver == nil || d.sharedCacheDir() == "" {
		return
	}
	for _, ref := range refs {
		if ctx.Err() != nil {
			return
		}
		resolved, err := d.resolver.Resolve(ctx, ref)
		if err != nil {
			continue
		}
		d.ensureSharedCompiled(ctx, resolved)
	}
}

// precompileFunc runs the trusted compile step (worker.Precompile).
type precompileFunc func(ctx context.Context, cacheDir, modulePath string) error
