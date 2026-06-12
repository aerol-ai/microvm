package wasmmod

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ModuleResolver is the single resolution chokepoint for every module_ref
// shape. ALL callers (sandbox create, CreateWasmModule, start/rehydrate by
// pinned digest, failover) go through Resolve so that allowlist enforcement,
// core-wasip1 validation, digest computation, and atomic cache publishing
// happen in exactly one place. Splitting this logic across call sites is how
// the SSRF allowlist or the validation gets silently skipped on one path.
//
// Resolution precedence (a single ref grammar with explicit ordering — see
// codex C3, the alias/bare-file collision):
//
//  1. reserved keyword  ("python")      -> ModulesDir/<staged filename>
//  2. oci:// ref        ("oci://h/r:t") -> allowlist -> pull -> cache/<digest>.wasm
//  3. catalogue id      (BYO digest id) -> CatalogueLookup -> local path
//  4. file:// / abs / bare filename     -> ModulesDir (legacy Resolver)
//
// Reserved keywords win over a same-named bare file on disk, so a stray
// ModulesDir/python file can never shadow the standard "python" runtime.
type ModuleResolver struct {
	// file does steps 1/4 local resolution + validation + digest.
	file *Resolver
	// CacheDir holds pulled oci:// modules as <digest>.wasm. Distinct from the
	// checkpoint root so eviction never walks a passivated sandbox's mem.snap.
	CacheDir string
	// Reserved maps a standard keyword to its staged filename under ModulesDir
	// (e.g. "python" -> "python.wasm"). Provisioned by Ansible, identical fleet
	// wide; never DB-backed (codex C1).
	Reserved map[string]string
	// Allowlist is the set of registry hosts an oci:// ref may target. Empty
	// means "deny all remote pulls" — the safe default until configured.
	Allowlist map[string]struct{}
	// PullTimeout bounds a single oci:// pull so it cannot stall sandbox boot.
	PullTimeout time.Duration
	// MaxBytes caps a pulled artifact (mirrors ValidateFile's 256MiB).
	MaxBytes int64
	// Auth carries the default registry credentials for oci:// pulls. A
	// per-tenant override can be passed to ResolveWithAuth (failover, BYO).
	Auth ModuleAuth
	// CatalogueLookup resolves a BYO catalogue id to an already-local path +
	// digest. Optional; nil disables step 3.
	CatalogueLookup func(ctx context.Context, id string) (path, digest string, ok bool)
}

// NewModuleResolver builds a chokepoint over modulesDir. cacheDir defaults to
// modulesDir/cache when empty.
func NewModuleResolver(modulesDir, cacheDir string) *ModuleResolver {
	if strings.TrimSpace(cacheDir) == "" {
		cacheDir = filepath.Join(modulesDir, "cache")
	}
	return &ModuleResolver{
		file:      &Resolver{ModulesDir: modulesDir},
		CacheDir:  cacheDir,
		Reserved:  map[string]string{},
		Allowlist: map[string]struct{}{},
		MaxBytes:  maxModuleBytes,
	}
}

// Resolve resolves ref using the default Auth.
func (r *ModuleResolver) Resolve(ctx context.Context, ref string) (*ResolvedModule, error) {
	return r.ResolveWithAuth(ctx, ref, nil)
}

// ResolveWithAuth resolves ref, using authOverride for an oci:// pull when
// non-nil (failover hands the original tenant's sealed creds here so a private
// module re-pulls on the new owner — codex C4).
func (r *ModuleResolver) ResolveWithAuth(ctx context.Context, ref string, authOverride *ModuleAuth) (*ResolvedModule, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("%w: empty ref", ErrModuleNotFound)
	}

	// 1. Reserved keyword (exact, case-insensitive, no scheme/slash).
	if !strings.Contains(ref, "/") && !strings.Contains(ref, "://") {
		if filename, ok := r.Reserved[strings.ToLower(ref)]; ok {
			return r.file.Resolve(ctx, filename)
		}
	}

	// 2. oci:// remote ref.
	if strings.HasPrefix(ref, "oci://") {
		return r.resolveOCI(ctx, ref, authOverride)
	}

	// 3. BYO catalogue id.
	if r.CatalogueLookup != nil {
		if path, digest, ok := r.CatalogueLookup(ctx, ref); ok {
			if err := ValidateFile(path); err != nil {
				return nil, err
			}
			return &ResolvedModule{Ref: ref, Path: path, Digest: digest}, nil
		}
	}

	// 4. file:// / absolute / bare filename under ModulesDir.
	resolved, err := r.file.Resolve(ctx, ref)
	if err != nil {
		// Normalize a missing-file into the typed not-found so the service can
		// answer 404 with the valid reserved keywords.
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %q", ErrModuleNotFound, ref)
		}
		return nil, err
	}
	return resolved, nil
}

// resolveOCI enforces the allowlist, then pulls (single artifact) into a temp
// dir, validates, digests, and atomically publishes to CacheDir/<digest>.wasm.
// A cache hit (same digest already published) skips the network entirely on
// the second-and-later resolve of the same bytes.
func (r *ModuleResolver) resolveOCI(ctx context.Context, ref string, authOverride *ModuleAuth) (*ResolvedModule, error) {
	registryRef := strings.TrimPrefix(ref, "oci://")
	host := registryHost(registryRef)
	if host == "" {
		return nil, fmt.Errorf("%w: oci ref has no host", ErrModuleNotFound)
	}
	if _, ok := r.Allowlist[host]; !ok {
		return nil, fmt.Errorf("%w: %q", ErrRegistryNotAllowed, host)
	}

	auth := r.Auth
	if authOverride != nil {
		auth = *authOverride
	}

	if err := os.MkdirAll(r.CacheDir, 0o700); err != nil {
		return nil, err
	}

	pullCtx := ctx
	if r.PullTimeout > 0 {
		var cancel context.CancelFunc
		pullCtx, cancel = context.WithTimeout(ctx, r.PullTimeout)
		defer cancel()
	}

	tmpDir, err := os.MkdirTemp(r.CacheDir, ".pull-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	wasmPath, err := PullModuleArtifact(pullCtx, auth, registryRef, tmpDir, r.MaxBytes)
	if err != nil {
		return nil, err
	}
	// Validate (core-wasip1, size, magic) BEFORE the bytes are publishable.
	if err := ValidateFile(wasmPath); err != nil {
		return nil, err
	}
	digest, size, err := fileDigest(wasmPath)
	if err != nil {
		return nil, err
	}

	final := filepath.Join(r.CacheDir, digest+".wasm")
	if st, statErr := os.Stat(final); statErr == nil && !st.IsDir() {
		// Cache hit: identical bytes already published by a prior resolve.
		return &ResolvedModule{Ref: ref, Path: final, Digest: digest, SizeBytes: st.Size()}, nil
	}

	// Atomic publish: fsync the temp file, then rename into place. A reader
	// only ever sees an absent file or the complete artifact — never a
	// half-written one (hard rule 4).
	if err := fsyncFile(wasmPath); err != nil {
		return nil, err
	}
	if err := os.Rename(wasmPath, final); err != nil {
		// Lost a publish race with a concurrent resolve of the same digest;
		// the existing file is byte-identical, so treat it as a hit.
		if st, statErr := os.Stat(final); statErr == nil && !st.IsDir() {
			return &ResolvedModule{Ref: ref, Path: final, Digest: digest, SizeBytes: st.Size()}, nil
		}
		return nil, err
	}
	return &ResolvedModule{Ref: ref, Path: final, Digest: digest, SizeBytes: size}, nil
}

// ResolveByDigest returns the content-addressed cached module for digest, if a
// frozen copy exists in CacheDir. start/rehydrate use this to boot the EXACT
// bytes pinned at create rather than re-resolving a mutable alias/tag (codex
// C2). Reports ok=false on a cache miss; the caller then falls back to ref
// resolution with a digest-match assertion.
func (r *ModuleResolver) ResolveByDigest(digest string) (*ResolvedModule, bool) {
	digest = strings.TrimSpace(digest)
	if digest == "" {
		return nil, false
	}
	p := filepath.Join(r.CacheDir, digest+".wasm")
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return &ResolvedModule{Ref: digest, Path: p, Digest: digest, SizeBytes: st.Size()}, true
	}
	return nil, false
}

func fsyncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
