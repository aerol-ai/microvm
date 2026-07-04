package wasmmod

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
)

// ociResolveManifestFunc and ociPullArtifactFunc are the network boundary for
// resolveOCI. Tests swap them to exercise cache/single-flight without a live
// registry.
var (
	ociResolveManifestFunc = ResolveModuleManifestDigest
	ociPullArtifactFunc    = PullModuleArtifact
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

	// pullGroup collapses concurrent oci:// blob downloads of the same manifest
	// digest to a single network pull. N duplicate creates of one module_ref
	// (e.g. a 100k-wide warm-up of "oci://…/python:1") download once and share
	// the published cache file, instead of each racing its own pull (codex P0).
	// Keyed on the manifest digest, NOT the ref, so each caller has already
	// passed its own credentialed manifest resolve before joining the group.
	pullGroup singleflight.Group
}

// NewModuleResolver builds a chokepoint over modulesDir. cacheDir defaults to
// modulesDir/cache when empty.
func NewModuleResolver(modulesDir, cacheDir string) *ModuleResolver {
	if strings.TrimSpace(cacheDir) == "" {
		cacheDir = filepath.Join(modulesDir, "cache")
	}
	return &ModuleResolver{
		file:      NewResolver(modulesDir),
		CacheDir:  cacheDir,
		Reserved:  map[string]string{},
		Allowlist: map[string]struct{}{},
		MaxBytes:  maxModuleBytes,
	}
}

// SetDigestMode switches verify-once vs always-hash for local file resolves.
func (r *ModuleResolver) SetDigestMode(mode string) {
	if r != nil && r.file != nil {
		r.file.SetDigestMode(mode)
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

// resolveOCI enforces the allowlist, resolves the manifest digest with the
// caller's own credentials (cheap, no blob download), and short-circuits to the
// content-addressed cache when that manifest's bytes are already local — so the
// second-and-later resolve of the same tag does ZERO blob I/O. Only on a true
// cache miss does it pull, and that pull is single-flighted on the manifest
// digest so 100k concurrent duplicate creates download exactly once (codex P0).
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

	// Per-caller credentialed manifest resolve: this both authorizes the caller
	// against the registry AND yields the cache key, all without fetching a blob.
	// A registry that refuses our token fails here, so the cache shortcut below
	// can never serve bytes to an unauthorized caller.
	manifestDigest, err := ociResolveManifestFunc(pullCtx, auth, registryRef)
	if err != nil {
		return nil, err
	}

	// Cache shortcut: the manifest digest points at a previously-published
	// content file. No blob download, no single-flight needed.
	if rm, ok := r.lookupByManifest(manifestDigest); ok {
		rm.Ref = ref
		return rm, nil
	}

	// True miss: single-flight the blob pull on the manifest digest so duplicate
	// concurrent creates collapse to one download. Every joiner already passed
	// its own manifest resolve above.
	v, err, _ := r.pullGroup.Do(manifestDigest, func() (interface{}, error) {
		// Re-check the cache inside the group: an earlier in-flight pull for this
		// same manifest may have published while we were queued.
		if rm, ok := r.lookupByManifest(manifestDigest); ok {
			return rm, nil
		}
		return r.pullAndPublish(pullCtx, registryRef, manifestDigest, auth)
	})
	if err != nil {
		return nil, err
	}
	rm := *(v.(*ResolvedModule))
	rm.Ref = ref
	return &rm, nil
}

// manifestPointer is the on-disk hint mapping a manifest digest to the content
// digest of the published .wasm, so a repeat resolve of a mutable tag can hit
// the cache after a single credentialed manifest resolve (no blob download).
func (r *ModuleResolver) manifestPointer(manifestDigest string) string {
	return filepath.Join(r.CacheDir, ".manifest", sanitizeDigest(manifestDigest))
}

// lookupByManifest returns the published module for a manifest digest if both
// the pointer and the content file it names are present.
func (r *ModuleResolver) lookupByManifest(manifestDigest string) (*ResolvedModule, bool) {
	b, err := os.ReadFile(r.manifestPointer(manifestDigest))
	if err != nil {
		return nil, false
	}
	contentDigest := strings.TrimSpace(string(b))
	if contentDigest == "" {
		return nil, false
	}
	final := filepath.Join(r.CacheDir, contentDigest+".wasm")
	st, err := os.Stat(final)
	if err != nil || st.IsDir() {
		return nil, false
	}
	return &ResolvedModule{Path: final, Digest: contentDigest, SizeBytes: st.Size()}, true
}

// pullAndPublish downloads, validates, digests, atomically publishes the blob,
// and records the manifest→content pointer. Runs under the single-flight group.
func (r *ModuleResolver) pullAndPublish(ctx context.Context, registryRef, manifestDigest string, auth ModuleAuth) (*ResolvedModule, error) {
	tmpDir, err := os.MkdirTemp(r.CacheDir, ".pull-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	wasmPath, err := ociPullArtifactFunc(ctx, auth, registryRef, tmpDir, r.MaxBytes)
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
		r.writeManifestPointer(manifestDigest, digest)
		return &ResolvedModule{Path: final, Digest: digest, SizeBytes: st.Size()}, nil
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
			r.writeManifestPointer(manifestDigest, digest)
			return &ResolvedModule{Path: final, Digest: digest, SizeBytes: st.Size()}, nil
		}
		return nil, err
	}
	r.writeManifestPointer(manifestDigest, digest)
	return &ResolvedModule{Path: final, Digest: digest, SizeBytes: size}, nil
}

// writeManifestPointer records the manifest→content hint atomically. Best
// effort: a failed write only costs a future blob re-pull, never correctness.
func (r *ModuleResolver) writeManifestPointer(manifestDigest, contentDigest string) {
	dir := filepath.Join(r.CacheDir, ".manifest")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".ptr-*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	_, werr := tmp.WriteString(contentDigest)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmpName)
		return
	}
	if err := os.Rename(tmpName, r.manifestPointer(manifestDigest)); err != nil {
		_ = os.Remove(tmpName)
	}
}

// sanitizeDigest makes a manifest digest ("sha256:abc…") safe as a filename.
func sanitizeDigest(d string) string {
	return strings.ReplaceAll(strings.TrimSpace(d), ":", "-")
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
