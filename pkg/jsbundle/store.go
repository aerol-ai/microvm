package jsbundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// Store is a content-addressed bundle store backing POST /v1/js-bundles
// (plans/isolate-runtime.md §8). Bundles are keyed by digest on disk;
// uploaded names are pointers to a digest, and a per-tenant index bounds how
// many distinct bundles one tenant may hold. It ships with the abuse controls
// the plan requires from day one: a per-bundle size cap and a per-tenant
// bundle-count quota. GC of unreferenced bundles is reference-counted by the
// caller (the service knows which digests live sandboxes pin); the store
// exposes Delete for it.
//
// The store is process-local and guarded by a single mutex — bundle writes are
// rare (a push), not on the sandbox hot path, so contention is a non-issue and
// a plain lock keeps the invariants (digest file + name pointer + tenant index
// stay consistent) obvious.
type Store struct {
	dir          string
	maxBytes     int64
	perTenantMax int

	mu       sync.Mutex
	names    map[string]string   // uploaded name → digest
	byTenant map[string][]string // tenant → digests it owns
}

// StoreConfig configures the abuse controls. Zero maxBytes / perTenantMax mean
// unlimited on that axis (operator/self-host default); the managed control
// plane sets real caps.
type StoreConfig struct {
	Dir          string
	MaxBytes     int64
	PerTenantMax int
}

// NewStore opens (creating if needed) a content-addressed bundle store rooted
// at cfg.Dir and rebuilds its in-memory name/tenant indexes from disk so
// pushed bundles survive a daemon restart.
func NewStore(cfg StoreConfig) (*Store, error) {
	if strings.TrimSpace(cfg.Dir) == "" {
		return nil, fmt.Errorf("jsbundle: store dir is required")
	}
	if err := os.MkdirAll(filepath.Join(cfg.Dir, "blobs"), 0o700); err != nil {
		return nil, fmt.Errorf("jsbundle: mkdir store: %w", err)
	}
	s := &Store{
		dir:          cfg.Dir,
		maxBytes:     cfg.MaxBytes,
		perTenantMax: cfg.PerTenantMax,
		names:        make(map[string]string),
		byTenant:     make(map[string][]string),
	}
	if err := s.loadIndex(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) blobPath(digest string) string {
	return filepath.Join(s.dir, "blobs", digest+".json")
}

func (s *Store) indexPath() string {
	return filepath.Join(s.dir, "index.json")
}

type persistedIndex struct {
	Names    map[string]string   `json:"names"`
	ByTenant map[string][]string `json:"by_tenant"`
}

func (s *Store) loadIndex() error {
	raw, err := os.ReadFile(s.indexPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("jsbundle: read index: %w", err)
	}
	var idx persistedIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return fmt.Errorf("jsbundle: parse index: %w", err)
	}
	if idx.Names != nil {
		s.names = idx.Names
	}
	if idx.ByTenant != nil {
		s.byTenant = idx.ByTenant
	}
	return nil
}

// persistIndexLocked writes the name/tenant index. Callers hold s.mu.
func (s *Store) persistIndexLocked() error {
	raw, err := json.Marshal(persistedIndex{Names: s.names, ByTenant: s.byTenant})
	if err != nil {
		return err
	}
	tmp := s.indexPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.indexPath())
}

// Put stores a bundle content-addressed by digest and, when name is non-empty,
// points that uploaded name at the digest for the given tenant. Storing an
// identical bundle again is idempotent (same digest → same blob), and re-using
// a name just repoints it. tenant "" is the operator/self-host null tenant and
// is exempt from the per-tenant quota. Returns the digest.
func (s *Store) Put(tenant, name string, b *Bundle) (string, error) {
	if err := b.Validate(); err != nil {
		return "", err
	}
	if s.maxBytes > 0 && b.SizeBytes() > s.maxBytes {
		return "", fmt.Errorf("%w: %d bytes > cap %d", ErrBundleTooLarge, b.SizeBytes(), s.maxBytes)
	}
	digest, err := b.ComputeDigest()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Quota is counted over DISTINCT digests a tenant owns; re-pushing an
	// existing digest (or repointing a name to it) never trips it.
	if s.perTenantMax > 0 && tenant != "" && !contains(s.byTenant[tenant], digest) {
		if len(s.byTenant[tenant]) >= s.perTenantMax {
			return "", fmt.Errorf("%w: tenant %q holds %d (max %d)", ErrTenantQuotaExceeded, tenant, len(s.byTenant[tenant]), s.perTenantMax)
		}
	}

	if _, err := os.Stat(s.blobPath(digest)); err != nil {
		raw, err := json.Marshal(b)
		if err != nil {
			return "", err
		}
		tmp := s.blobPath(digest) + ".tmp"
		if err := os.WriteFile(tmp, raw, 0o600); err != nil {
			return "", fmt.Errorf("jsbundle: write blob: %w", err)
		}
		if err := os.Rename(tmp, s.blobPath(digest)); err != nil {
			return "", err
		}
	}

	// Track ownership for every tenant INCLUDING the null/operator tenant so
	// the catalogue (list/ownership) works for it too; the quota exemption for
	// "" lives in the check above, not here.
	if !contains(s.byTenant[tenant], digest) {
		s.byTenant[tenant] = append(s.byTenant[tenant], digest)
	}
	if name != "" {
		s.names[nameKey(tenant, name)] = digest
	}
	if err := s.persistIndexLocked(); err != nil {
		return "", err
	}
	return digest, nil
}

// GetByDigest loads a bundle by its content digest.
func (s *Store) GetByDigest(digest string) (*Bundle, error) {
	raw, err := os.ReadFile(s.blobPath(digest))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: digest %s", ErrBundleNotFound, digest)
		}
		return nil, err
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("jsbundle: parse blob %s: %w", digest, err)
	}
	b.Digest = digest
	return &b, nil
}

// GetByName resolves an uploaded name (scoped to tenant) to its bundle.
func (s *Store) GetByName(tenant, name string) (*Bundle, error) {
	s.mu.Lock()
	digest, ok := s.names[nameKey(tenant, name)]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: name %q", ErrBundleNotFound, name)
	}
	return s.GetByDigest(digest)
}

// GCUnreferenced deletes every digest that is neither pinned by a live sandbox
// nor referenced by an uploaded catalogue name. Named uploads with no live
// sandbox are kept — the catalogue IS a reference. Returns digests removed.
func (s *Store) GCUnreferenced(pinned map[string]struct{}) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	named := make(map[string]struct{}, len(s.names))
	for _, d := range s.names {
		named[d] = struct{}{}
	}
	candidates := make(map[string]struct{})
	for _, digests := range s.byTenant {
		for _, d := range digests {
			if _, ok := pinned[d]; ok {
				continue
			}
			if _, ok := named[d]; ok {
				continue
			}
			candidates[d] = struct{}{}
		}
	}
	var removed []string
	for d := range candidates {
		if err := os.Remove(s.blobPath(d)); err != nil && !os.IsNotExist(err) {
			return removed, err
		}
		for tenant, digests := range s.byTenant {
			s.byTenant[tenant] = remove(digests, d)
			if len(s.byTenant[tenant]) == 0 {
				delete(s.byTenant, tenant)
			}
		}
		removed = append(removed, d)
	}
	if len(removed) == 0 {
		return nil, nil
	}
	if err := s.persistIndexLocked(); err != nil {
		return removed, err
	}
	return removed, nil
}

// Delete removes tenant's ownership of a digest: it drops tenant's name
// pointers to it and its entry in tenant's ownership list, and removes the
// shared blob ONLY when no other tenant still owns it. Blobs are content-
// addressed and DEDUPLICATED across tenants, so a tenant deleting bytes it
// happens to share with another tenant must not evict the other tenant's
// bundle. Returns ErrBundleNotFound when tenant does not own the digest so
// DELETE /v1/js-bundles/{digest} 404s (matching /v1/wasm-modules) instead of
// silently succeeding on an unknown or unowned id.
func (s *Store) Delete(tenant, digest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.Contains(s.byTenant[tenant], digest) {
		return ErrBundleNotFound
	}
	// Drop only the caller's name pointers to this digest.
	prefix := tenant + "\x00"
	for name, d := range s.names {
		if d == digest && strings.HasPrefix(name, prefix) {
			delete(s.names, name)
		}
	}
	// Drop the caller's ownership.
	s.byTenant[tenant] = remove(s.byTenant[tenant], digest)
	if len(s.byTenant[tenant]) == 0 {
		delete(s.byTenant, tenant)
	}
	// Remove the shared blob only when no tenant owns it anymore.
	stillOwned := false
	for _, digests := range s.byTenant {
		if slices.Contains(digests, digest) {
			stillOwned = true
			break
		}
	}
	if !stillOwned {
		if err := os.Remove(s.blobPath(digest)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return s.persistIndexLocked()
}

// ListDigests returns the content digests a tenant owns (the catalogue GET
// scope for POST /v1/js-bundles). Order is unspecified.
func (s *Store) ListDigests(tenant string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.byTenant[tenant]))
	copy(out, s.byTenant[tenant])
	return out
}

// TenantOwns reports whether tenant owns digest — the ownership gate for
// GET/DELETE /v1/js-bundles/{digest} so one tenant cannot read or delete
// another's bundle by guessing a digest.
func (s *Store) TenantOwns(tenant, digest string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.byTenant[tenant], digest)
}

// NamesForTenant returns the uploaded name → digest pointers a tenant holds.
func (s *Store) NamesForTenant(tenant string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string)
	prefix := tenant + "\x00"
	for k, digest := range s.names {
		if name, ok := strings.CutPrefix(k, prefix); ok {
			out[name] = digest
		}
	}
	return out
}

// nameKey scopes an uploaded name to a tenant so two tenants may reuse the same
// name without collision (the null tenant "" is the operator's global scope).
func nameKey(tenant, name string) string {
	return tenant + "\x00" + name
}

func contains(xs []string, x string) bool {
	return slices.Contains(xs, x)
}

func remove(xs []string, x string) []string {
	out := xs[:0]
	for _, v := range xs {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}
