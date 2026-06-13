package service

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// StartWasmModuleGC launches the periodic wasm_modules catalogue janitor.
func (s *Service) StartWasmModuleGC(ctx context.Context) {
	if s == nil || !s.cfg.EnableWasm || !s.cfg.WasmModuleGCEnabled {
		return
	}
	interval := s.cfg.WasmModuleGCInterval
	if interval <= 0 {
		return
	}
	s.startPeriodic(ctx, interval, 30*time.Second, func(c context.Context) {
		s.runWasmModuleGC(c, time.Now())
		// Catalogue GC reclaims rows; cache GC reclaims the on-disk
		// content-addressed bytes those rows (and bare oci:// pulls) leave
		// behind. Run it second so a row deleted above frees its digest for
		// eviction in the same sweep.
		s.runWasmCacheGC(c, time.Now())
	})
}

func (s *Service) runWasmModuleGC(ctx context.Context, now time.Time) {
	ttl := s.cfg.WasmModuleGCTTL
	if ttl <= 0 {
		return
	}
	cutoff := now.UTC().Add(-ttl)
	records, err := s.store.ListWasmModulesOlderThan(ctx, cutoff)
	if err != nil {
		s.logger.Warn("wasm module gc list failed", "error", err)
		return
	}
	for _, rec := range records {
		referenced, err := s.store.IsWasmModuleReferenced(ctx, rec.ID, rec.ModuleRef, rec.Digest)
		if err != nil {
			s.logger.Warn("wasm module gc reference check failed", "module_id", rec.ID, "error", err)
			continue
		}
		if referenced {
			continue
		}
		// GC is strictly local — never hand a ref to RemoveImage here. An oci://
		// ref would re-resolve during cleanup, re-pulling from the registry (and
		// failing without the tenant's creds), which both does network I/O on the
		// janitor and strands the row when it errors (codex P1). Reclaim by the
		// recorded content digest (a local-only RemoveImage path that also drops
		// the warm-pool entry) or, lacking a digest, the recorded local path; the
		// content-addressed cache file is evicted separately by cache GC below.
		if s.wasm != nil && rec.Digest != "" {
			_ = s.wasm.RemoveImage(ctx, rec.Digest)
		} else if wasmPathUnderDir(s.cfg.WasmModulesDir, rec.ModulePath) {
			_ = os.RemoveAll(rec.ModulePath)
		}
		if err := s.store.DeleteWasmModule(ctx, rec.ID); err != nil {
			s.logger.Warn("wasm module gc delete failed", "module_id", rec.ID, "error", err)
			continue
		}
		s.invalidateWasmModuleInventoryCache()
		s.logger.Info("wasm module gc removed unreferenced catalogue row", "module_id", rec.ID)
	}
}

// runWasmCacheGC evicts content-addressed oci:// cache files
// (CacheDir/<digest>.wasm) that no live sandbox or catalogue row references.
// Two independent triggers, both refcount-gated:
//
//   - TTL: a file untouched (by mtime) for longer than WasmCacheGCTTL.
//   - Size cap: when the cache total exceeds WasmCacheMaxBytes, evict
//     unreferenced files oldest-first until back under the cap.
//
// Referenced files are NEVER evicted regardless of age or pressure — they still
// count toward the total, so a cache full of in-use modules simply stops
// shrinking rather than yanking live bytes (boot-path safety over disk).
func (s *Service) runWasmCacheGC(ctx context.Context, now time.Time) {
	ttl := s.cfg.WasmCacheGCTTL
	maxBytes := s.cfg.WasmCacheMaxBytes
	if ttl <= 0 && maxBytes <= 0 {
		return
	}
	cacheDir := strings.TrimSpace(s.cfg.WasmCacheDir)
	if cacheDir == "" {
		cacheDir = filepath.Join(s.cfg.WasmModulesDir, "cache")
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		if !os.IsNotExist(err) {
			s.logger.Warn("wasm cache gc readdir failed", "dir", cacheDir, "error", err)
		}
		return
	}

	type cacheFile struct {
		path   string
		digest string
		size   int64
		mod    time.Time
	}
	var files []cacheFile
	var total int64
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".wasm") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		f := cacheFile{
			path:   filepath.Join(cacheDir, name),
			digest: strings.TrimSuffix(name, ".wasm"),
			size:   info.Size(),
			mod:    info.ModTime(),
		}
		files = append(files, f)
		total += f.size
	}
	// Oldest-first so both TTL and size-pressure eviction reclaim the least
	// recently used bytes first.
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })

	// Resolve the in-use set (sandbox-referenced ∪ catalogued) in ONE batched
	// query for the whole sweep, rather than two DB probes per file against the
	// single-writer store (codex P1). Membership is then an O(1) map lookup.
	digests := make([]string, 0, len(files))
	for _, f := range files {
		digests = append(digests, f.digest)
	}
	inUse, err := s.store.WasmDigestsInUse(ctx, digests)
	if err != nil {
		s.logger.Warn("wasm cache gc in-use check failed", "error", err)
		return
	}

	ttlCutoff := now.UTC().Add(-ttl)
	for _, f := range files {
		overCap := maxBytes > 0 && total > maxBytes
		expired := ttl > 0 && f.mod.UTC().Before(ttlCutoff)
		if !overCap && !expired {
			// Files are sorted oldest-first: once we hit one that's neither
			// expired nor needed for cap relief, every later file is younger and
			// the total only shrinks, so nothing remaining can qualify.
			break
		}
		// Refcount gate: skip (but keep counting) anything still in use.
		if _, ok := inUse[f.digest]; ok {
			continue
		}
		if err := os.Remove(f.path); err != nil {
			if !os.IsNotExist(err) {
				s.logger.Warn("wasm cache gc delete failed", "path", f.path, "error", err)
			}
			continue
		}
		total -= f.size
		s.logger.Info("wasm cache gc evicted module", "digest", f.digest, "size_bytes", f.size, "reason", evictReason(expired, overCap))
	}
}

func evictReason(expired, overCap bool) string {
	switch {
	case expired && overCap:
		return "ttl+cap"
	case expired:
		return "ttl"
	default:
		return "cap"
	}
}

func wasmPathUnderDir(root, path string) bool {
	root = strings.TrimSpace(root)
	path = strings.TrimSpace(path)
	if root == "" || path == "" {
		return false
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel))
}
