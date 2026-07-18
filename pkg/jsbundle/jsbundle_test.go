package jsbundle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleWorker = `export default { async fetch(req) { return new Response("ok"); } };`

func TestBundleValidate(t *testing.T) {
	tests := []struct {
		name    string
		b       Bundle
		wantErr bool
	}{
		{"ok", Bundle{MainModule: "m.js", Modules: map[string]string{"m.js": "x"}, CompatibilityDate: "2026-01-01"}, false},
		{"empty main", Bundle{Modules: map[string]string{"m.js": "x"}, CompatibilityDate: "2026-01-01"}, true},
		{"no modules", Bundle{MainModule: "m.js", CompatibilityDate: "2026-01-01"}, true},
		{"main not in modules", Bundle{MainModule: "other.js", Modules: map[string]string{"m.js": "x"}, CompatibilityDate: "2026-01-01"}, true},
		{"empty source", Bundle{MainModule: "m.js", Modules: map[string]string{"m.js": ""}, CompatibilityDate: "2026-01-01"}, true},
		{"no compat date", Bundle{MainModule: "m.js", Modules: map[string]string{"m.js": "x"}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.b.Validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("err = %v, want ErrInvalidBundle", err)
			}
		})
	}
}

func TestComputeDigestDeterministicAndOrderInsensitive(t *testing.T) {
	a := &Bundle{MainModule: "m.js", Modules: map[string]string{"m.js": "A", "b.js": "B"}, CompatibilityDate: "2026-01-01"}
	b := &Bundle{MainModule: "m.js", Modules: map[string]string{"b.js": "B", "m.js": "A"}, CompatibilityDate: "2026-01-01"}
	da, err := a.ComputeDigest()
	if err != nil {
		t.Fatal(err)
	}
	db, _ := b.ComputeDigest()
	if da != db {
		t.Fatalf("digest not order-insensitive: %s != %s", da, db)
	}
	if len(da) != 64 {
		t.Fatalf("digest %q not 64 hex chars", da)
	}
	// A content change must change the digest.
	c := &Bundle{MainModule: "m.js", Modules: map[string]string{"m.js": "A2", "b.js": "B"}, CompatibilityDate: "2026-01-01"}
	dc, _ := c.ComputeDigest()
	if dc == da {
		t.Fatal("digest unchanged after source edit")
	}
}

func TestBuildFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "worker.js")
	if err := os.WriteFile(path, []byte(sampleWorker), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := BuildFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if b.MainModule != "worker.js" || b.Modules["worker.js"] != sampleWorker {
		t.Fatalf("bundle = %+v", b)
	}
	if b.Digest == "" {
		t.Fatal("digest not computed")
	}

	if _, err := BuildFromFile(filepath.Join(dir, "nope.js")); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("missing file err = %v, want ErrBundleNotFound", err)
	}
	bad := filepath.Join(dir, "x.txt")
	_ = os.WriteFile(bad, []byte("x"), 0o644)
	if _, err := BuildFromFile(bad); !errors.Is(err, ErrUnsupportedRef) {
		t.Fatalf(".txt err = %v, want ErrUnsupportedRef", err)
	}
}

func TestStorePutGetIdempotentAndNamed(t *testing.T) {
	s, err := NewStore(StoreConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := BuildFromSource("main.js", sampleWorker, "")
	d1, err := s.Put("acme", "hook", b)
	if err != nil {
		t.Fatal(err)
	}
	// Idempotent: same bundle → same digest, no error.
	d2, err := s.Put("acme", "hook", b)
	if err != nil || d1 != d2 {
		t.Fatalf("re-put digest %s != %s (err=%v)", d1, d2, err)
	}
	got, err := s.GetByDigest(d1)
	if err != nil || got.Modules["main.js"] != sampleWorker {
		t.Fatalf("GetByDigest = %+v err=%v", got, err)
	}
	byName, err := s.GetByName("acme", "hook")
	if err != nil || byName.Digest != d1 {
		t.Fatalf("GetByName = %+v err=%v", byName, err)
	}
	// Name is tenant-scoped: another tenant's identical name misses.
	if _, err := s.GetByName("other", "hook"); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("cross-tenant name err = %v, want ErrBundleNotFound", err)
	}
}

func TestGCUnreferencedKeepsNamedAndPinned(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(StoreConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := BuildFromSource("a.js", "export default {async fetch(){return new Response('a')}}", "")
	b, _ := BuildFromSource("b.js", "export default {async fetch(){return new Response('b')}}", "")
	c, _ := BuildFromSource("c.js", "export default {async fetch(){return new Response('c')}}", "")
	da, err := s.Put("t1", "", a) // unreferenced, unnamed → GC
	if err != nil {
		t.Fatal(err)
	}
	db, err := s.Put("t1", "named", b) // named → keep
	if err != nil {
		t.Fatal(err)
	}
	dc, err := s.Put("t1", "", c) // pinned → keep
	if err != nil {
		t.Fatal(err)
	}
	removed, err := s.GCUnreferenced(map[string]struct{}{dc: {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != da {
		t.Fatalf("removed = %v, want [%s]", removed, da)
	}
	if _, err := s.GetByDigest(db); err != nil {
		t.Fatalf("named digest was GC'd: %v", err)
	}
	if _, err := s.GetByDigest(dc); err != nil {
		t.Fatalf("pinned digest was GC'd: %v", err)
	}
	if _, err := s.GetByDigest(da); err == nil {
		t.Fatal("unreferenced unnamed digest still present")
	}
}

func TestStoreSizeCapAndQuota(t *testing.T) {
	s, err := NewStore(StoreConfig{Dir: t.TempDir(), MaxBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	big, _ := BuildFromSource("main.js", strings.Repeat("x", 50), "")
	if _, err := s.Put("acme", "", big); !errors.Is(err, ErrBundleTooLarge) {
		t.Fatalf("size cap err = %v, want ErrBundleTooLarge", err)
	}

	q, err := NewStore(StoreConfig{Dir: t.TempDir(), PerTenantMax: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i, src := range []string{"const a=1;", "const b=2;", "const c=3;"} {
		b, _ := BuildFromSource("main.js", "export default{};//"+src, "")
		_, err := q.Put("acme", "", b)
		if i < 2 && err != nil {
			t.Fatalf("put %d unexpected err %v", i, err)
		}
		if i == 2 && !errors.Is(err, ErrTenantQuotaExceeded) {
			t.Fatalf("put %d err = %v, want ErrTenantQuotaExceeded", i, err)
		}
	}
	// Null tenant is exempt from the quota.
	for i := range 5 {
		b, _ := BuildFromSource("main.js", "export default{};//op"+string(rune('a'+i)), "")
		if _, err := q.Put("", "", b); err != nil {
			t.Fatalf("null-tenant put %d err %v", i, err)
		}
	}
}

func TestStoreReloadIndex(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(StoreConfig{Dir: dir})
	b, _ := BuildFromSource("main.js", sampleWorker, "")
	d, _ := s.Put("acme", "hook", b)

	// Reopen: the name pointer must survive.
	s2, err := NewStore(StoreConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.GetByName("acme", "hook")
	if err != nil || got.Digest != d {
		t.Fatalf("reloaded GetByName = %+v err=%v", got, err)
	}
}

func TestStoreDelete(t *testing.T) {
	s, _ := NewStore(StoreConfig{Dir: t.TempDir()})
	b, _ := BuildFromSource("main.js", sampleWorker, "")
	d, _ := s.Put("acme", "hook", b)
	if err := s.Delete("acme", d); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetByDigest(d); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("post-delete GetByDigest err = %v, want ErrBundleNotFound", err)
	}
	if _, err := s.GetByName("acme", "hook"); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("post-delete name still resolves: %v", err)
	}
	// Deleting again is now ErrBundleNotFound (the tenant no longer owns it),
	// which the API maps to 404 — matching /v1/wasm-modules.
	if err := s.Delete("acme", d); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("re-delete err = %v, want ErrBundleNotFound", err)
	}
}

// TestStoreDeleteRefcountedAcrossTenants proves a tenant deleting bytes it
// shares with another tenant (same content digest) does not evict the other
// tenant's bundle — the blob is removed only when no tenant owns it.
func TestStoreDeleteRefcountedAcrossTenants(t *testing.T) {
	s, _ := NewStore(StoreConfig{Dir: t.TempDir()})
	b, _ := BuildFromSource("main.js", sampleWorker, "")
	d, _ := s.Put("acme", "hook", b)
	if _, err := s.Put("other", "mine", b); err != nil { // same bytes → same digest
		t.Fatal(err)
	}
	// acme deletes: the shared blob must survive because other still owns it.
	if err := s.Delete("acme", d); err != nil {
		t.Fatal(err)
	}
	if s.TenantOwns("acme", d) {
		t.Fatal("acme should no longer own the digest")
	}
	if got, err := s.GetByName("other", "mine"); err != nil || got.Digest != d {
		t.Fatalf("other's bundle evicted by acme's delete: %+v err=%v", got, err)
	}
	// A tenant that never owned the digest gets 404, not a silent success.
	if err := s.Delete("stranger", d); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("stranger delete = %v, want ErrBundleNotFound", err)
	}
	// other deletes last owner → blob is gone.
	if err := s.Delete("other", d); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetByDigest(d); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("blob should be gone after last owner deletes: %v", err)
	}
}

func TestResolver(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(StoreConfig{Dir: dir})
	b, _ := BuildFromSource("main.js", sampleWorker, "")
	digest, _ := store.Put("acme", "hook", b)
	r := NewResolver(store)
	ctx := context.Background()

	// By digest (both forms).
	for _, ref := range []string{digest, "sha256:" + digest} {
		got, err := r.Resolve(ctx, "acme", ref)
		if err != nil || got.Digest != digest {
			t.Fatalf("resolve %q = %+v err=%v", ref, got, err)
		}
	}
	// By uploaded name, tenant-scoped.
	got, err := r.Resolve(ctx, "acme", "hook")
	if err != nil || got.Digest != digest {
		t.Fatalf("resolve name = %+v err=%v", got, err)
	}
	if _, err := r.Resolve(ctx, "stranger", "hook"); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("cross-tenant resolve err = %v", err)
	}
	// By file path.
	path := filepath.Join(dir, "w.js")
	_ = os.WriteFile(path, []byte(sampleWorker), 0o644)
	for _, ref := range []string{path, "file://" + path} {
		got, err := r.Resolve(ctx, "acme", ref)
		if err != nil || got.Modules["w.js"] != sampleWorker {
			t.Fatalf("resolve file %q = %+v err=%v", ref, got, err)
		}
	}
	// Empty ref.
	if _, err := r.Resolve(ctx, "acme", "  "); !errors.Is(err, ErrUnsupportedRef) {
		t.Fatalf("empty ref err = %v, want ErrUnsupportedRef", err)
	}
}

func TestStoreListAndOwnership(t *testing.T) {
	s, _ := NewStore(StoreConfig{Dir: t.TempDir()})
	a, _ := BuildFromSource("main.js", "export default{};//a", "")
	b, _ := BuildFromSource("main.js", "export default{};//b", "")
	da, _ := s.Put("acme", "one", a)
	db, _ := s.Put("acme", "two", b)
	_, _ = s.Put("other", "x", a) // other tenant owns the same digest da

	got := s.ListDigests("acme")
	if len(got) != 2 {
		t.Fatalf("acme owns %d digests, want 2", len(got))
	}
	if !s.TenantOwns("acme", da) || !s.TenantOwns("acme", db) {
		t.Fatal("acme should own both digests")
	}
	if s.TenantOwns("acme", "deadbeef") {
		t.Fatal("acme should not own an unknown digest")
	}
	// A digest one tenant never stored is not theirs.
	if s.TenantOwns("stranger", da) {
		t.Fatal("stranger owns nothing")
	}
	names := s.NamesForTenant("acme")
	if names["one"] != da || names["two"] != db || len(names) != 2 {
		t.Fatalf("acme names = %+v", names)
	}
	// Names are tenant-scoped: other's "x" must not leak into acme's view.
	if _, ok := names["x"]; ok {
		t.Fatal("cross-tenant name leaked into acme's NamesForTenant")
	}
}

func TestResolverNilStore(t *testing.T) {
	r := NewResolver(nil)
	ctx := context.Background()
	// Digest and name refs need a store.
	if _, err := r.Resolve(ctx, "", strings.Repeat("a", 64)); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("digest w/o store err = %v", err)
	}
	if _, err := r.Resolve(ctx, "", "somename"); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("name w/o store err = %v", err)
	}
	// File refs still work with no store.
	dir := t.TempDir()
	path := filepath.Join(dir, "w.js")
	_ = os.WriteFile(path, []byte(sampleWorker), 0o644)
	if got, err := r.Resolve(ctx, "", path); err != nil || got == nil {
		t.Fatalf("file resolve w/o store err = %v", err)
	}
}
