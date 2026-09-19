package jsbundle

import "testing"

// The replicated artifact catalogue publishes a node's WHOLE inventory of a
// kind, so it enumerates tenants rather than being asked per tenant: a tenant
// this node holds nothing for is an answer the catalogue must be able to give.
func TestStoreTenantsEnumeratesOwnersWithBundles(t *testing.T) {
	st, err := NewStore(StoreConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Tenants(); len(got) != 0 {
		t.Fatalf("empty store reported tenants %v", got)
	}

	for _, tenant := range []string{"tenant-b", "tenant-a"} {
		if _, err := st.Put(tenant, "hook", &Bundle{MainModule: "index.js", Modules: map[string]string{"index.js": "export default {}"}, CompatibilityDate: "2026-01-01"}); err != nil {
			t.Fatalf("put for %s: %v", tenant, err)
		}
	}
	got := st.Tenants()
	if len(got) != 2 || got[0] != "tenant-a" || got[1] != "tenant-b" {
		t.Fatalf("tenants = %v, want both owners in a stable order", got)
	}

	// A tenant whose last bundle is deleted drops out rather than lingering
	// as an empty entry.
	digests := st.ListDigests("tenant-a")
	if len(digests) != 1 {
		t.Fatalf("tenant-a digests = %v", digests)
	}
	if err := st.Delete("tenant-a", digests[0]); err != nil {
		t.Fatal(err)
	}
	if got := st.Tenants(); len(got) != 1 || got[0] != "tenant-b" {
		t.Fatalf("tenants after delete = %v", got)
	}
}
