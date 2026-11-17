package wasmmod

import (
	"context"
	"testing"
)

func TestHostPathRef(t *testing.T) {
	r := NewModuleResolver(t.TempDir(), "")
	r.Reserved["python"] = "python.wasm"
	r.CatalogueLookup = func(ctx context.Context, id string) (string, string, bool) {
		owner, _ := CatalogueOwner(ctx)
		return "/m/" + id, "d", owner == "team:a" && id == "wmod_1"
	}
	ctx := WithCatalogueOwner(context.Background(), "team:a")
	for ref, want := range map[string]bool{
		"":                    false,
		"python":              false,
		"PYTHON":              false,
		"oci://r.example/m:1": false,
		"wmod_1":              false,
		"staged.wasm":         true,
		"/etc/m.wasm":         true,
		"file:///opt/m.wasm":  true,
		"sub/python":          true,
		"wmod_2":              true,
	} {
		if got := r.HostPathRef(ctx, ref); got != want {
			t.Errorf("%q: %v, want %v", ref, got, want)
		}
	}
	// Another owner's catalogue entry is a bare name like any other.
	if !r.HostPathRef(WithCatalogueOwner(context.Background(), "team:b"), "wmod_1") {
		t.Error("another owner's catalogue id read as theirs")
	}
	r.CatalogueLookup = nil
	if !r.HostPathRef(ctx, "wmod_1") {
		t.Error("no catalogue: a bare name is a host file")
	}
}
