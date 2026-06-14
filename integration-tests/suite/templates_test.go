//go:build integration

package suite

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-46 — Build an image from a Dockerfile and get a usable tag back.
func TestBuildImageFromDockerfile(t *testing.T) {
	harness.Require(t, sc, "UC-46")
	c := client(t)
	img := microvm.BaseImage("alpine:3.20").
		RunCommands("echo built-by-aerol > /built.txt")
	if err := img.Err(); err != nil {
		t.Fatalf("build image spec: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tag, err := c.SDK().BuildImage(ctx, img)
	if err != nil {
		t.Fatalf("build image: %v", err)
	}
	if tag == "" {
		t.Fatal("build returned empty image tag")
	}
}

// UC-47/48/49/50 — Template lifecycle: create, list+get, rebuild, delete.
func TestTemplateLifecycle(t *testing.T) {
	// create gates the rest; declare the subtests' UCs so a firecracker-skip
	// marks them skipped (not missing) when the subtests never run.
	harness.Require(t, sc, "UC-47", "UC-48", "UC-49", "UC-50")
	c := client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	tmpl, err := c.SDK().CreateTemplate(ctx, sdktypes.CreateTemplateOptions{
		Image: "docker://alpine:3.20",
	})
	if err != nil {
		t.Fatalf("create template: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().DeleteTemplate(cctx, tmpl.ID)
	})

	// UC-48 — list includes it and get returns it.
	t.Run("UC-48-list-get", func(t *testing.T) {
		harness.Require(t, sc, "UC-48")
		list, err := c.SDK().ListTemplates(ctx)
		if err != nil {
			t.Fatalf("list templates: %v", err)
		}
		found := false
		for _, tl := range list {
			if tl.ID == tmpl.ID {
				found = true
			}
		}
		if !found {
			t.Fatalf("template %s not in list", tmpl.ID)
		}
		if _, err := c.SDK().GetTemplate(ctx, tmpl.ID); err != nil {
			t.Fatalf("get template: %v", err)
		}
	})

	// UC-49 — rebuild is accepted.
	t.Run("UC-49-rebuild", func(t *testing.T) {
		harness.Require(t, sc, "UC-49")
		if _, err := c.SDK().RebuildTemplate(ctx, tmpl.ID); err != nil {
			t.Fatalf("rebuild template: %v", err)
		}
	})

	// UC-50 — delete; a subsequent get fails.
	t.Run("UC-50-delete", func(t *testing.T) {
		harness.Require(t, sc, "UC-50")
		if err := c.SDK().DeleteTemplate(ctx, tmpl.ID); err != nil {
			t.Fatalf("delete template: %v", err)
		}
		if _, err := c.SDK().GetTemplate(ctx, tmpl.ID); err == nil {
			t.Fatal("get after delete returned no error")
		}
	})
}

// UC-51 — Register a WASM module, then list and get it back.
func TestWasmModuleRegisterListGet(t *testing.T) {
	harness.Require(t, sc, "UC-51")
	c := client(t)

	// Distinct from AEROL_WASM_MODULE_REF (a staged standard-module alias the
	// runtime UC uses): registering via the catalogue API needs a ref the node
	// can actually pull, inside wasm.registry_allowlist. Operator-supplied.
	ref := os.Getenv("AEROL_WASM_REGISTER_REF")
	if ref == "" {
		t.Skip("AEROL_WASM_REGISTER_REF not set (allowlisted oci ref to register)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	mod, err := c.SDK().CreateWasmModule(ctx, sdktypes.CreateWasmModuleOptions{
		ModuleRef: ref,
	})
	if err != nil {
		t.Fatalf("create wasm module: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().DeleteWasmModule(cctx, mod.ID)
	})

	list, err := c.SDK().ListWasmModules(ctx)
	if err != nil {
		t.Fatalf("list wasm modules: %v", err)
	}
	found := false
	for _, m := range list {
		if m.ID == mod.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("wasm module %s not in list", mod.ID)
	}
	if _, err := c.SDK().GetWasmModule(ctx, mod.ID); err != nil {
		t.Fatalf("get wasm module: %v", err)
	}
}

// UC-52 — Push a BYO .wasm to the registry and get back an oci ref.
func TestWasmModulePush(t *testing.T) {
	harness.Require(t, sc, "UC-52")
	c := client(t)

	wasmPath := os.Getenv("AEROL_WASM_FILE")
	user := os.Getenv("AEROL_WASM_REGISTRY_USER")
	token := os.Getenv("AEROL_WASM_REGISTRY_TOKEN")
	if wasmPath == "" || user == "" || token == "" {
		t.Skip("AEROL_WASM_FILE / AEROL_WASM_REGISTRY_USER / AEROL_WASM_REGISTRY_TOKEN not set")
	}
	body, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("read wasm file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	resp, err := c.SDK().PushWasmModule(ctx, sdktypes.PushWasmModuleOptions{
		Name:             "aerol-itest",
		Tag:              "latest",
		Module:           body,
		RegistryUsername: user,
		RegistryToken:    token,
	})
	if err != nil {
		t.Fatalf("push wasm module: %v", err)
	}
	if resp.ModuleRef == "" {
		t.Fatal("push returned empty module ref")
	}
}
