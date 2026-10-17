package wasm

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// ownerRecordingResolver records the catalogue namespace pinned on each
// Resolve context, then fails so the boot stops right after resolution.
type ownerRecordingResolver struct {
	owners []string
	pinned []bool
}

var errStopAfterResolve = errors.New("stop after resolve")

func (r *ownerRecordingResolver) Resolve(ctx context.Context, _ string) (*wasmmod.ResolvedModule, error) {
	owner, ok := wasmmod.CatalogueOwner(ctx)
	r.owners = append(r.owners, owner)
	r.pinned = append(r.pinned, ok)
	return nil, errStopAfterResolve
}

// The resident-host bucket owner follows the owner the service pinned for the
// create, so a caller-less failover recreate of a tenant's sandbox lands in
// that tenant's bucket rather than the operator's shared one.
func TestOwnerRefFromCreateCtx(t *testing.T) {
	tenant := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Identity: controlplane.Identity{OwnerRef: " acct-a "}})
	operator := controlplane.ContextWithAccess(context.Background(), controlplane.Access{Operator: true, Identity: controlplane.Identity{OwnerRef: "ignored"}})
	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"no access", context.Background(), ""},
		{"tenant access", tenant, "acct-a"},
		{"operator access", operator, ""},
		{"pinned owner on caller-less recreate", wasmmod.WithCatalogueOwner(context.Background(), "acct-b"), "acct-b"},
		{"pinned operator namespace", wasmmod.WithCatalogueOwner(tenant, ""), ""},
	}
	for _, tc := range tests {
		if got := ownerRefFromCreateCtx(tc.ctx); got != tc.want {
			t.Errorf("%s: ownerRefFromCreateCtx = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Catalogue ids are per owner, so restarting or rehydrating a sandbox must
// resolve its module in the sandbox owner's namespace even when the call runs
// on an internal context with no caller identity (lifecycle wake, failover).
func TestBootExistingSandboxPinsCatalogueOwner(t *testing.T) {
	for _, owner := range []string{"acct-a", ""} {
		t.Run("start/"+owner, func(t *testing.T) {
			d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir(), DefaultMemoryMB: 64}, nil)
			d.SetWorkerSupervisor(&fakeSupervisor{})
			res := &ownerRecordingResolver{}
			d.SetModuleResolver(res)
			sb := &models.Sandbox{ID: "sb-start", ModuleRef: "catalogue-id", OwnerRef: owner}
			if _, err := d.StartSandbox(context.Background(), sb, nil); !errors.Is(err, errStopAfterResolve) {
				t.Fatalf("StartSandbox = %v, want the resolver's error", err)
			}
			if len(res.owners) != 1 || !res.pinned[0] || res.owners[0] != owner {
				t.Fatalf("resolve ctx owner = %v pinned %v, want [%q] pinned", res.owners, res.pinned, owner)
			}
		})
		t.Run("rehydrate/"+owner, func(t *testing.T) {
			d := New(Config{ModulesDir: t.TempDir(), RunDir: t.TempDir(), DefaultMemoryMB: 64}, nil)
			d.SetWorkerSupervisor(&fakeSupervisor{})
			res := &ownerRecordingResolver{}
			d.SetModuleResolver(res)
			checkpointDir := d.checkpointDir("sb-rehydrate")
			if err := os.MkdirAll(checkpointDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := wasmengine.WriteSnapshotDir(checkpointDir, wasmengine.SnapshotCapture{
				Config: wasmengine.SnapshotConfig{
					SchemaVersion:   1,
					Engine:          wasmengine.EngineNameWazero(),
					Entrypoint:      "_start",
					CloneGeneration: "gen",
				},
			}); err != nil {
				t.Fatalf("WriteSnapshotDir: %v", err)
			}
			sb := &models.Sandbox{
				ID: "sb-rehydrate", ModuleRef: "catalogue-id", OwnerRef: owner,
				CheckpointPath: checkpointDir, CloneGeneration: "gen",
			}
			if _, err := d.RehydrateSandbox(context.Background(), sb, nil); !errors.Is(err, errStopAfterResolve) {
				t.Fatalf("RehydrateSandbox = %v, want the resolver's error", err)
			}
			if len(res.owners) != 1 || !res.pinned[0] || res.owners[0] != owner {
				t.Fatalf("resolve ctx owner = %v pinned %v, want [%q] pinned", res.owners, res.pinned, owner)
			}
		})
	}
}
