package wasm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// retargetingResolver simulates an alias/tag that MOVED after a sandbox was
// created: Resolve() now hands back a different digest (and file) for the same
// ref, while ResolveByDigest() still serves the original frozen bytes by their
// pinned digest. This is the exact codex C2 condition — a restart/rehydrate
// must boot the bytes pinned at create, never the moved-to bytes. Leave frozen
// nil to model "frozen copy evicted", which must turn the swap into a loud
// ErrModuleDigestMismatch instead of a silent code-swap.
type retargetingResolver struct {
	movedPath   string
	movedDigest string
	frozen      map[string]*wasmmod.ResolvedModule // pinnedDigest -> original module
}

func (r *retargetingResolver) Resolve(_ context.Context, ref string) (*wasmmod.ResolvedModule, error) {
	return &wasmmod.ResolvedModule{Ref: ref, Path: r.movedPath, Digest: r.movedDigest, SizeBytes: 1}, nil
}

func (r *retargetingResolver) ResolveByDigest(digest string) (*wasmmod.ResolvedModule, bool) {
	m, ok := r.frozen[digest]
	return m, ok
}

// newDigestPinDriver builds a driver wired to an in-process worker so the boot
// path runs end-to-end (LoadModule + Instantiate), not just the resolver seam.
func newDigestPinDriver(t *testing.T) (*Driver, string) {
	t.Helper()
	dir := t.TempDir()
	// macOS sun_path is capped at 104 bytes — keep worker sockets under /tmp.
	runDir := filepath.Join(os.TempDir(), "aw-pin")
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	modulesDir := filepath.Join(dir, "modules")
	if err := os.MkdirAll(modulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})
	d := New(Config{RunDir: runDir, ModulesDir: modulesDir, DefaultMemoryMB: 64}, nil)
	d.SetWorkerSupervisor(sup)
	return d, modulesDir
}

// TestStartSandboxBootsPinnedDigestAfterAliasMove is the codex C2 success-branch
// regression: the alias "py" pointed at digest X at create, then moved to Y. A
// restart must boot X's original bytes (served from the frozen copy), never Y.
// This is the assertion the existing internal-only resolvePinned test cannot
// make — it exercises the public StartSandbox entry point and proves which bytes
// actually boot.
func TestStartSandboxBootsPinnedDigestAfterAliasMove(t *testing.T) {
	d, modulesDir := newDigestPinDriver(t)
	origPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "orig.wasm")
	movedPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "moved.wasm")

	d.SetModuleResolver(&retargetingResolver{
		movedPath:   movedPath,
		movedDigest: "digest-Y-moved",
		frozen: map[string]*wasmmod.ResolvedModule{
			"digest-X-pinned": {Ref: "py", Path: origPath, Digest: "digest-X-pinned", SizeBytes: 1},
		},
	})

	sandbox := &models.Sandbox{
		ID:           "pin-start",
		ModuleRef:    "py",
		ModuleDigest: "digest-X-pinned",
		Durability:   models.DurabilityPassivatable,
		MemoryMB:     64,
	}
	if _, err := d.StartSandbox(context.Background(), sandbox, nil); err != nil {
		t.Fatalf("StartSandbox: %v", err)
	}

	inst, err := d.instance(sandbox.ID)
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	if inst.moduleDigest != "digest-X-pinned" {
		t.Fatalf("booted digest = %q, want pinned digest-X-pinned (alias move leaked through)", inst.moduleDigest)
	}
	if inst.modulePath != origPath {
		t.Fatalf("booted path = %q, want original %q (booted the moved-to bytes — silent code-swap)", inst.modulePath, origPath)
	}
}

// TestStartSandboxFailsLoudOnDigestDriftNoFrozenCopy is the codex C2 failure
// branch through the public entry point: alias moved AND the frozen copy is
// gone, so re-resolution drifts from the pin. The boot must fail loudly with
// ErrModuleDigestMismatch rather than silently boot the moved-to bytes.
func TestStartSandboxFailsLoudOnDigestDriftNoFrozenCopy(t *testing.T) {
	d, modulesDir := newDigestPinDriver(t)
	movedPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "moved.wasm")

	d.SetModuleResolver(&retargetingResolver{
		movedPath:   movedPath,
		movedDigest: "digest-Y-moved",
		frozen:      nil, // frozen copy evicted: nothing to fall back to
	})

	sandbox := &models.Sandbox{
		ID:           "pin-drift",
		ModuleRef:    "py",
		ModuleDigest: "digest-X-pinned",
		Durability:   models.DurabilityPassivatable,
		MemoryMB:     64,
	}
	_, err := d.StartSandbox(context.Background(), sandbox, nil)
	if err == nil || !errors.Is(err, wasmmod.ErrModuleDigestMismatch) {
		t.Fatalf("StartSandbox err = %v, want ErrModuleDigestMismatch", err)
	}
	if _, instErr := d.instance(sandbox.ID); instErr == nil {
		t.Fatal("expected no live instance after a loud digest-drift failure")
	}
}

// TestRehydrateBootsPinnedDigestAfterAliasMove proves the same C2 guarantee on
// the passivate→rehydrate path (the failover-adjacent one): create+checkpoint
// at digest X, move the alias to Y, then rehydrate. The frozen copy of X must
// win so the restored sandbox keeps running its original bytes.
func TestRehydrateBootsPinnedDigestAfterAliasMove(t *testing.T) {
	d, modulesDir := newDigestPinDriver(t)
	origPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "orig.wasm")
	movedPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "moved.wasm")

	ctx := context.Background()

	// Create + checkpoint while the alias still resolves to the original bytes.
	d.SetModuleResolver(fakeResolver{path: origPath, digest: "digest-X-pinned"})
	if _, err := d.Create(ctx, models.CreateSandboxRequest{
		Image:      "py",
		Durability: models.DurabilityPassivatable,
		MemoryMB:   64,
	}, "pin-rehydrate", "", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	sb := &models.Sandbox{
		ID:           "pin-rehydrate",
		ModuleRef:    "py",
		ModuleDigest: "digest-X-pinned",
		Durability:   models.DurabilityPassivatable,
		MemoryMB:     64,
	}
	path, gen, err := d.CheckpointSandbox(ctx, sb)
	if err != nil {
		t.Fatalf("CheckpointSandbox: %v", err)
	}

	// Now the alias moves: Resolve() drifts to Y, but the frozen copy of X
	// is still available content-addressed.
	d.SetModuleResolver(&retargetingResolver{
		movedPath:   movedPath,
		movedDigest: "digest-Y-moved",
		frozen: map[string]*wasmmod.ResolvedModule{
			"digest-X-pinned": {Ref: "py", Path: origPath, Digest: "digest-X-pinned", SizeBytes: 1},
		},
	})

	sb.Status = models.SandboxStatusPassivated
	sb.CheckpointPath = path
	sb.CloneGeneration = gen
	if _, err := d.RehydrateSandbox(ctx, sb, nil); err != nil {
		t.Fatalf("RehydrateSandbox: %v", err)
	}

	inst, err := d.instance(sb.ID)
	if err != nil {
		t.Fatalf("instance: %v", err)
	}
	if inst.moduleDigest != "digest-X-pinned" || inst.modulePath != origPath {
		t.Fatalf("rehydrated digest=%q path=%q, want pinned digest-X-pinned/%q (alias move leaked through)",
			inst.moduleDigest, inst.modulePath, origPath)
	}
}
