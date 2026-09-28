package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// manifestRegistry is a fake OCI registry with the properties that make
// checkpoint lifecycles dangerous:
//
//   - deleting a ref RESOLVES its tag and deletes the MANIFEST, removing every
//     tag that points at it — what wasmmod.DeleteSnapshotRef does;
//   - a manifest is identified by what was pushed (the snapshot and the
//     lifetime it is bound to), so the two tag writes of one push land on one
//     manifest, as they did when manifests carried only a whole-second stamp;
//   - a pull refuses a manifest another lifetime published, as
//     wasmmod.PullSnapshotArtifact does.
//
// A fake that deleted only the named tag, or gave every write its own
// manifest, would hide exactly the failures these tests exist for.
type manifestRegistry struct {
	mu         sync.Mutex
	tags       map[string]string // ref -> manifest
	manifests  map[string]registryManifest
	nextDigest string
	deleted    []string
	pushCalls  int
	// failPushCall makes the Nth PushOnceTo fail (1-based), e.g. a push's
	// digest-tag write.
	failPushCall int
	// beforeDelete runs inside DeleteRef before the tag is resolved, without
	// the lock held, so a test can pause a delete that already passed its
	// in-use check.
	beforeDelete func(ref string)
	// skipLifetimeCheck disables the pull's lifetime verification.
	skipLifetimeCheck bool
}

type registryManifest struct {
	incarnation string
	snapshotDir string
	digest      string
}

func newManifestRegistry() *manifestRegistry {
	return &manifestRegistry{tags: map[string]string{}, manifests: map[string]registryManifest{}}
}

func (r *manifestRegistry) DestRefTagged(sandboxID, tag string) string {
	return "reg/" + sandboxID + ":" + tag
}

func (r *manifestRegistry) PushOnceTo(_ context.Context, _, incarnationID, memSnapDir, dest string) (WasmCheckpointPushResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pushCalls++
	if r.failPushCall != 0 && r.pushCalls == r.failPushCall {
		return WasmCheckpointPushResult{}, errors.New("registry refused the write")
	}
	key := incarnationID + "\x00" + memSnapDir
	m, ok := r.manifests[key]
	if !ok {
		digest := r.nextDigest
		if digest == "" {
			digest = fmt.Sprintf("sha256:%064x", len(r.manifests)+1)
		}
		m = registryManifest{incarnation: incarnationID, snapshotDir: memSnapDir, digest: digest}
		r.manifests[key] = m
	}
	r.tags[dest] = key
	return WasmCheckpointPushResult{RegistryRef: dest, Digest: m.digest}, nil
}

func (r *manifestRegistry) PullOnce(_ context.Context, ref, incarnationID, dstDir string) error {
	r.mu.Lock()
	key, ok := r.tags[ref]
	m := r.manifests[key]
	skip := r.skipLifetimeCheck
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("pull %s: not found", ref)
	}
	if !skip && m.incarnation != "" && m.incarnation != incarnationID {
		return fmt.Errorf("%w: %s", wasmmod.ErrCheckpointLifetimeMismatch, ref)
	}
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}
	return copyWasmSnapshotDir(m.snapshotDir, dstDir)
}

func (r *manifestRegistry) DeleteRef(_ context.Context, ref string) error {
	if r.beforeDelete != nil {
		r.beforeDelete(ref)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key, ok := r.tags[ref]
	if !ok {
		return nil
	}
	for tag, k := range r.tags {
		if k == key {
			delete(r.tags, tag)
		}
	}
	delete(r.manifests, key)
	r.deleted = append(r.deleted, ref)
	return nil
}

// owner reports which lifetime's manifest ref resolves to, if it resolves.
func (r *manifestRegistry) owner(ref string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key, ok := r.tags[ref]
	if !ok {
		return "", false
	}
	return r.manifests[key].incarnation, true
}

func (r *manifestRegistry) resolves(ref string) bool {
	_, ok := r.owner(ref)
	return ok
}

func (r *manifestRegistry) setDigest(d string) {
	r.mu.Lock()
	r.nextDigest = d
	r.mu.Unlock()
}

// A checkpoint push is detached from its request with a multi-minute budget,
// so pushes from a sandbox's PREVIOUS incarnation can land after the id was
// destroyed and re-created. The metadata write is fenced by incarnation, but
// retention and the orphan sweep were not: late old pushes consumed the live
// incarnation's keep-last-N budget, and retention deleted the replacement's
// valid checkpoint while its row still pointed at it. Recovery then pulls a
// manifest that no longer exists.
func TestLateOldIncarnationPushesCannotDeleteTheLiveCheckpoint(t *testing.T) {
	for _, tc := range []struct {
		name     string
		keep     int
		latePush int
	}{
		{name: "keep-last-1, one late push", keep: 1, latePush: 1},
		{name: "keep-last-3 (default), three late pushes", keep: 3, latePush: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
			reg := newManifestRegistry()
			svc.wasmCheckpointPusher = reg
			svc.cfg.WasmCheckpointKeepLastN = tc.keep

			sb := &models.Sandbox{
				ID: "sb-reborn", Runtime: models.RuntimeWasm, Image: "wasm:test",
				Status: models.SandboxStatusPassivated, AuditIncarnationID: "inc-new",
			}
			if err := st.Create(ctx, sb); err != nil {
				t.Fatal(err)
			}

			// The replacement incarnation checkpoints.
			reg.setDigest("sha256:live")
			svc.pushWasmCheckpointBestEffort(sb.ID, "inc-new", t.TempDir())
			live, err := st.Get(ctx, sb.ID)
			if err != nil {
				t.Fatal(err)
			}
			liveRef := live.WasmRegistryRef
			if liveRef == "" || !reg.resolves(liveRef) {
				t.Fatalf("setup: the live push did not record a resolvable ref (%q)", liveRef)
			}

			// Pushes from the destroyed incarnation finish afterwards.
			for i := range tc.latePush {
				reg.setDigest("sha256:old-" + string(rune('a'+i)))
				svc.pushWasmCheckpointBestEffort(sb.ID, "inc-old", t.TempDir())
			}

			live, err = st.Get(ctx, sb.ID)
			if err != nil {
				t.Fatal(err)
			}
			if live.WasmRegistryRef != liveRef {
				t.Fatalf("an old push rewrote the live ref to %q", live.WasmRegistryRef)
			}
			if !reg.resolves(liveRef) {
				t.Fatalf("the live checkpoint %q was deleted by retention for a dead incarnation (deleted refs: %v); the row still points at it, so recovery cannot pull it",
					liveRef, reg.deleted)
			}

			// The rejected pushes are a cleanup obligation, not a leak: the
			// orphan sweep must find them even though a sandbox with this id
			// is alive, and reclaim them without touching the live manifest.
			svc.runWasmOrphanRefSweep(ctx)
			if !reg.resolves(liveRef) {
				t.Fatalf("the orphan sweep deleted the live checkpoint %q", liveRef)
			}
			for i := range tc.latePush {
				stale := reg.DestRefTagged(sb.ID, wasmmod.WasmCheckpointLifetimeDigestTag("inc-old", "sha256:old-"+string(rune('a'+i))))
				if reg.resolves(stale) {
					t.Fatalf("the dead incarnation's checkpoint %q was never reclaimed: the orphan sweep only looks for sandbox ids that no longer exist", stale)
				}
			}
			recs, err := st.ListWasmCheckpointPushes(ctx, sb.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, rec := range recs {
				if strings.Contains(rec.Digest, "old-") {
					t.Fatalf("a reclaimed dead-incarnation row survived: %+v", rec)
				}
			}
		})
	}
}

// snapshotAt writes a real mem.snap directory whose clone generation names the
// lifetime that produced it, so a restore can be checked for WHICH checkpoint
// it brought back.
func snapshotAt(t *testing.T, generation string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "mem.snap")
	seedWasmSnapshot(t, dir, generation)
	return dir
}

func newCheckpointService(t *testing.T, reg *manifestRegistry) (*Service, *store.Store, *fakeWasmRecreateRuntime) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rt := &fakeWasmRecreateRuntime{}
	svc := New(config.Config{EnableWasm: true, WasmModulesDir: t.TempDir(), WasmCheckpointKeepLastN: 3}, slog.New(slog.NewTextHandler(io.Discard, nil)), st, rt, nil, nil, nil, nil, nil)
	svc.SetWasmRuntime(rt)
	svc.wasmCheckpointPusher = reg
	return svc, st, rt
}

func seedLifetime(t *testing.T, st *store.Store, id, incarnation string) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: id, Runtime: models.RuntimeWasm, Durability: models.DurabilityDurable,
		ModuleRef: "file:///tmp/demo.wasm", Status: models.SandboxStatusPassivated,
		AuditIncarnationID: incarnation, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

// A failover owner has no local row, so no recorded ref. It used to fall back to
// the id-wide :latest, which every lifetime's pushes wrote — and the metadata
// fence that rejected a destroyed lifetime's late push ran only AFTER that
// push had re-pointed the tag. The new owner restored the dead lifetime's
// snapshot and adopted its clone generation as current.
func TestFailoverRestoresTheCurrentLifetimeNotALateOldPush(t *testing.T) {
	ctx := context.Background()
	reg := newManifestRegistry()
	owner, ownerStore, _ := newCheckpointService(t, reg)
	seedLifetime(t, ownerStore, "sb-fo", "inc-new")

	owner.pushWasmCheckpointBestEffort("sb-fo", "inc-new", snapshotAt(t, "generation-new"))
	// The destroyed lifetime's detached push lands afterwards; every registry
	// write succeeds.
	owner.pushWasmCheckpointBestEffort("sb-fo", "inc-old", snapshotAt(t, "generation-old"))

	// A different node takes over with an empty store.
	survivor, survivorStore, rt := newCheckpointService(t, reg)
	if _, err := survivor.recreateWasmDurableSandbox(ctx, "sb-fo", "inc-new", models.CreateSandboxRequest{
		Runtime: models.RuntimeWasm, Durability: models.DurabilityDurable, ModuleRef: "file:///tmp/demo.wasm",
	}, nil); err != nil {
		t.Fatalf("failover recreate: %v", err)
	}
	restored, err := survivorStore.Get(ctx, "sb-fo")
	if err != nil {
		t.Fatal(err)
	}
	if restored.CloneGeneration != "generation-new" {
		t.Fatalf("failover restored clone generation %q, want %q: the new owner brought back a destroyed lifetime's memory",
			restored.CloneGeneration, "generation-new")
	}
	if restored.AuditIncarnationID != "inc-new" {
		t.Fatalf("restored lifetime = %q", restored.AuditIncarnationID)
	}
	if len(rt.rehydrated) != 1 {
		t.Fatalf("rehydrated %v", rt.rehydrated)
	}

	// With no lifetime to bind to there is nothing safe to restore.
	if _, err := survivor.recreateWasmDurableSandbox(ctx, "sb-unbound", "", models.CreateSandboxRequest{
		Runtime: models.RuntimeWasm, Durability: models.DurabilityDurable, ModuleRef: "file:///tmp/demo.wasm",
	}, nil); err == nil {
		t.Fatal("a recreate with no lifetime restored a checkpoint anyway")
	}
}

// Without failover: the live lifetime's digest-tag write fails, so its row
// falls back to the rolling pointer. A late push from the destroyed lifetime
// must neither re-point what that ref resolves to nor — when orphan GC reclaims
// the dead lifetime's manifest — take the live alias down with it.
func TestLiveRollingRefSurvivesALateOldPushAndOrphanGC(t *testing.T) {
	ctx := context.Background()
	reg := newManifestRegistry()
	svc, st, _ := newCheckpointService(t, reg)
	seedLifetime(t, st, "sb-roll", "inc-new")

	reg.failPushCall = 2 // the live push's digest-tag write
	svc.pushWasmCheckpointBestEffort("sb-roll", "inc-new", snapshotAt(t, "generation-new"))
	live, err := st.Get(ctx, "sb-roll")
	if err != nil {
		t.Fatal(err)
	}
	liveRef := live.WasmRegistryRef
	if liveRef == "" {
		t.Fatal("setup: the live push recorded no ref")
	}

	svc.pushWasmCheckpointBestEffort("sb-roll", "inc-old", snapshotAt(t, "generation-old"))
	if owner, ok := reg.owner(liveRef); !ok || owner != "inc-new" {
		t.Fatalf("after a late old push the live ref %q resolves to lifetime %q (ok=%v): recovery would restore the wrong checkpoint", liveRef, owner, ok)
	}

	svc.runWasmOrphanRefSweep(ctx)
	if owner, ok := reg.owner(liveRef); !ok || owner != "inc-new" {
		t.Fatalf("orphan GC of the dead lifetime left the live ref %q resolving to %q (ok=%v; deleted %v): the recovery reference is gone",
			liveRef, owner, ok, reg.deleted)
	}
}

// The in-use check is a point-in-time read, and nothing holds it true through
// the external delete. If a delete of a dead lifetime's rolling pointer is
// still in flight when the id is re-created and a new checkpoint published,
// resolving that pointer must not land on the new lifetime's manifest. With
// lifetime-scoped tags nothing the new lifetime writes can be reached through
// the dead lifetime's name, so no coordination is needed at all.
func TestOrphanDeleteRacingARecreateCannotRemoveTheNewCheckpoint(t *testing.T) {
	ctx := context.Background()
	reg := newManifestRegistry()
	svc, st, _ := newCheckpointService(t, reg)

	// A lifetime publishes (its digest-tag write fails, so its history row
	// tracks the rolling pointer) and is destroyed.
	seedLifetime(t, st, "sb-race", "inc-old")
	reg.failPushCall = 2
	svc.pushWasmCheckpointBestEffort("sb-race", "inc-old", snapshotAt(t, "generation-old"))
	if err := st.Delete(ctx, "sb-race"); err != nil {
		t.Fatal(err)
	}
	reg.failPushCall = 0

	// Orphan GC checks the row (no sandbox: not in use) and starts deleting,
	// then stalls before the registry resolves the tag.
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	reg.beforeDelete = func(string) {
		once.Do(func() {
			close(entered)
			<-release
		})
	}
	swept := make(chan struct{})
	go func() {
		defer close(swept)
		svc.runWasmOrphanRefSweep(ctx)
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the orphan sweep never reached the registry delete")
	}

	// Meanwhile the id is re-created and publishes a distinct checkpoint.
	seedLifetime(t, st, "sb-race", "inc-new")
	svc.pushWasmCheckpointBestEffort("sb-race", "inc-new", snapshotAt(t, "generation-new"))
	close(release)
	<-swept

	live, err := st.Get(ctx, "sb-race")
	if err != nil {
		t.Fatal(err)
	}
	if owner, ok := reg.owner(live.WasmRegistryRef); !ok || owner != "inc-new" {
		t.Fatalf("the stalled orphan delete removed the new lifetime's checkpoint %q (owner=%q ok=%v, deleted %v); the live row points at nothing",
			live.WasmRegistryRef, owner, ok, reg.deleted)
	}
}
