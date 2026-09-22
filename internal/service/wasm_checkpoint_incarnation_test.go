package service

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// manifestRegistry is a fake OCI registry with the one property that makes
// checkpoint retention dangerous: deleting a ref RESOLVES its tag and deletes
// the MANIFEST, which removes every tag pointing at that digest. That is what
// wasmmod.DeleteSnapshotRef does, and a fake that deleted only the named tag
// would hide exactly the failures below.
type manifestRegistry struct {
	mu         sync.Mutex
	tags       map[string]string // ref -> digest
	nextDigest string
	deleted    []string
}

func newManifestRegistry() *manifestRegistry {
	return &manifestRegistry{tags: map[string]string{}}
}

func (r *manifestRegistry) DestRefFor(id string) string { return r.DestRefTagged(id, "latest") }

func (r *manifestRegistry) DestRefTagged(sandboxID, tag string) string {
	return "reg/" + sandboxID + ":" + tag
}

func (r *manifestRegistry) PushOnceTo(_ context.Context, _, _, dest string) (WasmCheckpointPushResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tags[dest] = r.nextDigest
	return WasmCheckpointPushResult{RegistryRef: dest, Digest: r.nextDigest}, nil
}

func (r *manifestRegistry) PullOnce(context.Context, string, string) error { return nil }

func (r *manifestRegistry) DeleteRef(_ context.Context, ref string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	digest, ok := r.tags[ref]
	if !ok {
		return nil
	}
	for tag, d := range r.tags {
		if d == digest {
			delete(r.tags, tag)
		}
	}
	r.deleted = append(r.deleted, ref)
	return nil
}

func (r *manifestRegistry) resolves(ref string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.tags[ref]
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
				stale := reg.DestRefTagged(sb.ID, wasmmod.WasmCheckpointDigestTag("sha256:old-"+string(rune('a'+i))))
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
