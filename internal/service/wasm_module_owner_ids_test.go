package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// wasmOwnerIDsHarness is a WASM-enabled service whose resolver maps every ref
// to the same bytes (one digest), so two owners registering different refs
// still collide on the digest-derived default id.
func wasmOwnerIDsHarness(t *testing.T) (*Service, *store.Store, *recordingRuntime, string) {
	t.Helper()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	modPath := filepath.Join(t.TempDir(), "shared.wasm")
	if err := os.WriteFile(modPath, []byte("wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc.SetWasmModuleResolver(stubWasmModuleResolver{path: modPath, digest: "digest-shared"})
	rt := &recordingRuntime{}
	svc.SetWasmRuntime(rt)
	return svc, st, rt, modPath
}

// wasmModuleRefs maps each listed module_ref to its id, failing on a ref
// listed twice.
func wasmModuleRefs(t *testing.T, mods []*models.WasmModule) map[string]string {
	t.Helper()
	out := make(map[string]string, len(mods))
	for _, m := range mods {
		if prev, dup := out[m.ModuleRef]; dup {
			t.Fatalf("module_ref %q listed twice (ids %q and %q)", m.ModuleRef, prev, m.ID)
		}
		out[m.ModuleRef] = m.ID
	}
	return out
}

// T0b: a module's identity is (owner_ref, id). Two owners registering the
// same bytes with no explicit id each get their own digest-id row, with no
// conflict and no sign of the other's; each sees its own row plus the
// operator-published ("") rows; delete stays inside the caller's namespace and
// the shared bytes go only with the last row that pins them.
func TestWasmModuleCatalogue_PerOwnerIDs(t *testing.T) {
	svc, st, rt, modPath := wasmOwnerIDsHarness(t)
	ctx := context.Background()
	a, b := ownerScopedCtx("acct-A"), ownerScopedCtx("acct-B")
	refA, refB := "oci://registry.example/a/mod:v1", "oci://registry.example/b/mod:v1"

	modA, err := svc.CreateWasmModule(a, models.CreateWasmModuleRequest{ModuleRef: refA})
	if err != nil {
		t.Fatalf("A create: %v", err)
	}
	modB, err := svc.CreateWasmModule(b, models.CreateWasmModuleRequest{ModuleRef: refB})
	if err != nil {
		t.Fatalf("B create of identical bytes = %v, want its own row", err)
	}
	if modA.ID != "digest-shared" || modB.ID != modA.ID {
		t.Fatalf("ids = %q, %q; want both to default to the digest", modA.ID, modB.ID)
	}
	for owner, ref := range map[string]string{"acct-A": refA, "acct-B": refB} {
		rec, err := st.GetWasmModule(ctx, owner, modA.ID)
		if err != nil || rec.ModuleRef != ref || rec.OwnerRef != owner {
			t.Fatalf("store row (%s) = %+v, %v; want ref %s", owner, rec, err, ref)
		}
	}
	// A retry is idempotent: the caller's own row comes back.
	if again, err := svc.CreateWasmModule(a, models.CreateWasmModuleRequest{ModuleRef: refA}); err != nil || again.ModuleRef != refA {
		t.Fatalf("A retry = %+v, %v", again, err)
	}
	// An id bound to a different ref is still a conflict inside one namespace.
	if _, err := svc.CreateWasmModule(a, models.CreateWasmModuleRequest{ID: modA.ID, ModuleRef: "oci://registry.example/a/other:v1"}); !errors.Is(err, store.ErrWasmModuleIDConflict) {
		t.Fatalf("A same-id other-ref = %v, want ErrWasmModuleIDConflict", err)
	}

	now := time.Now().UTC()
	if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
		ID: "std-mod", ModuleRef: "std", Status: "ready", ModulePath: modPath,
		Digest: "std-digest", CreatedAt: now, UpdatedAt: now, ReadyAt: &now,
	}); err != nil {
		t.Fatal(err)
	}
	// B may take an id the operator published: it lands in B's namespace and
	// shadows the operator row for B only.
	if _, err := svc.CreateWasmModule(b, models.CreateWasmModuleRequest{ID: "std-mod", ModuleRef: refB}); err != nil {
		t.Fatalf("B explicit id equal to an operator id = %v, want own row", err)
	}

	listA, err := svc.ListWasmModules(a)
	if err != nil {
		t.Fatal(err)
	}
	if got := wasmModuleRefs(t, listA); len(got) != 2 || got[refA] != modA.ID || got["std"] != "std-mod" {
		t.Fatalf("A list = %v, want own row + operator row only", got)
	}
	listB, err := svc.ListWasmModules(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(listB) != 3 {
		t.Fatalf("B list has %d rows, want own two + operator one", len(listB))
	}
	for _, m := range listB {
		if m.ModuleRef == refA {
			t.Fatalf("B list leaked A's row: %+v", m)
		}
	}
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		id, ref string
	}{
		{"A digest id", a, modA.ID, refA},
		{"B digest id", b, modA.ID, refB},
		{"A operator id", a, "std-mod", "std"},
		{"B shadowed operator id", b, "std-mod", refB},
	} {
		got, err := svc.GetWasmModule(tc.ctx, tc.id)
		if err != nil || got.ModuleRef != tc.ref {
			t.Fatalf("%s: get = %+v, %v; want ref %s", tc.name, got, err, tc.ref)
		}
	}

	// B deletes its digest row: A's row survives. A tenant (acct-B) is not
	// host-capable, so its delete reclaims no host bytes at all — the module
	// file it only ever referenced is left for the operator to reap (issue
	// #537). RemoveImage therefore never fires on any tenant delete below.
	if err := svc.DeleteWasmModule(b, modA.ID); err != nil {
		t.Fatalf("B delete own: %v", err)
	}
	if len(rt.removeImages) != 0 {
		t.Fatalf("RemoveImage = %v; a tenant delete must not reclaim host bytes (#537)", rt.removeImages)
	}
	if _, _, ok := svc.ResolveOwnedWasmModule(a, modA.ID); !ok {
		t.Fatal("A's module stopped resolving after B's delete")
	}
	if err := svc.DeleteWasmModule(b, modA.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("B delete again = %v, want ErrNotFound (A's row is out of reach)", err)
	}
	// Both remaining rows belong to tenants, so neither delete reclaims bytes:
	// the row goes, the shared host file stays. A's delete drops A's row; B's
	// delete drops B's shadow and the operator ("") row surfaces again.
	if err := svc.DeleteWasmModule(a, modA.ID); err != nil {
		t.Fatalf("A delete own: %v", err)
	}
	if err := svc.DeleteWasmModule(b, "std-mod"); err != nil {
		t.Fatalf("B delete shadow row: %v", err)
	}
	if len(rt.removeImages) != 0 {
		t.Fatalf("RemoveImage = %v; tenant deletes must never reclaim host bytes (#537)", rt.removeImages)
	}
	if got, err := svc.GetWasmModule(b, "std-mod"); err != nil || got.ModuleRef != "std" {
		t.Fatalf("B get after deleting its shadow = %+v, %v; want the operator row back", got, err)
	}
}

// T0b: a create-time boot by catalogue id resolves the booting owner's own row
// first, then an operator-published one, and never another owner's.
func TestResolveOwnedWasmModule_OwnFirstThenOperator(t *testing.T) {
	svc, st, _, _ := wasmOwnerIDsHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, rec := range []store.WasmModuleRecord{
		{OwnerRef: "", ID: "shared-id", Status: "ready", ModulePath: "/m/op.wasm", Digest: "d-op"},
		{OwnerRef: "acct-A", ID: "shared-id", Status: "ready", ModulePath: "/m/a.wasm", Digest: "d-a"},
		{OwnerRef: "", ID: "failed-id", Status: "ready", ModulePath: "/m/op-f.wasm", Digest: "d-op-f"},
		{OwnerRef: "acct-A", ID: "failed-id", Status: "failed"},
		{OwnerRef: "acct-B", ID: "b-only", Status: "ready", ModulePath: "/m/b.wasm", Digest: "d-b"},
		{OwnerRef: "", ID: "op-only", Status: "ready", ModulePath: "/m/op2.wasm", Digest: "d-op2"},
	} {
		rec.ModuleRef, rec.CreatedAt, rec.UpdatedAt = "ref-"+rec.ID, now, now
		if err := st.UpsertWasmModule(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name       string
		ctx        context.Context
		id         string
		wantDigest string // "" means it must not resolve
	}{
		{"own row before operator row", ownerScopedCtx("acct-A"), "shared-id", "d-a"},
		{"no own row falls back to operator", ownerScopedCtx("acct-B"), "shared-id", "d-op"},
		{"own failed row shadows operator row", ownerScopedCtx("acct-A"), "failed-id", ""},
		{"another owner's row never resolves", ownerScopedCtx("acct-A"), "b-only", ""},
		{"operator create resolves only operator rows", operatorCtx(), "b-only", ""},
		{"operator create resolves operator row", operatorCtx(), "shared-id", "d-op"},
		{"internal boot pinned to the sandbox owner", wasmmod.WithCatalogueOwner(ctx, "acct-B"), "b-only", "d-b"},
		{"pin wins over the caller identity", wasmmod.WithCatalogueOwner(ownerScopedCtx("acct-B"), "acct-A"), "shared-id", "d-a"},
		{"tenant sees operator-only row", ownerScopedCtx("acct-A"), "op-only", "d-op2"},
		{"unknown id", ownerScopedCtx("acct-A"), "missing", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, digest, ok := svc.ResolveOwnedWasmModule(tc.ctx, tc.id)
			if tc.wantDigest == "" {
				if ok {
					t.Fatalf("resolved digest %q, want no match", digest)
				}
				return
			}
			if !ok || digest != tc.wantDigest {
				t.Fatalf("resolve = (%q, %v), want %q", digest, ok, tc.wantDigest)
			}
		})
	}
}

// T0b: the delete in-use gate looks only at sandboxes that can resolve
// through the row. A tenant's delete is never blocked by (and so never
// reveals) another owner's sandbox running the same bytes; those bytes stay
// on the host. An operator-published row is reachable from every namespace,
// so any sandbox using it blocks the delete.
func TestDeleteWasmModule_InUseGateIsPerNamespace(t *testing.T) {
	svc, st, rt, modPath := wasmOwnerIDsHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, rec := range []store.WasmModuleRecord{
		{OwnerRef: "acct-A", ID: "a-mod", ModuleRef: "oci://r/a:1", Digest: "d-shared"},
		{OwnerRef: "acct-A", ID: "a-busy", ModuleRef: "oci://r/a-busy:1", Digest: "d-busy"},
		{OwnerRef: "", ID: "op-mod", ModuleRef: "oci://r/op:1", Digest: "d-op"},
	} {
		rec.Status, rec.ModulePath, rec.CreatedAt, rec.UpdatedAt = "ready", modPath, now, now
		if err := st.UpsertWasmModule(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	for _, sb := range []*models.Sandbox{
		{ID: "sb-b-shared", OwnerRef: "acct-B", ModuleDigest: "d-shared", ModuleRef: "oci://r/b:1"},
		{ID: "sb-a-busy", OwnerRef: "acct-A", ModuleDigest: "d-busy", ModuleRef: "oci://r/a-busy:1"},
		{ID: "sb-b-op", OwnerRef: "acct-B", ModuleDigest: "d-op", ModuleRef: "op-mod"},
	} {
		sb.Runtime, sb.CreatedAt, sb.UpdatedAt = models.RuntimeWasm, now, now
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("Create %s: %v", sb.ID, err)
		}
	}

	if err := svc.DeleteWasmModule(ownerScopedCtx("acct-A"), "a-mod"); err != nil {
		t.Fatalf("A delete while only B runs the bytes = %v, want success", err)
	}
	if len(rt.removeImages) != 0 {
		t.Fatalf("RemoveImage = %v while B's sandbox still runs the bytes", rt.removeImages)
	}
	if err := svc.DeleteWasmModule(ownerScopedCtx("acct-A"), "a-busy"); !errors.Is(err, store.ErrWasmModuleInUse) {
		t.Fatalf("A delete with its own sandbox on it = %v, want ErrWasmModuleInUse", err)
	}
	if err := svc.DeleteWasmModule(operatorCtx(), "op-mod"); !errors.Is(err, store.ErrWasmModuleInUse) {
		t.Fatalf("operator delete of a row a tenant boots from = %v, want ErrWasmModuleInUse", err)
	}
}

// The catalogue janitor reclaims rows per namespace but the shared bytes (and
// their warm-pool target) only once, with the last row that pins them.
func TestRunWasmModuleGC_SharedDigestRemovedOnce(t *testing.T) {
	svc, st, rt, modPath := wasmOwnerIDsHarness(t)
	ctx := context.Background()
	svc.cfg.WasmModuleGCTTL = time.Hour
	for _, owner := range []string{"acct-A", "acct-B"} {
		if err := st.UpsertWasmModule(ctx, store.WasmModuleRecord{
			OwnerRef: owner, ID: "digest-shared", ModuleRef: "oci://r/" + owner + ":1",
			Digest: "digest-shared", Status: "ready", ModulePath: modPath,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Upsert stamps updated_at with the wall clock; sweep from two hours ahead
	// so both rows are past the one-hour TTL.
	svc.runWasmModuleGC(ctx, time.Now().UTC().Add(2*time.Hour))
	for _, owner := range []string{"acct-A", "acct-B"} {
		if _, err := st.GetWasmModule(ctx, owner, "digest-shared"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s row after GC = %v, want deleted", owner, err)
		}
	}
	if len(rt.removeImages) != 1 || rt.removeImages[0] != "digest-shared" {
		t.Fatalf("RemoveImage = %v, want the shared digest exactly once", rt.removeImages)
	}
}

// A failed shared-digest check skips that row: the janitor never removes bytes
// it could not prove unshared. The first row's byte removal drops the catalogue
// table out from under the sweep, so the second row's check fails.
func TestRunWasmModuleGC_SharedDigestCheckErrorSkipsRow(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	for _, rec := range []store.WasmModuleRecord{
		{OwnerRef: "acct-A", ID: "first", ModuleRef: "oci://r/a:1", Digest: "d-first", Status: "ready"},
		{OwnerRef: "acct-B", ID: "second", ModuleRef: "oci://r/b:1", Digest: "d-second", Status: "ready"},
	} {
		if err := st.UpsertWasmModule(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	logs := &strings.Builder{}
	svc := &Service{
		cfg:    config.Config{WasmModuleGCTTL: time.Hour},
		store:  st,
		logger: slog.New(slog.NewTextHandler(logs, nil)),
		wasm:   wasmModuleGCDropRuntime{dbPath: dbPath},
	}
	svc.runWasmModuleGC(ctx, time.Now().UTC().Add(2*time.Hour))
	if !strings.Contains(logs.String(), "wasm module gc shared-digest check failed") {
		t.Fatalf("GC log = %q, want the shared-digest check failure", logs.String())
	}
}

// Auto-registration after a create writes into the sandbox owner's namespace.
// Before per-owner ids the upsert keyed on id alone, so a second tenant's
// create rewrote the first tenant's row (owner and ref included).
func TestRegisterWasmModuleCatalogue_StaysInOwnerNamespace(t *testing.T) {
	svc, st, _, modPath := wasmOwnerIDsHarness(t)
	ctx := context.Background()
	for _, sb := range []*models.Sandbox{
		{ID: "sb-a", OwnerRef: "acct-A", Runtime: models.RuntimeWasm, ModuleRef: "oci://r/a:1", ModuleDigest: "d-same"},
		{ID: "sb-b", OwnerRef: "acct-B", Runtime: models.RuntimeWasm, ModuleRef: "oci://r/b:1", ModuleDigest: "d-same"},
	} {
		svc.registerWasmModuleCatalogue(ctx, sb, modPath, 4)
	}
	for owner, ref := range map[string]string{"acct-A": "oci://r/a:1", "acct-B": "oci://r/b:1"} {
		rec, err := st.GetWasmModule(ctx, owner, "d-same")
		if err != nil || rec.ModuleRef != ref {
			t.Fatalf("%s auto-registered row = %+v, %v; want ref %s", owner, rec, err, ref)
		}
	}
}

// wasmCatalogueOwnerRuntime records the catalogue namespace pinned on the
// create context, which is what the module resolver's catalogue lookup sees.
type wasmCatalogueOwnerRuntime struct {
	*wasmRecordingRuntime
	owner  string
	pinned bool
}

func (r *wasmCatalogueOwnerRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, id, token string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	r.owner, r.pinned = wasmmod.CatalogueOwner(ctx)
	return r.wasmRecordingRuntime.Create(ctx, req, id, token, binds)
}

// A WASM create pins the catalogue namespace to the owner the sandbox row
// will carry: the caller's account, or on a caller-less failover recreate the
// owner recorded in the placement.
func TestCreateWasmSandbox_PinsCatalogueOwner(t *testing.T) {
	tests := []struct {
		name      string
		ctx       context.Context
		placement string
		wantOwner string
	}{
		{name: "tenant create", ctx: ownerScopedCtx("acct-A"), wantOwner: "acct-A"},
		{name: "operator create", ctx: operatorCtx(), wantOwner: ""},
		{name: "failover recreate", ctx: context.Background(), placement: "acct-B", wantOwner: "acct-B"},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
			svc.cfg.EnableWasm = true
			if tc.placement != "" {
				svc.cluster = &ownerRefPlacementCluster{Noop: cluster.NewNoop("node-a", "", ""), ownerRef: tc.placement}
			}
			rt := &wasmCatalogueOwnerRuntime{wasmRecordingRuntime: &wasmRecordingRuntime{}}
			svc.SetWasmRuntime(rt)
			id := fmt.Sprintf("sb-pin-%d", i)
			if _, err := svc.createWasmSandbox(tc.ctx, models.CreateSandboxRequest{Runtime: models.RuntimeWasm, ModuleRef: "mod-id"}, id); err != nil {
				t.Fatalf("createWasmSandbox: %v", err)
			}
			if !rt.pinned || rt.owner != tc.wantOwner {
				t.Fatalf("catalogue owner on create ctx = (%q, %v), want (%q, true)", rt.owner, rt.pinned, tc.wantOwner)
			}
			sb, err := st.Get(context.Background(), id)
			if err != nil || sb.OwnerRef != tc.wantOwner {
				t.Fatalf("sandbox owner = %+v, %v; want %q", sb, err, tc.wantOwner)
			}
		})
	}
}
