package service

import (
	"context"
	"errors"
	"expvar"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestFacadeStateCompatAndTagHelpers(t *testing.T) {
	ctx := context.Background()
	svc, st := newFacadeStateTestService(t)

	sandbox := &models.Sandbox{
		ID:             "sb-facade",
		Image:          "alpine:3.20",
		Status:         models.SandboxStatusStarted,
		PublicURL:      "https://sb-facade.example.test",
		ContainerID:    "ctr-facade",
		ContainerIP:    "10.0.0.10",
		CPU:            1,
		MemoryMB:       512,
		DiskGB:         10,
		OSUser:         "root",
		ToolboxEnabled: true,
		Name:           "facade-name",
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
		LastActiveAt:   time.Now().UTC(),
	}
	if err := st.Create(ctx, sandbox); err != nil {
		t.Fatalf("create sandbox: %v", err)
	}

	if err := svc.UpsertCompatState(ctx, sandbox.ID, models.FacadeDaytona, `{"target":"ws-1"}`); err != nil {
		t.Fatalf("upsert compat state: %v", err)
	}
	if err := svc.UpsertCompatState(ctx, sandbox.ID, models.FacadeDaytona, `{"target":"ws-2"}`); err != nil {
		t.Fatalf("update compat state: %v", err)
	}

	state, err := svc.GetCompatState(ctx, sandbox.ID, models.FacadeDaytona)
	if err != nil {
		t.Fatalf("get compat state: %v", err)
	}
	if state.StateJSON != `{"target":"ws-2"}` {
		t.Fatalf("state json = %q, want updated value", state.StateJSON)
	}

	states, err := svc.ListCompatState(ctx, models.FacadeDaytona)
	if err != nil {
		t.Fatalf("list compat state: %v", err)
	}
	if got := len(states); got != 1 {
		t.Fatalf("compat state count = %d, want 1", got)
	}
	if got := states[sandbox.ID].StateJSON; got != state.StateJSON {
		t.Fatalf("listed state json = %q, want %q", got, state.StateJSON)
	}

	resolvedID, err := svc.ResolveSandboxIDByName(ctx, sandbox.Name)
	if err != nil {
		t.Fatalf("resolve sandbox id by name: %v", err)
	}
	if resolvedID != sandbox.ID {
		t.Fatalf("resolved id = %q, want %q", resolvedID, sandbox.ID)
	}

	tags := map[string]string{"team": "platform", "env": "test"}
	if err := svc.UpdateTags(ctx, sandbox.ID, tags); err != nil {
		t.Fatalf("update tags: %v", err)
	}
	stored, err := st.Get(ctx, sandbox.ID)
	if err != nil {
		t.Fatalf("get sandbox after tag update: %v", err)
	}
	if got := stored.Tags["team"]; got != "platform" {
		t.Fatalf("team tag = %q, want platform", got)
	}
	if got := stored.Tags["env"]; got != "test" {
		t.Fatalf("env tag = %q, want test", got)
	}
}

func TestFacadeStateSnapshotAliasHelpers(t *testing.T) {
	ctx := context.Background()
	svc, st := newFacadeStateTestService(t)

	snapshot := &models.SandboxSnapshot{
		Name:            "snap-facade",
		Image:           "registry.example.test/facade:snap",
		SourceSandboxID: "sb-source",
		CreatedAt:       time.Now().UTC(),
	}
	if err := st.CreateSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	alias := models.SnapshotAlias{
		Alias:        "alias-facade",
		SnapshotName: snapshot.Name,
		Facade:       models.FacadeE2B,
		ExtraNames:   []string{"snapshot-alpha", "snapshot-beta"},
	}
	if err := svc.UpsertSnapshotAlias(ctx, alias); err != nil {
		t.Fatalf("upsert snapshot alias: %v", err)
	}

	alias.ExtraNames = []string{"snapshot-gamma"}
	if err := svc.UpsertSnapshotAlias(ctx, alias); err != nil {
		t.Fatalf("update snapshot alias: %v", err)
	}

	got, err := svc.GetSnapshotAlias(ctx, alias.Alias)
	if err != nil {
		t.Fatalf("get snapshot alias: %v", err)
	}
	if got.SnapshotName != snapshot.Name {
		t.Fatalf("snapshot name = %q, want %q", got.SnapshotName, snapshot.Name)
	}
	if len(got.ExtraNames) != 1 || got.ExtraNames[0] != "snapshot-gamma" {
		t.Fatalf("extra names = %v, want [snapshot-gamma]", got.ExtraNames)
	}

	aliases, err := svc.ListSnapshotAliases(ctx, models.FacadeE2B)
	if err != nil {
		t.Fatalf("list snapshot aliases: %v", err)
	}
	if got := len(aliases); got != 1 {
		t.Fatalf("snapshot alias count = %d, want 1", got)
	}
	if aliases[alias.Alias].SnapshotName != snapshot.Name {
		t.Fatalf("listed snapshot name = %q, want %q", aliases[alias.Alias].SnapshotName, snapshot.Name)
	}

	if err := svc.DeleteSnapshotAlias(ctx, alias.Alias); err != nil {
		t.Fatalf("delete snapshot alias: %v", err)
	}
	_, err = svc.GetSnapshotAlias(ctx, alias.Alias)
	if !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("get deleted snapshot alias error = %v, want ErrNotFound", err)
	}
}

func TestFacadeStateIdempotentRequestHelpers(t *testing.T) {
	ctx := context.Background()
	svc, _ := newFacadeStateTestService(t)
	const (
		scope       = "e2b.create"
		fingerprint = "fp-123"
	)
	now := time.Now().UTC()

	claimsBefore := expvarMapValue(facadeIdempotencyClaims, scope+".pending")
	readyClaimsBefore := expvarMapValue(facadeIdempotencyClaims, scope+".ready")
	acquiredBefore := expvarMapValue(facadeIdempotencyAcquired, scope)
	conflictsBefore := expvarMapValue(facadeIdempotencyConflicts, scope)
	completeBefore := expvarMapValue(facadeIdempotencyComplete, scope)
	deletesBefore := expvarMapValue(facadeIdempotencyDeletes, scope)

	if _, _, err := svc.ClaimIdempotentRequest(ctx, "", fingerprint, now, 30*time.Second); err == nil {
		t.Fatal("blank scope claim unexpectedly succeeded")
	}

	record, acquired, err := svc.ClaimIdempotentRequest(ctx, scope, fingerprint, now, 30*time.Second)
	if err != nil {
		t.Fatalf("initial claim: %v", err)
	}
	if !acquired {
		t.Fatal("initial claim not acquired")
	}
	if record.State != models.RequestStatePending {
		t.Fatalf("initial claim state = %q, want pending", record.State)
	}

	pendingRecord, acquired, err := svc.ClaimIdempotentRequest(ctx, scope, fingerprint, now.Add(5*time.Second), 30*time.Second)
	if err != nil {
		t.Fatalf("second claim while pending: %v", err)
	}
	if acquired {
		t.Fatal("second claim unexpectedly acquired")
	}
	if pendingRecord.State != models.RequestStatePending {
		t.Fatalf("pending claim state = %q, want pending", pendingRecord.State)
	}

	if err := svc.CompleteIdempotentRequest(ctx, scope, "missing", "sb-missing", now, time.Minute); err == nil {
		t.Fatal("complete missing request unexpectedly succeeded")
	}
	if err := svc.CompleteIdempotentRequest(ctx, scope, fingerprint, "sb-claimed", now.Add(10*time.Second), time.Minute); err != nil {
		t.Fatalf("complete claim: %v", err)
	}

	readyRecord, err := svc.GetIdempotentRequest(ctx, scope, fingerprint)
	if err != nil {
		t.Fatalf("get ready request: %v", err)
	}
	if readyRecord.State != models.RequestStateReady {
		t.Fatalf("ready record state = %q, want ready", readyRecord.State)
	}
	if readyRecord.TargetID != "sb-claimed" {
		t.Fatalf("ready record target = %q, want sb-claimed", readyRecord.TargetID)
	}

	replayedRecord, acquired, err := svc.ClaimIdempotentRequest(ctx, scope, fingerprint, now.Add(20*time.Second), 30*time.Second)
	if err != nil {
		t.Fatalf("claim ready request: %v", err)
	}
	if acquired {
		t.Fatal("ready request unexpectedly acquired")
	}
	if replayedRecord.State != models.RequestStateReady {
		t.Fatalf("replayed record state = %q, want ready", replayedRecord.State)
	}

	if err := svc.DeleteIdempotentRequest(ctx, scope, "missing"); err == nil {
		t.Fatal("delete missing request unexpectedly succeeded")
	}
	if err := svc.DeleteIdempotentRequest(ctx, scope, fingerprint); err != nil {
		t.Fatalf("delete request: %v", err)
	}
	if _, err := svc.GetIdempotentRequest(ctx, scope, fingerprint); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("get deleted request error = %v, want ErrNotFound", err)
	}

	if got := expvarMapValue(facadeIdempotencyClaims, scope+".pending") - claimsBefore; got != 2 {
		t.Fatalf("pending claim metric delta = %d, want 2", got)
	}
	if got := expvarMapValue(facadeIdempotencyClaims, scope+".ready") - readyClaimsBefore; got != 1 {
		t.Fatalf("ready claim metric delta = %d, want 1", got)
	}
	if got := expvarMapValue(facadeIdempotencyAcquired, scope) - acquiredBefore; got != 1 {
		t.Fatalf("acquired metric delta = %d, want 1", got)
	}
	if got := expvarMapValue(facadeIdempotencyConflicts, scope) - conflictsBefore; got != 1 {
		t.Fatalf("conflicts metric delta = %d, want 1", got)
	}
	if got := expvarMapValue(facadeIdempotencyComplete, scope) - completeBefore; got != 1 {
		t.Fatalf("complete metric delta = %d, want 1", got)
	}
	if got := expvarMapValue(facadeIdempotencyDeletes, scope) - deletesBefore; got != 1 {
		t.Fatalf("delete metric delta = %d, want 1", got)
	}
}

func newFacadeStateTestService(t *testing.T) (*Service, *storepkg.Store) {
	t.Helper()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	return &Service{store: st}, st
}

func expvarMapValue(metric *expvar.Map, key string) int64 {
	if metric == nil {
		return 0
	}
	value := metric.Get(key)
	if value == nil {
		return 0
	}
	parsed, err := strconv.ParseInt(value.String(), 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}
