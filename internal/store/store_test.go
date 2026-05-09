package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestStoreCases(t *testing.T) {
	ctx := context.Background()

	// 24 cases
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "open_creates_schema_and_close_succeeds",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "state.db")
				st, err := Open(path)
				if err != nil {
					t.Fatalf("Open() error = %v", err)
				}
				defer st.Close()
				if err := st.Close(); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
			},
		},
		{
			name: "open_applies_sqlite_contention_settings",
			run: func(t *testing.T) {
				st := newTestStore(t)

				if got := st.db.Stats().MaxOpenConnections; got != 1 {
					t.Fatalf("MaxOpenConnections = %d, want 1", got)
				}

				var busyTimeout int
				if err := st.db.QueryRowContext(ctx, `PRAGMA busy_timeout;`).Scan(&busyTimeout); err != nil {
					t.Fatalf("read busy_timeout pragma: %v", err)
				}
				if busyTimeout != sqliteBusyTimeoutMS {
					t.Fatalf("busy_timeout = %d, want %d", busyTimeout, sqliteBusyTimeoutMS)
				}

				var foreignKeys int
				if err := st.db.QueryRowContext(ctx, `PRAGMA foreign_keys;`).Scan(&foreignKeys); err != nil {
					t.Fatalf("read foreign_keys pragma: %v", err)
				}
				if foreignKeys != 1 {
					t.Fatalf("foreign_keys = %d, want 1", foreignKeys)
				}
			},
		},
		{
			name: "create_and_get_roundtrip",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-1")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.ID != sandbox.ID || got.Image != sandbox.Image || got.PublicURL != sandbox.PublicURL {
					t.Fatalf("unexpected sandbox: %+v", got)
				}
				if !reflect.DeepEqual(got.Env, sandbox.Env) || !reflect.DeepEqual(got.ContainerCommand, sandbox.ContainerCommand) {
					t.Fatalf("unexpected env/command: %+v", got)
				}
				if got.Runtime != sandbox.Runtime {
					t.Fatalf("unexpected runtime: got %q, want %q", got.Runtime, sandbox.Runtime)
				}
			},
		},
		{
			name: "runtime_empty_roundtrip",
			run: func(t *testing.T) {
				// Pre-migration rows carry empty Runtime; the store must
				// preserve "" rather than coercing it to a default.
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-rt-empty")
				sandbox.Runtime = ""
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.Runtime != "" {
					t.Fatalf("expected empty runtime, got %q", got.Runtime)
				}
			},
		},
		{
			name: "create_duplicate_returns_error",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-dup")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := st.Create(ctx, sandbox); err == nil {
					t.Fatalf("expected duplicate Create() error")
				}
			},
		},
		{
			name: "list_returns_all_sandboxes",
			run: func(t *testing.T) {
				st := newTestStore(t)
				if err := st.Create(ctx, sampleSandbox("sb-a")); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := st.Create(ctx, sampleSandbox("sb-b")); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				items, err := st.List(ctx)
				if err != nil {
					t.Fatalf("List() error = %v", err)
				}
				if len(items) != 2 {
					t.Fatalf("List() len = %d", len(items))
				}
			},
		},
		{
			name: "upsert_updates_existing_sandbox",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-upsert")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				sandbox.Status = models.SandboxStatusStopped
				sandbox.CPU = 4
				sandbox.MemoryMB = 4096
				sandbox.LastError = "stopped"
				if err := st.Upsert(ctx, sandbox); err != nil {
					t.Fatalf("Upsert() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.Status != models.SandboxStatusStopped || got.CPU != 4 || got.MemoryMB != 4096 || got.LastError != "stopped" {
					t.Fatalf("unexpected updated sandbox: %+v", got)
				}
			},
		},
		{
			name: "delete_removes_sandbox",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-delete")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := st.Delete(ctx, sandbox.ID); err != nil {
					t.Fatalf("Delete() error = %v", err)
				}
				if _, err := st.Get(ctx, sandbox.ID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound, got %v", err)
				}
			},
		},
		{
			name: "delete_missing_returns_not_found",
			run: func(t *testing.T) {
				st := newTestStore(t)
				if err := st.Delete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound, got %v", err)
				}
			},
		},
		{
			name: "update_status_changes_fields",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-status")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := st.UpdateStatus(ctx, sandbox.ID, models.SandboxStatusError, "boom"); err != nil {
					t.Fatalf("UpdateStatus() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.Status != models.SandboxStatusError || got.LastError != "boom" {
					t.Fatalf("unexpected status update: %+v", got)
				}
			},
		},
		{
			name: "update_runtime_changes_fields",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-runtime")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := st.UpdateRuntime(ctx, sandbox.ID, "container-2", "10.0.0.22", "https://new.example.com"); err != nil {
					t.Fatalf("UpdateRuntime() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.ContainerID != "container-2" || got.ContainerIP != "10.0.0.22" || got.PublicURL != "https://new.example.com" {
					t.Fatalf("unexpected runtime update: %+v", got)
				}
			},
		},
		{
			name: "touch_updates_last_active",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-touch")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				want := time.Now().UTC().Add(2 * time.Hour).Round(0)
				if err := st.Touch(ctx, sandbox.ID, want); err != nil {
					t.Fatalf("Touch() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if !got.LastActiveAt.UTC().Equal(want) {
					t.Fatalf("LastActiveAt = %s, want %s", got.LastActiveAt.UTC(), want)
				}
			},
		},
		{
			name: "upsert_port_persists_on_get",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-port")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				exposure := models.ExposedPort{SandboxID: sandbox.ID, Port: 3000, PublicURL: "https://sb-port-3000.example.com", CreatedAt: time.Now().UTC()}
				if err := st.UpsertPort(ctx, exposure); err != nil {
					t.Fatalf("UpsertPort() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if len(got.ExposedPorts) != 1 || got.ExposedPorts[0].Port != 3000 {
					t.Fatalf("unexpected exposed ports: %+v", got.ExposedPorts)
				}
			},
		},
		{
			name: "delete_port_removes_on_get",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-port-delete")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				exposure := models.ExposedPort{SandboxID: sandbox.ID, Port: 3000, PublicURL: "https://sb-port-delete-3000.example.com", CreatedAt: time.Now().UTC()}
				if err := st.UpsertPort(ctx, exposure); err != nil {
					t.Fatalf("UpsertPort() error = %v", err)
				}
				if err := st.DeletePort(ctx, sandbox.ID, 3000); err != nil {
					t.Fatalf("DeletePort() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if len(got.ExposedPorts) != 0 {
					t.Fatalf("expected no exposed ports, got %+v", got.ExposedPorts)
				}
			},
		},
		{
			name: "delete_sandbox_cascades_exposed_ports",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-cascade")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				exposure := models.ExposedPort{SandboxID: sandbox.ID, Port: 3000, PublicURL: "https://sb-cascade-3000.example.com", CreatedAt: time.Now().UTC()}
				if err := st.UpsertPort(ctx, exposure); err != nil {
					t.Fatalf("UpsertPort() error = %v", err)
				}
				if err := st.Delete(ctx, sandbox.ID); err != nil {
					t.Fatalf("Delete() error = %v", err)
				}
				ports, err := st.loadPorts(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("loadPorts() error = %v", err)
				}
				if len(ports) != 0 {
					t.Fatalf("expected no ports, got %+v", ports)
				}
			},
		},
		{
			name: "has_active_image_ref_returns_false_when_only_destroyed",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-img-destroyed")
				sandbox.Image = "alpine:3.19"
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := st.UpdateStatus(ctx, sandbox.ID, models.SandboxStatusDestroyed, ""); err != nil {
					t.Fatalf("UpdateStatus() error = %v", err)
				}
				active, err := st.HasActiveImageRef(ctx, "alpine:3.19")
				if err != nil {
					t.Fatalf("HasActiveImageRef() error = %v", err)
				}
				if active {
					t.Fatal("expected no active references for image with only destroyed rows")
				}
			},
		},
		{
			name: "has_active_image_ref_returns_true_when_stopped_present",
			run: func(t *testing.T) {
				st := newTestStore(t)
				stopped := sampleSandbox("sb-img-stopped")
				stopped.Image = "alpine:3.19"
				stopped.Status = models.SandboxStatusStopped
				if err := st.Create(ctx, stopped); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				dead := sampleSandbox("sb-img-dead")
				dead.Image = "alpine:3.19"
				if err := st.Create(ctx, dead); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := st.UpdateStatus(ctx, dead.ID, models.SandboxStatusDestroyed, ""); err != nil {
					t.Fatalf("UpdateStatus() error = %v", err)
				}
				active, err := st.HasActiveImageRef(ctx, "alpine:3.19")
				if err != nil {
					t.Fatalf("HasActiveImageRef() error = %v", err)
				}
				if !active {
					t.Fatal("expected stopped sandbox to count as an active reference")
				}
			},
		},
		{
			name: "has_active_image_ref_isolates_by_image",
			run: func(t *testing.T) {
				st := newTestStore(t)
				other := sampleSandbox("sb-img-other")
				other.Image = "ubuntu:22.04"
				if err := st.Create(ctx, other); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				active, err := st.HasActiveImageRef(ctx, "alpine:3.19")
				if err != nil {
					t.Fatalf("HasActiveImageRef() error = %v", err)
				}
				if active {
					t.Fatal("expected no references for unrelated image")
				}
			},
		},
		{
			name: "has_active_image_ref_returns_true_for_empty_image",
			run: func(t *testing.T) {
				st := newTestStore(t)
				active, err := st.HasActiveImageRef(ctx, "")
				if err != nil {
					t.Fatalf("HasActiveImageRef() error = %v", err)
				}
				if !active {
					t.Fatal("expected empty image to be treated as still in use")
				}
			},
		},
		{
			name: "purge_destroyed_before_only_affects_destroyed_rows",
			run: func(t *testing.T) {
				st := newTestStore(t)

				live := sampleSandbox("sb-purge-live")
				if err := st.Create(ctx, live); err != nil {
					t.Fatalf("Create(live) error = %v", err)
				}

				dead := sampleSandbox("sb-purge-dead")
				if err := st.Create(ctx, dead); err != nil {
					t.Fatalf("Create(dead) error = %v", err)
				}
				if err := st.UpdateStatus(ctx, dead.ID, models.SandboxStatusDestroyed, ""); err != nil {
					t.Fatalf("UpdateStatus() error = %v", err)
				}

				// Cutoff in the future ensures both rows are technically
				// "before" cutoff — but only the destroyed one should be
				// deleted. Live sandboxes are immune even if they're old.
				purged, err := st.PurgeDestroyedBefore(ctx, time.Now().Add(time.Hour))
				if err != nil {
					t.Fatalf("PurgeDestroyedBefore() error = %v", err)
				}
				if purged != 1 {
					t.Fatalf("expected 1 row purged, got %d", purged)
				}

				if _, err := st.Get(ctx, live.ID); err != nil {
					t.Fatalf("live sandbox should still exist: %v", err)
				}
				if _, err := st.Get(ctx, dead.ID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("destroyed row should be gone, got err = %v", err)
				}
			},
		},
		{
			name: "purge_destroyed_before_respects_cutoff",
			run: func(t *testing.T) {
				st := newTestStore(t)

				dead := sampleSandbox("sb-purge-recent")
				if err := st.Create(ctx, dead); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := st.UpdateStatus(ctx, dead.ID, models.SandboxStatusDestroyed, ""); err != nil {
					t.Fatalf("UpdateStatus() error = %v", err)
				}

				// Cutoff one hour in the past: the row was destroyed just
				// now, so it's NEWER than cutoff and must not be purged.
				purged, err := st.PurgeDestroyedBefore(ctx, time.Now().Add(-time.Hour))
				if err != nil {
					t.Fatalf("PurgeDestroyedBefore() error = %v", err)
				}
				if purged != 0 {
					t.Fatalf("expected 0 rows purged for fresh destroy, got %d", purged)
				}
				if _, err := st.Get(ctx, dead.ID); err != nil {
					t.Fatalf("recently destroyed row should still exist: %v", err)
				}
			},
		},
		{
			name: "purge_destroyed_before_noop_on_empty_table",
			run: func(t *testing.T) {
				st := newTestStore(t)
				purged, err := st.PurgeDestroyedBefore(ctx, time.Now())
				if err != nil {
					t.Fatalf("PurgeDestroyedBefore() error = %v", err)
				}
				if purged != 0 {
					t.Fatalf("expected 0 rows purged on empty table, got %d", purged)
				}
			},
		},
		{
			name: "lifecycle_persists_through_create_and_get",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-lifecycle")
				sandbox.Lifecycle = models.Lifecycle{
					StopIfIdleFor:    time.Hour,
					DestroyIfIdleFor: 4 * time.Hour,
					StopAtAge:        2 * time.Hour,
					DestroyAtAge:     24 * time.Hour,
				}
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.Lifecycle != sandbox.Lifecycle {
					t.Fatalf("Lifecycle roundtrip mismatch: got %+v want %+v", got.Lifecycle, sandbox.Lifecycle)
				}
			},
		},
		{
			name: "update_lifecycle_replaces_fields",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-update-lifecycle")
				sandbox.Lifecycle = models.Lifecycle{StopIfIdleFor: time.Hour}
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				newL := models.Lifecycle{
					DestroyAtAge: 24 * time.Hour,
				}
				if err := st.UpdateLifecycle(ctx, sandbox.ID, newL); err != nil {
					t.Fatalf("UpdateLifecycle() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.Lifecycle != newL {
					t.Fatalf("Lifecycle replacement mismatch: got %+v want %+v", got.Lifecycle, newL)
				}
				// StopIfIdleFor should be cleared by full-replace semantics.
				if got.Lifecycle.StopIfIdleFor != 0 {
					t.Fatalf("expected StopIfIdleFor cleared, got %v", got.Lifecycle.StopIfIdleFor)
				}
			},
		},
		{
			name: "update_lifecycle_returns_not_found_for_missing_id",
			run: func(t *testing.T) {
				st := newTestStore(t)
				err := st.UpdateLifecycle(ctx, "missing", models.Lifecycle{})
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound, got %v", err)
				}
			},
		},
		{
			name: "list_returns_all_ports_with_one_query_per_call",
			run: func(t *testing.T) {
				// Three sandboxes: one with two ports, one with one port, one
				// with zero. Validates that the bulk-port attach correctly
				// distributes rows by sandbox_id and leaves zero-port
				// sandboxes alone.
				st := newTestStore(t)
				a := sampleSandbox("sb-list-a")
				b := sampleSandbox("sb-list-b")
				c := sampleSandbox("sb-list-c")
				for _, sb := range []*models.Sandbox{a, b, c} {
					if err := st.Create(ctx, sb); err != nil {
						t.Fatalf("Create(%s) error = %v", sb.ID, err)
					}
				}
				now := time.Now().UTC()
				ports := []models.ExposedPort{
					{SandboxID: a.ID, Port: 3000, PublicURL: "https://a-3000.example.com", CreatedAt: now},
					{SandboxID: a.ID, Port: 4000, PublicURL: "https://a-4000.example.com", CreatedAt: now},
					{SandboxID: b.ID, Port: 5000, PublicURL: "https://b-5000.example.com", CreatedAt: now},
				}
				for _, p := range ports {
					if err := st.UpsertPort(ctx, p); err != nil {
						t.Fatalf("UpsertPort(%s:%d) error = %v", p.SandboxID, p.Port, err)
					}
				}

				items, err := st.List(ctx)
				if err != nil {
					t.Fatalf("List() error = %v", err)
				}
				byID := map[string]*models.Sandbox{}
				for _, sb := range items {
					byID[sb.ID] = sb
				}
				if len(byID[a.ID].ExposedPorts) != 2 {
					t.Fatalf("a: expected 2 ports, got %+v", byID[a.ID].ExposedPorts)
				}
				if len(byID[b.ID].ExposedPorts) != 1 || byID[b.ID].ExposedPorts[0].Port != 5000 {
					t.Fatalf("b: expected 1 port == 5000, got %+v", byID[b.ID].ExposedPorts)
				}
				if len(byID[c.ID].ExposedPorts) != 0 {
					t.Fatalf("c: expected 0 ports, got %+v", byID[c.ID].ExposedPorts)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

func TestStoreHelperCases(t *testing.T) {
	// 2 cases
	t.Run("marshal_json_nil_returns_fallback", func(t *testing.T) {
		got, err := marshalJSON(nil, "{}")
		if err != nil {
			t.Fatalf("marshalJSON() error = %v", err)
		}
		if got != "{}" {
			t.Fatalf("marshalJSON() = %q", got)
		}
	})

	t.Run("scan_sandbox_invalid_env_json_returns_error", func(t *testing.T) {
		row := sqlRowStub{values: []any{
			"sb-bad", "image", models.SandboxStatusStarted, "https://example.com", "container", "10.0.0.1",
			float64(1), 1024, 10, "root", "{bad json", 0, 1, "", "", "", "[]", time.Now(), time.Now(), time.Now(),
			int64(0), int64(0), int64(0), int64(0), "", "",
		}}
		_, err := scanSandbox(row)
		if err == nil {
			t.Fatalf("expected scanSandbox() error")
		}
	})
}

type sqlRowStub struct {
	values []any
}

func (s sqlRowStub) Scan(dest ...any) error {
	for i := range dest {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(s.values[i]))
	}
	return nil
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		_ = st.Close()
	})
	return st
}

func sampleSandbox(id string) *models.Sandbox {
	now := time.Now().UTC().Round(0)
	return &models.Sandbox{
		ID:               id,
		Image:            "ubuntu:22.04",
		Status:           models.SandboxStatusStarted,
		PublicURL:        "https://" + id + ".example.com",
		ContainerID:      "container-" + id,
		ContainerIP:      "10.0.0.10",
		CPU:              2,
		MemoryMB:         2048,
		DiskGB:           20,
		OSUser:           "root",
		Env:              map[string]string{"KEY": "VALUE"},
		NetworkBlockAll:  true,
		ToolboxEnabled:   true,
		LastError:        "",
		ContainerCommand: []string{"bash", "-lc", "echo hello"},
		CreatedAt:        now,
		UpdatedAt:        now,
		LastActiveAt:     now,
		Runtime:          models.RuntimeGvisor,
	}
}
