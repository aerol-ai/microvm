package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestStoreCases(t *testing.T) {
	ctx := context.Background()

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
			// Regression: env_json and toolbox_token are secrets. The DB
			// directory and file must end up owner-only so a custom DBPath
			// or a dev run on a shared host can't leak them via umask
			// defaults. Re-chmod also has to tighten a directory the
			// caller created at 0o755 before opening.
			name: "open_locks_db_dir_and_file_to_owner_only",
			run: func(t *testing.T) {
				if runtime.GOOS == "windows" {
					t.Skip("POSIX permission bits not meaningful on Windows")
				}
				dir := t.TempDir()
				// Pre-create the dir at the old, lax mode so we exercise
				// the chmod-on-existing path, not just MkdirAll.
				if err := os.Chmod(dir, 0o755); err != nil {
					t.Fatalf("seed dir mode: %v", err)
				}
				path := filepath.Join(dir, "state.db")
				st, err := Open(path)
				if err != nil {
					t.Fatalf("Open() error = %v", err)
				}
				defer st.Close()

				dirInfo, err := os.Stat(dir)
				if err != nil {
					t.Fatalf("stat dir: %v", err)
				}
				if mode := dirInfo.Mode().Perm(); mode != 0o700 {
					t.Fatalf("dir mode = %o, want 0700", mode)
				}

				fileInfo, err := os.Stat(path)
				if err != nil {
					t.Fatalf("stat db file: %v", err)
				}
				if mode := fileInfo.Mode().Perm(); mode != 0o600 {
					t.Fatalf("db file mode = %o, want 0600", mode)
				}

				// WAL/SHM sidecars carry the same data — if they exist
				// after schema setup, they must be owner-only too.
				for _, sidecar := range []string{path + "-wal", path + "-shm"} {
					info, err := os.Stat(sidecar)
					if errors.Is(err, os.ErrNotExist) {
						continue
					}
					if err != nil {
						t.Fatalf("stat %s: %v", sidecar, err)
					}
					if mode := info.Mode().Perm(); mode != 0o600 {
						t.Fatalf("%s mode = %o, want 0600", sidecar, mode)
					}
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
			name: "daytona_metadata_roundtrip_and_resolve_by_name",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-daytona")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				autoStop := float32(15)
				autoArchive := float32(60)
				meta := models.DaytonaSandboxMetadata{
					SandboxID:                  sandbox.ID,
					Name:                       "workspace-alpha",
					Snapshot:                   "snapshot-123",
					User:                       "ubuntu",
					Labels:                     map[string]string{"team": "sdk"},
					Target:                     "default",
					NetworkAllowList:           "10.0.0.0/24",
					AutoStopIntervalMinutes:    &autoStop,
					AutoArchiveIntervalMinutes: &autoArchive,
				}
				if err := st.UpsertDaytonaMetadata(ctx, meta); err != nil {
					t.Fatalf("UpsertDaytonaMetadata() error = %v", err)
				}

				got, err := st.GetDaytonaMetadata(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("GetDaytonaMetadata() error = %v", err)
				}
				if got.Name != meta.Name || got.Snapshot != meta.Snapshot || got.User != meta.User || got.Target != meta.Target || got.NetworkAllowList != meta.NetworkAllowList {
					t.Fatalf("unexpected metadata: %+v", got)
				}
				if !reflect.DeepEqual(got.Labels, meta.Labels) {
					t.Fatalf("labels = %+v, want %+v", got.Labels, meta.Labels)
				}
				if got.AutoStopIntervalMinutes == nil || *got.AutoStopIntervalMinutes != autoStop {
					t.Fatalf("AutoStopIntervalMinutes = %+v, want %v", got.AutoStopIntervalMinutes, autoStop)
				}
				if got.AutoArchiveIntervalMinutes == nil || *got.AutoArchiveIntervalMinutes != autoArchive {
					t.Fatalf("AutoArchiveIntervalMinutes = %+v, want %v", got.AutoArchiveIntervalMinutes, autoArchive)
				}

				resolved, err := st.ResolveDaytonaSandboxID(ctx, meta.Name)
				if err != nil {
					t.Fatalf("ResolveDaytonaSandboxID() error = %v", err)
				}
				if resolved != sandbox.ID {
					t.Fatalf("resolved sandbox id = %q, want %q", resolved, sandbox.ID)
				}

				items, err := st.ListDaytonaMetadata(ctx)
				if err != nil {
					t.Fatalf("ListDaytonaMetadata() error = %v", err)
				}
				if listed, ok := items[sandbox.ID]; !ok || listed.Name != meta.Name {
					t.Fatalf("expected listed metadata for %q, got %+v", sandbox.ID, items)
				}
			},
		},
		{
			name: "daytona_metadata_name_conflict_returns_error",
			run: func(t *testing.T) {
				st := newTestStore(t)
				first := sampleSandbox("sb-daytona-first")
				second := sampleSandbox("sb-daytona-second")
				for _, sandbox := range []*models.Sandbox{first, second} {
					if err := st.Create(ctx, sandbox); err != nil {
						t.Fatalf("Create(%s) error = %v", sandbox.ID, err)
					}
				}
				if err := st.UpsertDaytonaMetadata(ctx, models.DaytonaSandboxMetadata{SandboxID: first.ID, Name: "shared-name"}); err != nil {
					t.Fatalf("first UpsertDaytonaMetadata() error = %v", err)
				}
				if err := st.UpsertDaytonaMetadata(ctx, models.DaytonaSandboxMetadata{SandboxID: second.ID, Name: "shared-name"}); !errors.Is(err, ErrDaytonaNameConflict) {
					t.Fatalf("expected ErrDaytonaNameConflict, got %v", err)
				}
			},
		},
		{
			name: "delete_sandbox_cascades_daytona_metadata",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-daytona-cascade")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := st.UpsertDaytonaMetadata(ctx, models.DaytonaSandboxMetadata{SandboxID: sandbox.ID, Name: "cascade-name"}); err != nil {
					t.Fatalf("UpsertDaytonaMetadata() error = %v", err)
				}
				if err := st.Delete(ctx, sandbox.ID); err != nil {
					t.Fatalf("Delete() error = %v", err)
				}
				if _, err := st.GetDaytonaMetadata(ctx, sandbox.ID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound after delete, got %v", err)
				}
				if _, err := st.ResolveDaytonaSandboxID(ctx, "cascade-name"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound from ResolveDaytonaSandboxID(), got %v", err)
				}
			},
		},
		{
			name: "e2b_sandbox_metadata_roundtrip",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-e2b")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				allowInternet := false
				allowPublic := true
				createdAt := time.Now().UTC().Add(-time.Minute)
				meta := models.E2BSandboxMetadata{
					SandboxID:           sandbox.ID,
					TemplateID:          "base",
					TemplateAlias:       "base",
					Metadata:            map[string]string{"team": "sdk"},
					TimeoutSeconds:      45,
					OnTimeout:           "pause",
					AutoResume:          true,
					Secure:              true,
					AllowInternetAccess: &allowInternet,
					NetworkAllowOut:     []string{"10.0.0.0/24"},
					NetworkDenyOut:      []string{"0.0.0.0/0"},
					AllowPublicTraffic:  &allowPublic,
					MaskRequestHost:     "sandbox.example.com",
					CreatedAt:           createdAt,
				}
				if err := st.UpsertE2BSandboxMetadata(ctx, meta); err != nil {
					t.Fatalf("UpsertE2BSandboxMetadata() error = %v", err)
				}

				got, err := st.GetE2BSandboxMetadata(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("GetE2BSandboxMetadata() error = %v", err)
				}
				if got.TemplateID != meta.TemplateID || got.TemplateAlias != meta.TemplateAlias || got.TimeoutSeconds != meta.TimeoutSeconds || got.OnTimeout != meta.OnTimeout || got.MaskRequestHost != meta.MaskRequestHost {
					t.Fatalf("unexpected e2b metadata: %+v", got)
				}
				if !reflect.DeepEqual(got.Metadata, meta.Metadata) {
					t.Fatalf("Metadata = %+v, want %+v", got.Metadata, meta.Metadata)
				}
				if !reflect.DeepEqual(got.NetworkAllowOut, meta.NetworkAllowOut) {
					t.Fatalf("NetworkAllowOut = %+v, want %+v", got.NetworkAllowOut, meta.NetworkAllowOut)
				}
				if !reflect.DeepEqual(got.NetworkDenyOut, meta.NetworkDenyOut) {
					t.Fatalf("NetworkDenyOut = %+v, want %+v", got.NetworkDenyOut, meta.NetworkDenyOut)
				}
				if got.AllowInternetAccess == nil || *got.AllowInternetAccess != allowInternet {
					t.Fatalf("AllowInternetAccess = %+v, want %v", got.AllowInternetAccess, allowInternet)
				}
				if got.AllowPublicTraffic == nil || *got.AllowPublicTraffic != allowPublic {
					t.Fatalf("AllowPublicTraffic = %+v, want %v", got.AllowPublicTraffic, allowPublic)
				}
				items, err := st.ListE2BSandboxMetadata(ctx)
				if err != nil {
					t.Fatalf("ListE2BSandboxMetadata() error = %v", err)
				}
				if listed, ok := items[sandbox.ID]; !ok || listed.TemplateID != meta.TemplateID {
					t.Fatalf("expected listed e2b metadata for %q, got %+v", sandbox.ID, items)
				}
			},
		},
		{
			name: "e2b_snapshot_metadata_roundtrip_and_delete",
			run: func(t *testing.T) {
				st := newTestStore(t)
				meta := models.E2BSnapshotMetadata{
					SnapshotID:      "snapshot-name:default",
					SnapshotName:    "snapshot-name",
					Names:           []string{"snapshot-name:default"},
					SourceSandboxID: "sb-1",
					CreatedAt:       time.Now().UTC(),
				}
				if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
					Name:            meta.SnapshotName,
					Image:           meta.SnapshotName,
					ImageID:         "sha256:e2b-snapshot",
					SourceSandboxID: meta.SourceSandboxID,
					CreatedAt:       meta.CreatedAt,
				}); err != nil {
					t.Fatalf("CreateSnapshot() error = %v", err)
				}
				if err := st.UpsertE2BSnapshot(ctx, meta); err != nil {
					t.Fatalf("UpsertE2BSnapshot() error = %v", err)
				}

				got, err := st.GetE2BSnapshot(ctx, meta.SnapshotID)
				if err != nil {
					t.Fatalf("GetE2BSnapshot() error = %v", err)
				}
				if got.SnapshotName != meta.SnapshotName || got.SourceSandboxID != meta.SourceSandboxID {
					t.Fatalf("unexpected e2b snapshot metadata: %+v", got)
				}
				if !reflect.DeepEqual(got.Names, meta.Names) {
					t.Fatalf("Names = %+v, want %+v", got.Names, meta.Names)
				}
				items, err := st.ListE2BSnapshots(ctx)
				if err != nil {
					t.Fatalf("ListE2BSnapshots() error = %v", err)
				}
				if listed, ok := items[meta.SnapshotID]; !ok || listed.SnapshotName != meta.SnapshotName {
					t.Fatalf("expected listed snapshot metadata for %q, got %+v", meta.SnapshotID, items)
				}
				if err := st.DeleteE2BSnapshot(ctx, meta.SnapshotID); err != nil {
					t.Fatalf("DeleteE2BSnapshot() error = %v", err)
				}
				if _, err := st.GetE2BSnapshot(ctx, meta.SnapshotID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound after delete, got %v", err)
				}
			},
		},
		{
			name: "e2b_snapshot_metadata_cascades_with_native_snapshot_delete",
			run: func(t *testing.T) {
				st := newTestStore(t)
				meta := models.E2BSnapshotMetadata{
					SnapshotID:      "snapshot-cascade:default",
					SnapshotName:    "snapshot-cascade",
					Names:           []string{"snapshot-cascade:default"},
					SourceSandboxID: "sb-cascade",
					CreatedAt:       time.Now().UTC(),
				}
				if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
					Name:            meta.SnapshotName,
					Image:           meta.SnapshotName,
					ImageID:         "sha256:e2b-cascade",
					SourceSandboxID: meta.SourceSandboxID,
					CreatedAt:       meta.CreatedAt,
				}); err != nil {
					t.Fatalf("CreateSnapshot() error = %v", err)
				}
				if err := st.UpsertE2BSnapshot(ctx, meta); err != nil {
					t.Fatalf("UpsertE2BSnapshot() error = %v", err)
				}
				if err := st.DeleteSnapshot(ctx, meta.SnapshotName); err != nil {
					t.Fatalf("DeleteSnapshot() error = %v", err)
				}
				if _, err := st.GetE2BSnapshot(ctx, meta.SnapshotID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected E2B snapshot metadata cascade delete, got %v", err)
				}
			},
		},
		{
			name: "e2b_create_request_claim_complete_and_reclaim",
			run: func(t *testing.T) {
				st := newTestStore(t)
				now := time.Now().UTC().Round(0)
				fingerprint := "fp:test"

				record, acquired, err := st.ClaimE2BCreateRequest(ctx, fingerprint, now, 30*time.Second)
				if err != nil {
					t.Fatalf("first ClaimE2BCreateRequest() error = %v", err)
				}
				if !acquired {
					t.Fatal("expected first claim to acquire reservation")
				}
				if record.State != models.E2BCreateRequestStatePending {
					t.Fatalf("record.State = %q, want %q", record.State, models.E2BCreateRequestStatePending)
				}

				record, acquired, err = st.ClaimE2BCreateRequest(ctx, fingerprint, now.Add(5*time.Second), 30*time.Second)
				if err != nil {
					t.Fatalf("second ClaimE2BCreateRequest() error = %v", err)
				}
				if acquired {
					t.Fatal("expected second claim to observe pending reservation")
				}
				if record.State != models.E2BCreateRequestStatePending {
					t.Fatalf("pending record.State = %q, want %q", record.State, models.E2BCreateRequestStatePending)
				}

				if err := st.CompleteE2BCreateRequest(ctx, fingerprint, "sb-e2b-claim", now.Add(8*time.Second), 15*time.Second); err != nil {
					t.Fatalf("CompleteE2BCreateRequest() error = %v", err)
				}

				record, acquired, err = st.ClaimE2BCreateRequest(ctx, fingerprint, now.Add(10*time.Second), 30*time.Second)
				if err != nil {
					t.Fatalf("ready ClaimE2BCreateRequest() error = %v", err)
				}
				if acquired {
					t.Fatal("expected ready claim to replay existing sandbox")
				}
				if record.State != models.E2BCreateRequestStateReady || record.SandboxID != "sb-e2b-claim" {
					t.Fatalf("unexpected ready record: %+v", record)
				}

				record, acquired, err = st.ClaimE2BCreateRequest(ctx, fingerprint, now.Add(40*time.Second), 30*time.Second)
				if err != nil {
					t.Fatalf("stale ready ClaimE2BCreateRequest() error = %v", err)
				}
				if !acquired {
					t.Fatal("expected stale ready record to be reclaimed")
				}
				if record.State != models.E2BCreateRequestStatePending || record.SandboxID != "" {
					t.Fatalf("unexpected reclaimed record: %+v", record)
				}

				if err := st.DeleteE2BCreateRequest(ctx, fingerprint); err != nil {
					t.Fatalf("DeleteE2BCreateRequest() error = %v", err)
				}
				if _, err := st.GetE2BCreateRequest(ctx, fingerprint); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound after delete, got %v", err)
				}
			},
		},
		{
			name: "e2b_create_request_concurrent_claims_share_pending_record",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "state.db")
				const contenders = 6
				stores := make([]*Store, 0, contenders)
				for i := 0; i < contenders; i++ {
					st, err := Open(path)
					if err != nil {
						t.Fatalf("Open(%d) error = %v", i, err)
					}
					defer st.Close()
					stores = append(stores, st)
				}

				start := make(chan struct{})
				var wg sync.WaitGroup
				var mu sync.Mutex
				var errs []error
				acquiredCount := 0
				for _, st := range stores {
					wg.Add(1)
					go func(st *Store) {
						defer wg.Done()
						<-start
						record, acquired, err := st.ClaimE2BCreateRequest(ctx, "fp:concurrent", time.Now().UTC(), time.Minute)
						mu.Lock()
						defer mu.Unlock()
						if err != nil {
							errs = append(errs, err)
							return
						}
						if record.State != models.E2BCreateRequestStatePending {
							errs = append(errs, fmt.Errorf("record.State = %q, want %q", record.State, models.E2BCreateRequestStatePending))
							return
						}
						if acquired {
							acquiredCount++
						}
					}(st)
				}
				close(start)
				wg.Wait()
				if len(errs) > 0 {
					t.Fatalf("concurrent ClaimE2BCreateRequest() errors = %v", errs)
				}
				if acquiredCount != 1 {
					t.Fatalf("acquired claims = %d, want 1", acquiredCount)
				}
			},
		},
		{
			name: "snapshot_roundtrip_by_name",
			run: func(t *testing.T) {
				st := newTestStore(t)
				snapshot := &models.SandboxSnapshot{
					Name:            "snapshots/demo:v1",
					Image:           "snapshots/demo:v1",
					ImageID:         "sha256:snap-1",
					SourceSandboxID: "sb-source",
					CreatedAt:       time.Now().UTC().Round(0),
				}
				if err := st.CreateSnapshot(ctx, snapshot); err != nil {
					t.Fatalf("CreateSnapshot() error = %v", err)
				}
				got, err := st.GetSnapshot(ctx, snapshot.Name)
				if err != nil {
					t.Fatalf("GetSnapshot() error = %v", err)
				}
				if !reflect.DeepEqual(got, snapshot) {
					t.Fatalf("snapshot = %+v, want %+v", got, snapshot)
				}
			},
		},
		{
			name: "snapshot_name_conflict_returns_error",
			run: func(t *testing.T) {
				st := newTestStore(t)
				first := &models.SandboxSnapshot{Name: "snapshots/shared:v1", Image: "snapshots/shared:v1", SourceSandboxID: "sb-one", CreatedAt: time.Now().UTC()}
				second := &models.SandboxSnapshot{Name: "snapshots/shared:v1", Image: "snapshots/shared:v1", SourceSandboxID: "sb-two", CreatedAt: time.Now().UTC()}
				if err := st.CreateSnapshot(ctx, first); err != nil {
					t.Fatalf("first CreateSnapshot() error = %v", err)
				}
				if err := st.CreateSnapshot(ctx, second); !errors.Is(err, ErrSnapshotNameConflict) {
					t.Fatalf("expected ErrSnapshotNameConflict, got %v", err)
				}
			},
		},
		{
			name: "snapshot_survives_source_sandbox_delete",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-snapshot-source")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				snapshot := &models.SandboxSnapshot{
					Name:            "snapshots/preserved:v1",
					Image:           "snapshots/preserved:v1",
					ImageID:         "sha256:snap-preserved",
					SourceSandboxID: sandbox.ID,
					CreatedAt:       time.Now().UTC(),
				}
				if err := st.CreateSnapshot(ctx, snapshot); err != nil {
					t.Fatalf("CreateSnapshot() error = %v", err)
				}
				if err := st.Delete(ctx, sandbox.ID); err != nil {
					t.Fatalf("Delete() error = %v", err)
				}
				got, err := st.GetSnapshot(ctx, snapshot.Name)
				if err != nil {
					t.Fatalf("GetSnapshot() after delete error = %v", err)
				}
				if got.SourceSandboxID != sandbox.ID || got.Image != snapshot.Image {
					t.Fatalf("unexpected snapshot after delete: %+v", got)
				}
			},
		},
		{
			name: "list_and_delete_snapshots",
			run: func(t *testing.T) {
				st := newTestStore(t)
				older := &models.SandboxSnapshot{
					Name:            "alpha",
					Image:           "snapshots/alpha:v1",
					ImageID:         "sha256:alpha",
					SourceSandboxID: "sb-alpha",
					CreatedAt:       time.Now().UTC().Add(-time.Hour).Round(0),
				}
				newer := &models.SandboxSnapshot{
					Name:            "beta",
					Image:           "snapshots/beta:v1",
					ImageID:         "sha256:beta",
					SourceSandboxID: "sb-beta",
					CreatedAt:       time.Now().UTC().Round(0),
				}
				if err := st.CreateSnapshot(ctx, older); err != nil {
					t.Fatalf("CreateSnapshot(older) error = %v", err)
				}
				if err := st.CreateSnapshot(ctx, newer); err != nil {
					t.Fatalf("CreateSnapshot(newer) error = %v", err)
				}

				items, err := st.ListSnapshots(ctx)
				if err != nil {
					t.Fatalf("ListSnapshots() error = %v", err)
				}
				if len(items) != 2 {
					t.Fatalf("len(ListSnapshots()) = %d, want 2", len(items))
				}
				if items[0].Name != newer.Name || items[1].Name != older.Name {
					t.Fatalf("unexpected snapshot order: %+v", items)
				}

				if err := st.DeleteSnapshot(ctx, newer.Name); err != nil {
					t.Fatalf("DeleteSnapshot() error = %v", err)
				}
				if _, err := st.GetSnapshot(ctx, newer.Name); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound after delete, got %v", err)
				}
				remaining, err := st.GetSnapshot(ctx, older.Name)
				if err != nil {
					t.Fatalf("GetSnapshot(older) error = %v", err)
				}
				if !reflect.DeepEqual(remaining, older) {
					t.Fatalf("remaining snapshot = %+v, want %+v", remaining, older)
				}
			},
		},
		{
			name: "try_reserve_host_port_distinguishes_pk_collision_from_host_port_collision",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sb := sampleSandbox("sb-tcp-idem")
				if err := st.Create(ctx, sb); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				now := time.Now().UTC()

				// Initial reservation succeeds.
				r, err := st.TryReserveHostPort(ctx, sb.ID, 5432, 37001, models.ExposedPortProtocolTCP, "tcp://host:37001", now)
				if err != nil {
					t.Fatalf("first reserve error = %v", err)
				}
				if !r.Reserved || r.Existing != nil {
					t.Fatalf("first reserve = %+v, want Reserved=true Existing=nil", r)
				}

				// Re-reserving the same (sandbox, container_port) with a fresh
				// host_port must surface the existing row, NOT look like a
				// host_port collision (which would make the allocator walk
				// the pool to exhaustion).
				r, err = st.TryReserveHostPort(ctx, sb.ID, 5432, 37002, models.ExposedPortProtocolTCP, "tcp://host:37002", now)
				if err != nil {
					t.Fatalf("re-reserve error = %v", err)
				}
				if r.Reserved {
					t.Fatalf("re-reserve unexpectedly inserted a duplicate row: %+v", r)
				}
				if r.Existing == nil {
					t.Fatal("re-reserve returned no Existing row; allocator would walk the pool")
				}
				if r.Existing.HostPort != 37001 || r.Existing.Protocol != models.ExposedPortProtocolTCP {
					t.Fatalf("Existing = %+v, want host_port=37001 protocol=tcp", r.Existing)
				}

				// A different (sandbox, container_port) racing for the same
				// host_port must look like a host_port collision (Existing
				// nil), so the allocator can retry with another candidate.
				other := sampleSandbox("sb-tcp-other")
				if err := st.Create(ctx, other); err != nil {
					t.Fatalf("Create(other) error = %v", err)
				}
				r, err = st.TryReserveHostPort(ctx, other.ID, 6379, 37001, models.ExposedPortProtocolTCP, "tcp://host:37001", now)
				if err != nil {
					t.Fatalf("collision reserve error = %v", err)
				}
				if r.Reserved {
					t.Fatal("collision reserve unexpectedly succeeded against taken host_port")
				}
				if r.Existing != nil {
					t.Fatalf("collision reserve returned Existing = %+v, want nil so caller retries", r.Existing)
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
