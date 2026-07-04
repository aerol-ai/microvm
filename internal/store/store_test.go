package store

import (
	"context"
	"database/sql"
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
			name: "durability_roundtrip_and_default",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-dur")
				sandbox.Durability = models.DurabilityEphemeral
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.Durability != models.DurabilityEphemeral {
					t.Fatalf("durability = %q, want %q", got.Durability, models.DurabilityEphemeral)
				}

				defaulted := sampleSandbox("sb-dur-default")
				if err := st.Create(ctx, defaulted); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				gotDefault, err := st.Get(ctx, defaulted.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if gotDefault.Durability != models.DurabilityPassivatable {
					t.Fatalf("default durability = %q, want %q", gotDefault.Durability, models.DurabilityPassivatable)
				}
			},
		},
		{
			name: "module_ref_roundtrip",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-wasm-mod")
				sandbox.Runtime = models.RuntimeWasm
				sandbox.ModuleRef = "hello.wasm"
				sandbox.ModuleDigest = "abc123"
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.ModuleRef != "hello.wasm" || got.ModuleDigest != "abc123" {
					t.Fatalf("module fields = %+v", got)
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
			// The Daytona facade lives outside this package, so this test
			// exercises the generic primitives it relies on with a
			// Daytona-shaped payload — name on the native row,
			// labels in tags_json, and the facade-private scraps
			// (snapshot, target, allow-list) inside sandbox_compat_state.
			name: "daytona_metadata_roundtrip_and_resolve_by_name",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-daytona")
				sandbox.Name = "workspace-alpha"
				sandbox.OSUser = "ubuntu"
				sandbox.Tags = map[string]string{"team": "sdk"}
				sandbox.Lifecycle = models.Lifecycle{StopIfIdleFor: 15 * time.Minute}
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				blob := `{"snapshot":"snapshot-123","target":"default","network_allow_list":"10.0.0.0/24","auto_archive_interval_minutes":60}`
				if err := st.UpsertCompatState(ctx, sandbox.ID, models.FacadeDaytona, blob); err != nil {
					t.Fatalf("UpsertCompatState() error = %v", err)
				}

				got, err := st.GetCompatState(ctx, sandbox.ID, models.FacadeDaytona)
				if err != nil {
					t.Fatalf("GetCompatState() error = %v", err)
				}
				if got.StateJSON != blob {
					t.Fatalf("StateJSON = %q, want %q", got.StateJSON, blob)
				}
				native, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if native.Name != "workspace-alpha" || native.OSUser != "ubuntu" {
					t.Fatalf("unexpected native fields: %+v", native)
				}
				if !reflect.DeepEqual(native.Tags, map[string]string{"team": "sdk"}) {
					t.Fatalf("Tags = %+v, want team=sdk", native.Tags)
				}
				if native.Lifecycle.StopIfIdleFor != 15*time.Minute {
					t.Fatalf("StopIfIdleFor = %v, want 15m", native.Lifecycle.StopIfIdleFor)
				}

				resolved, err := st.ResolveSandboxIDByName(ctx, "workspace-alpha")
				if err != nil {
					t.Fatalf("ResolveSandboxIDByName() error = %v", err)
				}
				if resolved != sandbox.ID {
					t.Fatalf("resolved sandbox id = %q, want %q", resolved, sandbox.ID)
				}

				items, err := st.ListCompatState(ctx, models.FacadeDaytona)
				if err != nil {
					t.Fatalf("ListCompatState() error = %v", err)
				}
				if listed, ok := items[sandbox.ID]; !ok || listed.StateJSON != blob {
					t.Fatalf("expected listed compat state for %q, got %+v", sandbox.ID, items)
				}
			},
		},
		{
			// Same Daytona-shape coverage: two sandboxes that try to claim
			// the same `name` must collide on the partial unique index now
			// that name lives natively, not on a per-facade table.
			name: "daytona_metadata_name_conflict_returns_error",
			run: func(t *testing.T) {
				st := newTestStore(t)
				first := sampleSandbox("sb-daytona-first")
				first.Name = "shared-name"
				second := sampleSandbox("sb-daytona-second")
				second.Name = "shared-name"
				if err := st.Create(ctx, first); err != nil {
					t.Fatalf("Create(first) error = %v", err)
				}
				if err := st.Create(ctx, second); !errors.Is(err, ErrSandboxNameConflict) {
					t.Fatalf("expected ErrSandboxNameConflict, got %v", err)
				}
			},
		},
		{
			// IDs and names share one lookup namespace. If a name can equal
			// another sandbox's id, resolve-by-id wins forever and the named
			// sandbox is shadowed. The store rejects that ambiguity directly.
			name: "sandbox_name_cannot_match_existing_id",
			run: func(t *testing.T) {
				st := newTestStore(t)
				existing := sampleSandbox("claimed-name")
				existing.Name = "unrelated"
				if err := st.Create(ctx, existing); err != nil {
					t.Fatalf("Create(existing) error = %v", err)
				}

				candidate := sampleSandbox("sb-name-vs-id")
				candidate.Name = "claimed-name"
				if err := st.Create(ctx, candidate); !errors.Is(err, ErrSandboxNameConflict) {
					t.Fatalf("expected ErrSandboxNameConflict, got %v", err)
				}
			},
		},
		{
			// The inverse matters too for callers that supply their own IDs:
			// a new sandbox id must not steal an existing sandbox's name.
			name: "sandbox_id_cannot_match_existing_name",
			run: func(t *testing.T) {
				st := newTestStore(t)
				existing := sampleSandbox("sb-existing-name-owner")
				existing.Name = "reserved-lookup"
				if err := st.Create(ctx, existing); err != nil {
					t.Fatalf("Create(existing) error = %v", err)
				}

				candidate := sampleSandbox("reserved-lookup")
				if err := st.Create(ctx, candidate); !errors.Is(err, ErrSandboxNameConflict) {
					t.Fatalf("expected ErrSandboxNameConflict, got %v", err)
				}
			},
		},
		{
			name: "upsert_name_cannot_match_existing_id",
			run: func(t *testing.T) {
				st := newTestStore(t)
				existing := sampleSandbox("upsert-claimed-name")
				if err := st.Create(ctx, existing); err != nil {
					t.Fatalf("Create(existing) error = %v", err)
				}

				candidate := sampleSandbox("sb-upsert-name-vs-id")
				candidate.Name = "upsert-claimed-name"
				if err := st.Upsert(ctx, candidate); !errors.Is(err, ErrSandboxNameConflict) {
					t.Fatalf("expected ErrSandboxNameConflict, got %v", err)
				}
			},
		},
		{
			// FK CASCADE on sandbox_compat_state means deleting the native
			// sandbox row drops the Daytona compat blob too. ResolveSandboxIDByName
			// then misses because the unique-name index lives on the native
			// row that just went away.
			name: "delete_sandbox_cascades_daytona_metadata",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-daytona-cascade")
				sandbox.Name = "cascade-name"
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := st.UpsertCompatState(ctx, sandbox.ID, models.FacadeDaytona, `{"target":"default"}`); err != nil {
					t.Fatalf("UpsertCompatState() error = %v", err)
				}
				if err := st.Delete(ctx, sandbox.ID); err != nil {
					t.Fatalf("Delete() error = %v", err)
				}
				if _, err := st.GetCompatState(ctx, sandbox.ID, models.FacadeDaytona); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound after delete, got %v", err)
				}
				if _, err := st.ResolveSandboxIDByName(ctx, "cascade-name"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound from ResolveSandboxIDByName(), got %v", err)
				}
			},
		},
		{
			// E2B-shape coverage: native fields (tags_json, NetworkBlockAll,
			// Lifecycle) carry what AerolVM has equivalents for; the rest
			// (template_id, secure, on_timeout, mask_request_host, etc.)
			// rides inside the facade's compat blob — same partition the
			// E2B handlers use at runtime.
			name: "e2b_sandbox_metadata_roundtrip",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-e2b")
				sandbox.Tags = map[string]string{"team": "sdk"}
				sandbox.NetworkBlockAll = true
				sandbox.Lifecycle = models.Lifecycle{StopAtAge: 45 * time.Second}
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				blob := `{"template_id":"base","template_alias":"base","on_timeout":"pause","auto_resume":true,"secure":true,"network_allow_out":["10.0.0.0/24"],"network_deny_out":["0.0.0.0/0"],"allow_public_traffic":true,"mask_request_host":"sandbox.example.com"}`
				if err := st.UpsertCompatState(ctx, sandbox.ID, models.FacadeE2B, blob); err != nil {
					t.Fatalf("UpsertCompatState() error = %v", err)
				}

				got, err := st.GetCompatState(ctx, sandbox.ID, models.FacadeE2B)
				if err != nil {
					t.Fatalf("GetCompatState() error = %v", err)
				}
				if got.StateJSON != blob {
					t.Fatalf("StateJSON = %q, want %q", got.StateJSON, blob)
				}
				native, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if !reflect.DeepEqual(native.Tags, map[string]string{"team": "sdk"}) {
					t.Fatalf("Tags = %+v, want team=sdk", native.Tags)
				}
				if !native.NetworkBlockAll {
					t.Fatal("expected NetworkBlockAll=true")
				}
				if native.Lifecycle.StopAtAge != 45*time.Second {
					t.Fatalf("Lifecycle.StopAtAge = %v, want 45s", native.Lifecycle.StopAtAge)
				}
				items, err := st.ListCompatState(ctx, models.FacadeE2B)
				if err != nil {
					t.Fatalf("ListCompatState() error = %v", err)
				}
				if listed, ok := items[sandbox.ID]; !ok || listed.StateJSON != blob {
					t.Fatalf("expected listed e2b compat state for %q, got %+v", sandbox.ID, items)
				}
			},
		},
		{
			// E2B's snapshot tokens are facade-shaped aliases for native
			// sandbox_snapshots rows. The generic snapshot_aliases table
			// holds the mapping; the native row is authoritative.
			name: "e2b_snapshot_metadata_roundtrip_and_delete",
			run: func(t *testing.T) {
				st := newTestStore(t)
				createdAt := time.Now().UTC()
				snapshotName := "snapshot-name"
				aliasID := "snapshot-name:default"
				if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
					Name:            snapshotName,
					Image:           snapshotName,
					ImageID:         "sha256:e2b-snapshot",
					SourceSandboxID: "sb-1",
					CreatedAt:       createdAt,
				}); err != nil {
					t.Fatalf("CreateSnapshot() error = %v", err)
				}
				alias := models.SnapshotAlias{
					Alias:        aliasID,
					SnapshotName: snapshotName,
					Facade:       models.FacadeE2B,
					ExtraNames:   []string{aliasID},
					CreatedAt:    createdAt,
				}
				if err := st.UpsertSnapshotAlias(ctx, alias); err != nil {
					t.Fatalf("UpsertSnapshotAlias() error = %v", err)
				}

				got, err := st.GetSnapshotAlias(ctx, aliasID)
				if err != nil {
					t.Fatalf("GetSnapshotAlias() error = %v", err)
				}
				if got.SnapshotName != snapshotName || got.Facade != models.FacadeE2B {
					t.Fatalf("unexpected snapshot alias: %+v", got)
				}
				if !reflect.DeepEqual(got.ExtraNames, []string{aliasID}) {
					t.Fatalf("ExtraNames = %+v, want %+v", got.ExtraNames, []string{aliasID})
				}
				items, err := st.ListSnapshotAliases(ctx, models.FacadeE2B)
				if err != nil {
					t.Fatalf("ListSnapshotAliases() error = %v", err)
				}
				if listed, ok := items[aliasID]; !ok || listed.SnapshotName != snapshotName {
					t.Fatalf("expected listed alias for %q, got %+v", aliasID, items)
				}
				if err := st.DeleteSnapshotAlias(ctx, aliasID); err != nil {
					t.Fatalf("DeleteSnapshotAlias() error = %v", err)
				}
				if _, err := st.GetSnapshotAlias(ctx, aliasID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound after delete, got %v", err)
				}
			},
		},
		{
			// Deleting the native snapshot row must cascade through to
			// snapshot_aliases — same parity the old per-facade table
			// promised, now enforced by the FK on snapshot_aliases.
			name: "e2b_snapshot_metadata_cascades_with_native_snapshot_delete",
			run: func(t *testing.T) {
				st := newTestStore(t)
				createdAt := time.Now().UTC()
				snapshotName := "snapshot-cascade"
				aliasID := "snapshot-cascade:default"
				if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{
					Name:            snapshotName,
					Image:           snapshotName,
					ImageID:         "sha256:e2b-cascade",
					SourceSandboxID: "sb-cascade",
					CreatedAt:       createdAt,
				}); err != nil {
					t.Fatalf("CreateSnapshot() error = %v", err)
				}
				if err := st.UpsertSnapshotAlias(ctx, models.SnapshotAlias{
					Alias:        aliasID,
					SnapshotName: snapshotName,
					Facade:       models.FacadeE2B,
					ExtraNames:   []string{aliasID},
					CreatedAt:    createdAt,
				}); err != nil {
					t.Fatalf("UpsertSnapshotAlias() error = %v", err)
				}
				if err := st.DeleteSnapshot(ctx, snapshotName); err != nil {
					t.Fatalf("DeleteSnapshot() error = %v", err)
				}
				if _, err := st.GetSnapshotAlias(ctx, aliasID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected snapshot alias cascade delete, got %v", err)
				}
			},
		},
		{
			// Same end-to-end shape the E2B create handler relies on,
			// expressed against the generic primitive: claim → observe
			// pending → complete → replay ready → stale-reclaim → delete.
			// The only thing E2B-specific here is the scope string.
			name: "e2b_create_request_claim_complete_and_reclaim",
			run: func(t *testing.T) {
				st := newTestStore(t)
				now := time.Now().UTC().Round(0)
				const scope = "e2b.create"
				fingerprint := "fp:test"

				record, acquired, err := st.ClaimIdempotentRequest(ctx, scope, fingerprint, now, 30*time.Second)
				if err != nil {
					t.Fatalf("first ClaimIdempotentRequest() error = %v", err)
				}
				if !acquired {
					t.Fatal("expected first claim to acquire reservation")
				}
				if record.State != models.RequestStatePending {
					t.Fatalf("record.State = %q, want %q", record.State, models.RequestStatePending)
				}

				record, acquired, err = st.ClaimIdempotentRequest(ctx, scope, fingerprint, now.Add(5*time.Second), 30*time.Second)
				if err != nil {
					t.Fatalf("second ClaimIdempotentRequest() error = %v", err)
				}
				if acquired {
					t.Fatal("expected second claim to observe pending reservation")
				}
				if record.State != models.RequestStatePending {
					t.Fatalf("pending record.State = %q, want %q", record.State, models.RequestStatePending)
				}

				if err := st.CompleteIdempotentRequest(ctx, scope, fingerprint, "sb-e2b-claim", now.Add(8*time.Second), 15*time.Second); err != nil {
					t.Fatalf("CompleteIdempotentRequest() error = %v", err)
				}

				record, acquired, err = st.ClaimIdempotentRequest(ctx, scope, fingerprint, now.Add(10*time.Second), 30*time.Second)
				if err != nil {
					t.Fatalf("ready ClaimIdempotentRequest() error = %v", err)
				}
				if acquired {
					t.Fatal("expected ready claim to replay existing sandbox")
				}
				if record.State != models.RequestStateReady || record.TargetID != "sb-e2b-claim" {
					t.Fatalf("unexpected ready record: %+v", record)
				}

				record, acquired, err = st.ClaimIdempotentRequest(ctx, scope, fingerprint, now.Add(40*time.Second), 30*time.Second)
				if err != nil {
					t.Fatalf("stale ready ClaimIdempotentRequest() error = %v", err)
				}
				if !acquired {
					t.Fatal("expected stale ready record to be reclaimed")
				}
				if record.State != models.RequestStatePending || record.TargetID != "" {
					t.Fatalf("unexpected reclaimed record: %+v", record)
				}

				if err := st.DeleteIdempotentRequest(ctx, scope, fingerprint); err != nil {
					t.Fatalf("DeleteIdempotentRequest() error = %v", err)
				}
				if _, err := st.GetIdempotentRequest(ctx, scope, fingerprint); !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound after delete, got %v", err)
				}
			},
		},
		{
			// Concurrent dedupe regression for the E2B create path: many
			// processes racing to insert the same (scope, fingerprint) row
			// must converge on exactly one acquired claim.
			name: "e2b_create_request_concurrent_claims_share_pending_record",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "state.db")
				const contenders = 6
				const scope = "e2b.create"
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
						record, acquired, err := st.ClaimIdempotentRequest(ctx, scope, "fp:concurrent", time.Now().UTC(), time.Minute)
						mu.Lock()
						defer mu.Unlock()
						if err != nil {
							errs = append(errs, err)
							return
						}
						if record.State != models.RequestStatePending {
							errs = append(errs, fmt.Errorf("record.State = %q, want %q", record.State, models.RequestStatePending))
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
					t.Fatalf("concurrent ClaimIdempotentRequest() errors = %v", errs)
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
				verifiedAt := time.Now().UTC().Round(0)
				snapshot := &models.SandboxSnapshot{
					Name:                  "snapshots/demo:v1",
					Image:                 "registry.example.com/demo@sha256:abc",
					ImageID:               "sha256:snap-1",
					SourceSandboxID:       "sb-source",
					CreatedAt:             time.Now().UTC().Round(0),
					ImageDistributionMode: models.ImageDistributionExternalRegistry,
					ImageDigest:           "sha256:abc",
					ImageRegistryRef:      "registry.example.com/demo@sha256:abc",
					ImageVerifiedAt:       &verifiedAt,
					// Mirror what CreateSnapshot writes when push_state is
					// unset: schema default is 'active', so a read-back will
					// have it filled in even though the input did not.
					PushState: models.SnapshotPushStateActive,
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
					PushState:       models.SnapshotPushStateActive,
				}
				newer := &models.SandboxSnapshot{
					Name:            "beta",
					Image:           "snapshots/beta:v1",
					ImageID:         "sha256:beta",
					SourceSandboxID: "sb-beta",
					CreatedAt:       time.Now().UTC().Round(0),
					PushState:       models.SnapshotPushStateActive,
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
			name: "failover_policy_persists_through_create_and_get",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-failover")
				sandbox.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.Failover == nil || got.Failover.Policy != models.FailoverPolicyRecreate {
					t.Fatalf("Failover roundtrip mismatch: got %+v", got.Failover)
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
			// Round-trip: Lifecycle.Serverless on the model lands in the
			// serverless column and decodes back identically. Guards the
			// boolean conversion at both ends of the Create/Get path.
			name: "create_and_get_round_trips_serverless",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-serverless")
				sandbox.Lifecycle = models.Lifecycle{
					StopIfIdleFor: 5 * time.Minute,
					Serverless:    true,
				}
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if !got.Lifecycle.Serverless {
					t.Fatalf("Lifecycle.Serverless = false, want true (round-trip)")
				}
				if got.Lifecycle.StopIfIdleFor != 5*time.Minute {
					t.Fatalf("StopIfIdleFor mismatch: got %v want %v", got.Lifecycle.StopIfIdleFor, 5*time.Minute)
				}
				if got.WakeArmed {
					t.Fatalf("WakeArmed = true on fresh create, want false")
				}
			},
		},
		{
			// UpdateLifecycle full-replace semantics include the
			// serverless field. wake_armed must NOT be touched: it
			// transitions on stop/wake events, not on lifecycle edits.
			name: "update_lifecycle_replaces_serverless_preserves_wake_armed",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-update-serverless")
				sandbox.Lifecycle = models.Lifecycle{
					StopIfIdleFor: time.Hour,
					Serverless:    true,
				}
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := st.SetWakeArmed(ctx, sandbox.ID, true); err != nil {
					t.Fatalf("SetWakeArmed() error = %v", err)
				}
				// Replace the lifecycle: drop serverless and clear idle
				// timer. wake_armed should survive untouched.
				if err := st.UpdateLifecycle(ctx, sandbox.ID, models.Lifecycle{
					DestroyAtAge: 24 * time.Hour,
				}); err != nil {
					t.Fatalf("UpdateLifecycle() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.Lifecycle.Serverless {
					t.Fatalf("Lifecycle.Serverless = true after replace, want false")
				}
				if !got.WakeArmed {
					t.Fatalf("WakeArmed should not be cleared by UpdateLifecycle")
				}
			},
		},
		{
			// SetWakeArmed toggles independently of Upsert so a stop
			// event and a runtime-state-machine update on the row do
			// not race. Round-trip both directions.
			name: "set_wake_armed_toggles_independently",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-wake-toggle")
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if err := st.SetWakeArmed(ctx, sandbox.ID, true); err != nil {
					t.Fatalf("SetWakeArmed(true) error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if !got.WakeArmed {
					t.Fatalf("WakeArmed = false after SetWakeArmed(true)")
				}
				if err := st.SetWakeArmed(ctx, sandbox.ID, false); err != nil {
					t.Fatalf("SetWakeArmed(false) error = %v", err)
				}
				got, err = st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.WakeArmed {
					t.Fatalf("WakeArmed = true after SetWakeArmed(false)")
				}
			},
		},
		{
			name: "set_wake_armed_returns_not_found_for_missing_id",
			run: func(t *testing.T) {
				st := newTestStore(t)
				err := st.SetWakeArmed(ctx, "missing", true)
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound, got %v", err)
				}
			},
		},
		{
			// The expose_port opt-in flips flag and public_url in ONE
			// statement — a Get must never observe one moved without the
			// other, or reachability is misreported.
			name: "set_allow_public_traffic_moves_flag_and_url_together",
			run: func(t *testing.T) {
				st := newTestStore(t)
				sandbox := sampleSandbox("sb-flip-public")
				deny := false
				sandbox.AllowPublicTraffic = &deny
				sandbox.PublicURL = ""
				if err := st.Create(ctx, sandbox); err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				const url = "https://sb-flip-public.sandbox.test"
				if err := st.SetAllowPublicTraffic(ctx, sandbox.ID, true, url); err != nil {
					t.Fatalf("SetAllowPublicTraffic() error = %v", err)
				}
				got, err := st.Get(ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("Get() error = %v", err)
				}
				if got.AllowPublicTraffic == nil || !*got.AllowPublicTraffic {
					t.Fatalf("AllowPublicTraffic = %v after flip, want explicit true", got.AllowPublicTraffic)
				}
				if got.PublicURL != url {
					t.Fatalf("PublicURL = %q after flip, want %q", got.PublicURL, url)
				}
			},
		},
		{
			name: "set_allow_public_traffic_returns_not_found_for_missing_id",
			run: func(t *testing.T) {
				st := newTestStore(t)
				err := st.SetAllowPublicTraffic(ctx, "missing", true, "https://missing.sandbox.test")
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
		{
			name: "pending_image_gc_upsert_refreshes_scheduled_at",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "state.db")
				st, err := Open(path)
				if err != nil {
					t.Fatalf("Open() error = %v", err)
				}
				defer st.Close()

				early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
				later := early.Add(2 * time.Hour)

				if err := st.SchedulePendingImageGC(ctx, "img:1", early); err != nil {
					t.Fatalf("schedule early: %v", err)
				}
				if err := st.SchedulePendingImageGC(ctx, "img:1", later); err != nil {
					t.Fatalf("schedule later: %v", err)
				}

				// Cutoff between the two: must NOT return the row, because
				// the upsert refreshed scheduled_at to `later`.
				between := early.Add(time.Hour)
				due, err := st.ListPendingImageGCDue(ctx, between, 0)
				if err != nil {
					t.Fatalf("ListPendingImageGCDue() error = %v", err)
				}
				if len(due) != 0 {
					t.Fatalf("expected no due rows after upsert refresh, got %v", due)
				}

				// Cutoff after later: row is due and returns the refreshed timestamp.
				due, err = st.ListPendingImageGCDue(ctx, later.Add(time.Minute), 0)
				if err != nil {
					t.Fatalf("ListPendingImageGCDue() error = %v", err)
				}
				if len(due) != 1 || due[0].Image != "img:1" {
					t.Fatalf("expected [img:1], got %v", due)
				}
				if !due[0].ScheduledAt.Equal(later) {
					t.Fatalf("scheduled_at = %v, want refreshed %v", due[0].ScheduledAt, later)
				}
			},
		},
		{
			name: "pending_image_gc_list_honors_cutoff_and_ordering",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "state.db")
				st, err := Open(path)
				if err != nil {
					t.Fatalf("Open() error = %v", err)
				}
				defer st.Close()

				base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
				rows := []struct {
					image string
					at    time.Time
				}{
					{"img:newest", base.Add(30 * time.Minute)},
					{"img:oldest", base},
					{"img:middle", base.Add(15 * time.Minute)},
					{"img:future", base.Add(2 * time.Hour)},
				}
				for _, r := range rows {
					if err := st.SchedulePendingImageGC(ctx, r.image, r.at); err != nil {
						t.Fatalf("schedule %s: %v", r.image, err)
					}
				}

				due, err := st.ListPendingImageGCDue(ctx, base.Add(time.Hour), 0)
				if err != nil {
					t.Fatalf("ListPendingImageGCDue() error = %v", err)
				}
				want := []string{"img:oldest", "img:middle", "img:newest"}
				if len(due) != len(want) {
					t.Fatalf("got %v, want %v", due, want)
				}
				for i := range want {
					if due[i].Image != want[i] {
						t.Fatalf("position %d: got %q want %q (full=%v)", i, due[i].Image, want[i], due)
					}
				}
			},
		},
		{
			name: "pending_image_gc_delete_is_idempotent",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "state.db")
				st, err := Open(path)
				if err != nil {
					t.Fatalf("Open() error = %v", err)
				}
				defer st.Close()

				when := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
				if err := st.SchedulePendingImageGC(ctx, "img:1", when); err != nil {
					t.Fatalf("schedule: %v", err)
				}
				if err := st.DeletePendingImageGC(ctx, "img:1"); err != nil {
					t.Fatalf("first delete: %v", err)
				}
				if err := st.DeletePendingImageGC(ctx, "img:1"); err != nil {
					t.Fatalf("second delete: %v", err)
				}
				if err := st.DeletePendingImageGC(ctx, "img:never-scheduled"); err != nil {
					t.Fatalf("delete missing: %v", err)
				}
				if err := st.DeletePendingImageGC(ctx, ""); err != nil {
					t.Fatalf("delete empty: %v", err)
				}

				due, err := st.ListPendingImageGCDue(ctx, when.Add(time.Hour), 0)
				if err != nil {
					t.Fatalf("ListPendingImageGCDue() error = %v", err)
				}
				if len(due) != 0 {
					t.Fatalf("expected empty after delete, got %v", due)
				}
			},
		},
		{
			// LIMIT must clip the batch and prefer the oldest rows so a
			// big backlog drains across ticks (oldest first) instead of
			// fanning out into one huge sweep.
			name: "pending_image_gc_list_honors_limit",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "state.db")
				st, err := Open(path)
				if err != nil {
					t.Fatalf("Open() error = %v", err)
				}
				defer st.Close()

				base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
				for i := 0; i < 10; i++ {
					img := fmt.Sprintf("img:%02d", i)
					if err := st.SchedulePendingImageGC(ctx, img, base.Add(time.Duration(i)*time.Minute)); err != nil {
						t.Fatalf("schedule %s: %v", img, err)
					}
				}

				due, err := st.ListPendingImageGCDue(ctx, base.Add(time.Hour), 3)
				if err != nil {
					t.Fatalf("ListPendingImageGCDue(limit=3) error = %v", err)
				}
				if len(due) != 3 {
					t.Fatalf("expected 3 rows with limit=3, got %d (%v)", len(due), due)
				}
				want := []string{"img:00", "img:01", "img:02"}
				for i, w := range want {
					if due[i].Image != w {
						t.Fatalf("limit batch[%d] = %q, want %q (full=%v)", i, due[i].Image, w, due)
					}
				}

				// limit=0 == unbounded.
				due, err = st.ListPendingImageGCDue(ctx, base.Add(time.Hour), 0)
				if err != nil {
					t.Fatalf("ListPendingImageGCDue(limit=0) error = %v", err)
				}
				if len(due) != 10 {
					t.Fatalf("limit=0 must be unbounded, got %d", len(due))
				}
			},
		},
		{
			// Refresh-race guard: the conditional delete must match the
			// row's scheduled_at exactly. If a destroy upserted a fresh
			// timestamp between list and delete, the old delete must
			// become a no-op so the new TTL survives.
			name: "pending_image_gc_conditional_delete_matches_scheduled_at",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "state.db")
				st, err := Open(path)
				if err != nil {
					t.Fatalf("Open() error = %v", err)
				}
				defer st.Close()

				orig := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
				refreshed := orig.Add(time.Hour)
				if err := st.SchedulePendingImageGC(ctx, "img:1", orig); err != nil {
					t.Fatalf("schedule orig: %v", err)
				}

				// No refresh yet — conditional delete on the observed
				// timestamp must succeed.
				ok, err := st.DeletePendingImageGCIfScheduledAt(ctx, "img:1", orig)
				if err != nil {
					t.Fatalf("conditional delete: %v", err)
				}
				if !ok {
					t.Fatalf("expected delete to match the unrefreshed row")
				}

				// Re-seed and simulate a destroy that refreshed the row
				// after we read it. Conditional delete on the stale
				// timestamp must NOT remove the freshly-extended row.
				if err := st.SchedulePendingImageGC(ctx, "img:1", orig); err != nil {
					t.Fatalf("re-schedule orig: %v", err)
				}
				if err := st.SchedulePendingImageGC(ctx, "img:1", refreshed); err != nil {
					t.Fatalf("refresh: %v", err)
				}
				ok, err = st.DeletePendingImageGCIfScheduledAt(ctx, "img:1", orig)
				if err != nil {
					t.Fatalf("conditional delete after refresh: %v", err)
				}
				if ok {
					t.Fatalf("refreshed row must survive a stale conditional delete")
				}
				// Row still present at the refreshed timestamp.
				due, err := st.ListPendingImageGCDue(ctx, refreshed.Add(time.Minute), 0)
				if err != nil {
					t.Fatalf("list after stale delete: %v", err)
				}
				if len(due) != 1 || !due[0].ScheduledAt.Equal(refreshed) {
					t.Fatalf("expected one row at refreshed ts, got %v", due)
				}

				// Empty image and missing image are no-ops.
				if ok, err := st.DeletePendingImageGCIfScheduledAt(ctx, "", orig); err != nil || ok {
					t.Fatalf("empty image: ok=%v err=%v", ok, err)
				}
				if ok, err := st.DeletePendingImageGCIfScheduledAt(ctx, "img:never", orig); err != nil || ok {
					t.Fatalf("missing image: ok=%v err=%v", ok, err)
				}
			},
		},
		{
			// RefreshPendingImageGCIfExists is UPDATE-only. A fresh
			// create from the service layer must NOT cause an insert,
			// otherwise pending_image_gc would balloon to one row per
			// image ever used.
			name: "pending_image_gc_refresh_only_updates_existing_rows",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "state.db")
				st, err := Open(path)
				if err != nil {
					t.Fatalf("Open() error = %v", err)
				}
				defer st.Close()

				// No row yet — refresh must report nothing touched and
				// must not insert anything.
				ok, err := st.RefreshPendingImageGCIfExists(ctx, "img:1", time.Now().UTC())
				if err != nil {
					t.Fatalf("refresh missing: %v", err)
				}
				if ok {
					t.Fatalf("refresh on missing row must report false")
				}
				due, err := st.ListPendingImageGCDue(ctx, time.Now().UTC().Add(time.Hour), 0)
				if err != nil {
					t.Fatalf("list after empty refresh: %v", err)
				}
				if len(due) != 0 {
					t.Fatalf("refresh must not insert, got %v", due)
				}

				// Seed an old row; refresh moves scheduled_at forward.
				orig := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
				pushed := orig.Add(2 * time.Hour)
				if err := st.SchedulePendingImageGC(ctx, "img:1", orig); err != nil {
					t.Fatalf("seed: %v", err)
				}
				ok, err = st.RefreshPendingImageGCIfExists(ctx, "img:1", pushed)
				if err != nil {
					t.Fatalf("refresh existing: %v", err)
				}
				if !ok {
					t.Fatalf("refresh on existing row must report true")
				}
				due, err = st.ListPendingImageGCDue(ctx, pushed.Add(time.Minute), 0)
				if err != nil {
					t.Fatalf("list after refresh: %v", err)
				}
				if len(due) != 1 || !due[0].ScheduledAt.Equal(pushed) {
					t.Fatalf("scheduled_at = %v, want pushed = %v (got %v)", due[0].ScheduledAt, pushed, due)
				}

				// Empty image is a no-op.
				if ok, err := st.RefreshPendingImageGCIfExists(ctx, "", time.Now().UTC()); err != nil || ok {
					t.Fatalf("empty refresh: ok=%v err=%v", ok, err)
				}
			},
		},
		{
			name: "pending_image_gc_schedule_empty_image_noop",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "state.db")
				st, err := Open(path)
				if err != nil {
					t.Fatalf("Open() error = %v", err)
				}
				defer st.Close()

				if err := st.SchedulePendingImageGC(ctx, "", time.Now().UTC()); err != nil {
					t.Fatalf("schedule empty: %v", err)
				}
				due, err := st.ListPendingImageGCDue(ctx, time.Now().UTC().Add(time.Hour), 0)
				if err != nil {
					t.Fatalf("ListPendingImageGCDue() error = %v", err)
				}
				if len(due) != 0 {
					t.Fatalf("empty image must not insert a row, got %v", due)
				}
			},
		},
		// Regression: the firecracker_tap_pool partial unique index on
		// sandbox_id is the load-bearing primitive for the Firecracker
		// boot path's idempotency (see pr-review.md §5 and
		// plans/snapshot-clone-fast-boot.md). The shape mirrors the
		// host_port index — any change to the schema or to
		// AllocateFirecrackerTapSlot must re-run these cases AND the
		// surrounding TryReserveHostPort regression next to it.
		{
			name: "firecracker_tap_pool_seed_is_idempotent",
			run: func(t *testing.T) {
				st := newTestStore(t)
				now := time.Now().UTC()
				slot := FirecrackerTapSlot{
					TapName: "fctap0", CIDR: "172.16.0.0/30",
					HostIP: "172.16.0.1", GuestIP: "172.16.0.2", VsockCID: 3,
				}
				if err := st.SeedFirecrackerTapSlot(ctx, slot, now); err != nil {
					t.Fatalf("first seed: %v", err)
				}
				// Re-seeding the same tap_name must be a no-op (no error,
				// no duplicate row).
				if err := st.SeedFirecrackerTapSlot(ctx, slot, now); err != nil {
					t.Fatalf("re-seed: %v", err)
				}
				stats, err := st.GetFirecrackerTapPoolStats(ctx)
				if err != nil {
					t.Fatalf("stats: %v", err)
				}
				if stats.Total != 1 {
					t.Fatalf("Total = %d after duplicate seed, want 1", stats.Total)
				}
			},
		},
		{
			name: "firecracker_tap_pool_rejects_reserved_vsock_cid",
			run: func(t *testing.T) {
				st := newTestStore(t)
				err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
					TapName: "fctap0", CIDR: "172.16.0.0/30",
					HostIP: "172.16.0.1", GuestIP: "172.16.0.2", VsockCID: 2,
				}, time.Now().UTC())
				if err == nil {
					t.Fatal("expected error for reserved vsock_cid<3")
				}
			},
		},
		{
			name: "firecracker_tap_pool_rejects_duplicate_vsock_cid",
			run: func(t *testing.T) {
				st := newTestStore(t)
				now := time.Now().UTC()
				if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
					TapName: "fctap0", CIDR: "172.16.0.0/30",
					HostIP: "172.16.0.1", GuestIP: "172.16.0.2", VsockCID: 3,
				}, now); err != nil {
					t.Fatalf("seed slot 0: %v", err)
				}
				// Same vsock_cid on a different tap_name must trip the
				// unique index. SQLite's single-writer model serializes
				// the seed loop; this is just defense-in-depth.
				err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
					TapName: "fctap1", CIDR: "172.16.0.4/30",
					HostIP: "172.16.0.5", GuestIP: "172.16.0.6", VsockCID: 3,
				}, now)
				if err == nil {
					t.Fatal("expected unique-index violation for duplicate vsock_cid")
				}
			},
		},
		{
			name: "firecracker_tap_pool_allocate_release_round_trip",
			run: func(t *testing.T) {
				st := newTestStore(t)
				now := time.Now().UTC()
				for i, cid := range []uint32{3, 4, 5} {
					if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
						TapName:  "fctap" + iToStr(i),
						CIDR:     "172.16." + iToStr(i) + ".0/30",
						HostIP:   "172.16." + iToStr(i) + ".1",
						GuestIP:  "172.16." + iToStr(i) + ".2",
						VsockCID: cid,
					}, now); err != nil {
						t.Fatalf("seed slot %d: %v", i, err)
					}
				}
				sb := sampleSandbox("sb-fc-alloc")
				if err := st.Create(ctx, sb); err != nil {
					t.Fatalf("create sandbox: %v", err)
				}
				slot, err := st.AllocateFirecrackerTapSlot(ctx, sb.ID, now)
				if err != nil {
					t.Fatalf("allocate: %v", err)
				}
				if slot.TapName == "" || slot.SandboxID != sb.ID {
					t.Fatalf("allocated slot = %+v", slot)
				}

				// Idempotency: re-allocate for the same sandbox returns
				// the same slot, not a second one.
				again, err := st.AllocateFirecrackerTapSlot(ctx, sb.ID, now)
				if err != nil {
					t.Fatalf("re-allocate: %v", err)
				}
				if again.TapName != slot.TapName {
					t.Fatalf("re-allocate returned a different slot: %s vs %s", again.TapName, slot.TapName)
				}

				// GetFirecrackerTapSlotBySandbox sees it.
				got, err := st.GetFirecrackerTapSlotBySandbox(ctx, sb.ID)
				if err != nil || got == nil {
					t.Fatalf("get: %v / %+v", err, got)
				}
				if got.TapName != slot.TapName {
					t.Fatalf("get returned %s, want %s", got.TapName, slot.TapName)
				}

				// Release returns the slot to the pool.
				if err := st.ReleaseFirecrackerTapSlot(ctx, sb.ID); err != nil {
					t.Fatalf("release: %v", err)
				}
				stats, err := st.GetFirecrackerTapPoolStats(ctx)
				if err != nil {
					t.Fatalf("stats: %v", err)
				}
				if stats.Allocated != 0 || stats.Free != 3 {
					t.Fatalf("stats after release = %+v, want all free", stats)
				}

				// Re-allocate after release: any free slot is fine, and
				// the partial unique index allows reuse of the freed one.
				slot2, err := st.AllocateFirecrackerTapSlot(ctx, sb.ID, now)
				if err != nil {
					t.Fatalf("post-release allocate: %v", err)
				}
				if slot2.SandboxID != sb.ID {
					t.Fatalf("post-release slot = %+v", slot2)
				}
			},
		},
		{
			name: "firecracker_tap_pool_exhaustion_returns_sentinel",
			run: func(t *testing.T) {
				st := newTestStore(t)
				now := time.Now().UTC()
				if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
					TapName: "fctap0", CIDR: "172.16.0.0/30",
					HostIP: "172.16.0.1", GuestIP: "172.16.0.2", VsockCID: 3,
				}, now); err != nil {
					t.Fatalf("seed: %v", err)
				}
				sb1 := sampleSandbox("sb-fc-1")
				sb2 := sampleSandbox("sb-fc-2")
				for _, s := range []*models.Sandbox{sb1, sb2} {
					if err := st.Create(ctx, s); err != nil {
						t.Fatalf("create %s: %v", s.ID, err)
					}
				}
				if _, err := st.AllocateFirecrackerTapSlot(ctx, sb1.ID, now); err != nil {
					t.Fatalf("first allocate: %v", err)
				}
				// Pool is now exhausted — a second sandbox must get
				// ErrNoFreeFirecrackerTapSlot, NOT silently steal the
				// in-use slot. The admission controller upstream relies
				// on this sentinel to return a clean 503-ish error.
				_, err := st.AllocateFirecrackerTapSlot(ctx, sb2.ID, now)
				if !errors.Is(err, ErrNoFreeFirecrackerTapSlot) {
					t.Fatalf("expected ErrNoFreeFirecrackerTapSlot, got %v", err)
				}
			},
		},
		{
			name: "firecracker_tap_pool_partial_unique_index_blocks_double_allocate",
			run: func(t *testing.T) {
				// Direct-SQL test of the partial unique index. The Go
				// AllocateFirecrackerTapSlot path can't trigger this
				// case (its idempotency check returns early), but a
				// future code path that issues raw UPDATEs without that
				// check would. Pinning the index here catches a
				// migration that dropped it.
				st := newTestStore(t)
				now := time.Now().UTC()
				if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
					TapName: "fctap0", CIDR: "172.16.0.0/30",
					HostIP: "172.16.0.1", GuestIP: "172.16.0.2", VsockCID: 3,
				}, now); err != nil {
					t.Fatalf("seed 0: %v", err)
				}
				if err := st.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
					TapName: "fctap1", CIDR: "172.16.0.4/30",
					HostIP: "172.16.0.5", GuestIP: "172.16.0.6", VsockCID: 4,
				}, now); err != nil {
					t.Fatalf("seed 1: %v", err)
				}
				sb := sampleSandbox("sb-fc-dup")
				if err := st.Create(ctx, sb); err != nil {
					t.Fatalf("create sandbox: %v", err)
				}
				// First raw allocation
				if _, err := st.db.ExecContext(ctx, `
					UPDATE firecracker_tap_pool SET sandbox_id = ?, allocated_at = ?
					WHERE tap_name = 'fctap0'`, sb.ID, now); err != nil {
					t.Fatalf("first raw update: %v", err)
				}
				// Second raw allocation of a different row for the same
				// sandbox_id — the partial unique index must reject.
				_, err := st.db.ExecContext(ctx, `
					UPDATE firecracker_tap_pool SET sandbox_id = ?, allocated_at = ?
					WHERE tap_name = 'fctap1'`, sb.ID, now)
				if err == nil {
					t.Fatal("expected partial unique index to reject second slot for same sandbox_id")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

// iToStr is a tiny int-to-string helper used by the firecracker_tap_pool
// allocator tests to avoid pulling strconv into the file just for this.
func iToStr(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
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
		now := time.Now()
		row := sqlRowStub{values: []any{
			"sb-bad",                    // id
			"image",                     // image
			models.SandboxStatusStarted, // status
			"https://example.com",       // public_url
			"container",                 // container_id
			"10.0.0.1",                  // container_ip
			float64(1),                  // cpu
			1024,                        // memory_mb
			10,                          // disk_gb
			"root",                      // os_user
			"{bad json",                 // env_json — triggers the failure
			0,                           // network_blocked
			"[]",                        // network_allow_out_json
			"[]",                        // network_deny_out_json
			1,                           // allow_public_traffic
			"",                          // mask_request_host
			1,                           // toolbox_enabled
			"",                          // toolbox_token
			"",                          // ssh_public_key
			"",                          // last_error
			"[]",                        // container_command_json
			"",                          // name
			"{}",                        // tags_json
			now, now, now,               // created_at, updated_at, last_active_at
			int64(0), int64(0), int64(0), int64(0), // lifecycle ns columns
			"",                 // failover_policy
			"",                 // runtime
			"",                 // gpus_json
			int64(0), int64(0), // net_bytes_in, net_bytes_out
			int64(0), int64(0), // net_bytes_in_limit, net_bytes_out_limit
			0,              // net_quota_exceeded
			sql.NullTime{}, // net_quota_exceeded_at
			[]byte(nil),    // registry_auth_sealed
			0,              // auto_import_pending
			0,              // serverless
			0,              // wake_armed
			"",             // template_id
			0,              // overlay_size_gb
			"passivatable", // durability
			"", "",         // module_ref, module_digest
			"", "", // checkpoint_path, clone_generation
			"", "", // wasm_registry_ref, wasm_registry_digest
			"", // owner_ref
			0,  // fleet_suspended
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

func TestClusterSecretsStoreRoundTripAndDelete(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	rec := ClusterSecretRecord{
		Ref:           "cluster-secret://sandbox/sb-store/v1",
		SandboxID:     "sb-store",
		Version:       1,
		Recipients:    []string{"node-a"},
		SealedPayload: []byte("opaque-ciphertext"),
	}
	if err := st.PutClusterSecret(ctx, rec); err != nil {
		t.Fatalf("PutClusterSecret: %v", err)
	}
	got, err := st.GetClusterSecret(ctx, rec.Ref)
	if err != nil {
		t.Fatalf("GetClusterSecret: %v", err)
	}
	if got.Ref != rec.Ref || got.SandboxID != rec.SandboxID || got.Version != rec.Version {
		t.Fatalf("record identity = %+v, want %+v", got, rec)
	}
	if len(got.Recipients) != 1 || got.Recipients[0] != "node-a" {
		t.Fatalf("recipients = %+v, want node-a", got.Recipients)
	}
	if string(got.SealedPayload) != "opaque-ciphertext" {
		t.Fatalf("sealed payload = %q", string(got.SealedPayload))
	}

	if err := st.DeleteClusterSecretsForSandbox(ctx, rec.SandboxID); err != nil {
		t.Fatalf("DeleteClusterSecretsForSandbox: %v", err)
	}
	if _, err := st.GetClusterSecret(ctx, rec.Ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetClusterSecret after delete = %v, want ErrNotFound", err)
	}
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

func TestEgressPolicyColumnsRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	// Allowlist round-trips through Create + Get.
	allow := sampleSandbox("sb-egress-allow")
	allow.NetworkBlockAll = false
	allow.NetworkAllowOut = []string{"1.1.1.0/24", "8.8.8.8/32"}
	if err := st.Create(ctx, allow); err != nil {
		t.Fatalf("Create allow: %v", err)
	}
	got, err := st.Get(ctx, allow.ID)
	if err != nil {
		t.Fatalf("Get allow: %v", err)
	}
	if !reflect.DeepEqual(got.NetworkAllowOut, allow.NetworkAllowOut) || len(got.NetworkDenyOut) != 0 {
		t.Fatalf("allow round-trip = allow %+v deny %+v, want %+v / empty", got.NetworkAllowOut, got.NetworkDenyOut, allow.NetworkAllowOut)
	}

	// Blocklist round-trips through Upsert.
	deny := sampleSandbox("sb-egress-deny")
	deny.NetworkBlockAll = false
	deny.NetworkDenyOut = []string{"10.0.0.0/8"}
	if err := st.Upsert(ctx, deny); err != nil {
		t.Fatalf("Upsert deny: %v", err)
	}
	got, err = st.Get(ctx, deny.ID)
	if err != nil {
		t.Fatalf("Get deny: %v", err)
	}
	if !reflect.DeepEqual(got.NetworkDenyOut, deny.NetworkDenyOut) || len(got.NetworkAllowOut) != 0 {
		t.Fatalf("deny round-trip = deny %+v allow %+v, want %+v / empty", got.NetworkDenyOut, got.NetworkAllowOut, deny.NetworkDenyOut)
	}

	// A sandbox with no policy reads back as empty, not a stray '[]' artifact.
	none := sampleSandbox("sb-egress-none")
	none.NetworkBlockAll = false
	if err := st.Create(ctx, none); err != nil {
		t.Fatalf("Create none: %v", err)
	}
	got, err = st.Get(ctx, none.ID)
	if err != nil {
		t.Fatalf("Get none: %v", err)
	}
	if len(got.NetworkAllowOut) != 0 || len(got.NetworkDenyOut) != 0 {
		t.Fatalf("no-policy round-trip = allow %+v deny %+v, want both empty", got.NetworkAllowOut, got.NetworkDenyOut)
	}
}

func TestAllowPublicTrafficColumnRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	// Explicit false persists and reads back as a non-nil false.
	deny := sampleSandbox("sb-no-public")
	denyVal := false
	deny.AllowPublicTraffic = &denyVal
	if err := st.Create(ctx, deny); err != nil {
		t.Fatalf("Create deny: %v", err)
	}
	got, err := st.Get(ctx, deny.ID)
	if err != nil {
		t.Fatalf("Get deny: %v", err)
	}
	if got.AllowPublicTraffic == nil || *got.AllowPublicTraffic {
		t.Fatalf("AllowPublicTraffic = %v, want non-nil false", got.AllowPublicTraffic)
	}

	// Unset (nil) defaults to allowed (column default 1) on read-back.
	dflt := sampleSandbox("sb-default-public")
	dflt.AllowPublicTraffic = nil
	if err := st.Create(ctx, dflt); err != nil {
		t.Fatalf("Create default: %v", err)
	}
	got, err = st.Get(ctx, dflt.ID)
	if err != nil {
		t.Fatalf("Get default: %v", err)
	}
	if got.AllowPublicTraffic == nil || !*got.AllowPublicTraffic {
		t.Fatalf("default AllowPublicTraffic = %v, want non-nil true", got.AllowPublicTraffic)
	}
}

func TestMaskRequestHostColumnRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	// A set value persists and reads back verbatim.
	masked := sampleSandbox("sb-masked")
	masked.MaskRequestHost = "localhost"
	if err := st.Create(ctx, masked); err != nil {
		t.Fatalf("Create masked: %v", err)
	}
	got, err := st.Get(ctx, masked.ID)
	if err != nil {
		t.Fatalf("Get masked: %v", err)
	}
	if got.MaskRequestHost != "localhost" {
		t.Fatalf("MaskRequestHost = %q, want %q", got.MaskRequestHost, "localhost")
	}

	// Unset defaults to empty (column default '') on read-back.
	plain := sampleSandbox("sb-plain")
	if err := st.Create(ctx, plain); err != nil {
		t.Fatalf("Create plain: %v", err)
	}
	got, err = st.Get(ctx, plain.ID)
	if err != nil {
		t.Fatalf("Get plain: %v", err)
	}
	if got.MaskRequestHost != "" {
		t.Fatalf("default MaskRequestHost = %q, want empty", got.MaskRequestHost)
	}
}

func TestWasmCheckpointColumnsRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	sb := sampleSandbox("sb-wasm-ckpt")
	sb.Runtime = models.RuntimeWasm
	sb.Durability = models.DurabilityPassivatable
	sb.ModuleRef = "file:///tmp/demo.wasm"
	sb.ModuleDigest = "deadbeef"
	sb.CheckpointPath = "/var/lib/sandboxd/wasm/modules/sb-wasm-ckpt/mem.snap"
	sb.CloneGeneration = "gen-abc"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.CheckpointPath != sb.CheckpointPath || got.CloneGeneration != sb.CloneGeneration {
		t.Fatalf("checkpoint fields = %+v, want path=%q gen=%q", got, sb.CheckpointPath, sb.CloneGeneration)
	}
	if err := st.UpdateWasmCheckpoint(ctx, sb.ID, string(models.SandboxStatusPassivated), "/new/path", "gen-2", ""); err != nil {
		t.Fatalf("UpdateWasmCheckpoint: %v", err)
	}
	got, err = st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if got.Status != models.SandboxStatusPassivated || got.CheckpointPath != "/new/path" || got.CloneGeneration != "gen-2" {
		t.Fatalf("after update = status %q path %q gen %q", got.Status, got.CheckpointPath, got.CloneGeneration)
	}
	if err := st.CompareCloneGeneration(ctx, sb.ID, "gen-2"); err != nil {
		t.Fatalf("CompareCloneGeneration match: %v", err)
	}
	if err := st.CompareCloneGeneration(ctx, sb.ID, "stale-gen"); !errors.Is(err, models.ErrSnapshotFenced) {
		t.Fatalf("CompareCloneGeneration stale = %v, want ErrSnapshotFenced", err)
	}
	if err := st.UpsertWasmModule(ctx, WasmModuleRecord{
		ID:              "mod-1",
		ModuleRef:       "file:///tmp/demo.wasm",
		Status:          "ready",
		Digest:          "deadbeef",
		Entrypoint:      "_start",
		ModuleSizeBytes: 128,
		CreatedAt:       time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}
}

// A module is "referenced" when a sandbox shares its content digest, even
// though that sandbox's module_ref names a different alias/tag (codex C5).
// Deleting/evicting purely by ref would otherwise stomp shared bytes.
func TestIsWasmModuleReferencedByDigest(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	// Sandbox booted from alias "python" but pinned to digest sha256X.
	sb := sampleSandbox("sb-ref-digest")
	sb.ModuleRef = "python"
	sb.ModuleDigest = "sha256X"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A catalogue row whose id/ref differ from the sandbox's, but whose
	// resolved digest is the same bytes, must read as referenced.
	referenced, err := st.IsWasmModuleReferenced(ctx, "some-other-id", "oci://aocr/x:latest", "sha256X")
	if err != nil {
		t.Fatalf("IsWasmModuleReferenced: %v", err)
	}
	if !referenced {
		t.Fatal("module sharing the sandbox's digest must be referenced (C5)")
	}

	// An unrelated digest with no ref/id match is free to delete.
	referenced, err = st.IsWasmModuleReferenced(ctx, "unrelated-id", "unrelated-ref", "sha256-OTHER")
	if err != nil {
		t.Fatalf("IsWasmModuleReferenced: %v", err)
	}
	if referenced {
		t.Fatal("unrelated module must not be referenced")
	}
}

// WasmDigestsInUse batches sandbox + catalogue membership for cache GC instead
// of per-file probes (codex P1).
func TestWasmDigestsInUse(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	sb := sampleSandbox("sb-digest-in-use")
	sb.ModuleDigest = "digest-sandbox"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	now := time.Now().UTC()
	if err := st.UpsertWasmModule(ctx, WasmModuleRecord{
		ID: "mod-cat", ModuleRef: "oci://h/r:t", Digest: "digest-catalogue",
		Status: "ready", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}

	inUse, err := st.WasmDigestsInUse(ctx, []string{
		"digest-sandbox", "digest-catalogue", "digest-free",
	})
	if err != nil {
		t.Fatalf("WasmDigestsInUse: %v", err)
	}
	if _, ok := inUse["digest-sandbox"]; !ok {
		t.Fatal("sandbox digest should be in use")
	}
	if _, ok := inUse["digest-catalogue"]; !ok {
		t.Fatal("catalogue digest should be in use")
	}
	if _, ok := inUse["digest-free"]; ok {
		t.Fatal("unreferenced digest must not be in use")
	}

	empty, err := st.WasmDigestsInUse(ctx, nil)
	if err != nil {
		t.Fatalf("WasmDigestsInUse empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty input should return empty set, got %v", empty)
	}

	// Chunking: >400 digests exercises the batched query path.
	batch := make([]string, 0, 450)
	for i := 0; i < 450; i++ {
		batch = append(batch, fmt.Sprintf("free-%04d", i))
	}
	batch = append(batch, "digest-sandbox")
	got, err := st.WasmDigestsInUse(ctx, batch)
	if err != nil {
		t.Fatalf("WasmDigestsInUse chunked: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("chunked in-use = %v, want only digest-sandbox", got)
	}
}

func TestWasmDigestsInUseQueryError(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := st.WasmDigestsInUse(ctx, []string{"x"}); err == nil {
		t.Fatal("expected error on closed store")
	}
}

func TestWasmStateKVCRUD(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const sandboxID = "sb-wasm-kv"

	if err := st.PutWasmStateKV(ctx, sandboxID, "counter", []byte("1")); err != nil {
		t.Fatalf("PutWasmStateKV: %v", err)
	}
	got, ok, err := st.GetWasmStateKV(ctx, sandboxID, "counter")
	if err != nil || !ok || string(got) != "1" {
		t.Fatalf("GetWasmStateKV = %q ok=%v err=%v", got, ok, err)
	}
	if err := st.PutWasmStateKV(ctx, sandboxID, "counter", []byte("2")); err != nil {
		t.Fatalf("PutWasmStateKV update: %v", err)
	}
	got, ok, err = st.GetWasmStateKV(ctx, sandboxID, "counter")
	if err != nil || !ok || string(got) != "2" {
		t.Fatalf("GetWasmStateKV after update = %q ok=%v err=%v", got, ok, err)
	}
	if err := st.PutWasmStateKV(ctx, sandboxID, "other", []byte("x")); err != nil {
		t.Fatalf("PutWasmStateKV other: %v", err)
	}
	keys, err := st.ListWasmStateKVKeys(ctx, sandboxID)
	if err != nil {
		t.Fatalf("ListWasmStateKVKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys = %v, want 2 entries", keys)
	}
	if err := st.DeleteWasmStateKV(ctx, sandboxID, "counter"); err != nil {
		t.Fatalf("DeleteWasmStateKV: %v", err)
	}
	_, ok, err = st.GetWasmStateKV(ctx, sandboxID, "counter")
	if err != nil || ok {
		t.Fatalf("GetWasmStateKV after delete = ok=%v err=%v", ok, err)
	}
}
