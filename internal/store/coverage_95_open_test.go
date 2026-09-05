package store

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	_ "github.com/mattn/go-sqlite3"
)

func TestOpenMigrationAndIndexFailures(t *testing.T) {
	dir := t.TempDir()

	// Steal exposed_ports as a view so CREATE TABLE IF NOT EXISTS is a no-op
	// and the additive ALTER TABLE migration fails (not a duplicate-column).
	pView := filepath.Join(dir, "view.db")
	db, err := sql.Open("sqlite3", pView)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE VIEW exposed_ports AS SELECT 0 AS host_port`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := Open(pView); err == nil {
		t.Fatal("expected Open failure when exposed_ports is a view")
	}

	// Drop the host_port unique index, insert duplicates, reopen — CREATE
	// UNIQUE INDEX IF NOT EXISTS must fail on the colliding host_port values.
	pIdx := filepath.Join(dir, "idx", "state.db")
	st, err := Open(pIdx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.Create(ctx, sampleSandbox("sb-a")); err != nil {
		t.Fatal(err)
	}
	if err := st.Create(ctx, sampleSandbox("sb-b")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `DROP INDEX IF EXISTS idx_exposed_ports_host_port`); err != nil {
		t.Fatal(err)
	}
	for _, sb := range []string{"sb-a", "sb-b"} {
		if _, err := st.db.ExecContext(ctx, `
			INSERT INTO exposed_ports (sandbox_id, port, protocol, host_port, public_url, created_at)
			VALUES (?, 8080, 'tcp', 40000, 'https://x', ?)
		`, sb, now); err != nil {
			t.Fatalf("insert duplicate host_port for %s: %v", sb, err)
		}
	}
	_ = st.Close()
	if _, err := Open(pIdx); err == nil {
		t.Fatal("expected Open failure recreating unique host_port index over duplicates")
	}
}

func TestOpenChmodDirAndImmutableFile(t *testing.T) {
	dir := t.TempDir()

	// Directory chmod failure: path component is a non-directory file.
	asFile := filepath.Join(dir, "blocked")
	if err := os.WriteFile(asFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(asFile, "child", "state.db")); err == nil {
		t.Fatal("expected Open failure when mkdir parent is a file")
	}

	// file: URI + mode=ro → schema CREATE fails.
	roPath := filepath.Join(dir, "ro.db")
	if err := os.WriteFile(roPath, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open("file:" + roPath + "?mode=ro"); err == nil {
		t.Fatal("expected Open failure for read-only empty db")
	}

	dbPath := filepath.Join(dir, "imm", "state.db")
	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = st.Close()
	if err := exec.Command("chflags", "uchg", dbPath).Run(); err != nil {
		if err2 := exec.Command("chattr", "+i", dbPath).Run(); err2 != nil {
			t.Skipf("cannot make db immutable: %v / %v", err, err2)
		}
		t.Cleanup(func() { _ = exec.Command("chattr", "-i", dbPath).Run() })
	} else {
		t.Cleanup(func() { _ = exec.Command("chflags", "nouchg", dbPath).Run() })
	}
	if _, err := Open(dbPath); err == nil {
		t.Fatal("expected Open failure chmod'ing immutable db file")
	}
}

func TestListScanErrorsCorruptSandboxJSON(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	sb := sampleSandbox("sb-list-bad")
	sb.OwnerRef = "owner-bad"
	sb.Runtime = "docker"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE sandboxes SET tags_json = ? WHERE id = ?`, "{bad", sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.List(ctx); err == nil {
		t.Fatal("List corrupt tags_json")
	}
	if _, err := st.ListByOwner(ctx, "owner-bad"); err == nil {
		t.Fatal("ListByOwner corrupt tags_json")
	}
	if _, err := st.ListByRuntime(ctx, "docker"); err == nil {
		t.Fatal("ListByRuntime corrupt tags_json")
	}
}

func TestListHelpersScanCorruptRows(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("snapshots", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.Create(ctx, sampleSandbox("sb-s"))
		snap := modelsSandboxSnap("snap-bad", "sb-s")
		_ = st.CreateSnapshot(ctx, &snap)
		// Pending push filter must match or the corrupt row is never scanned.
		if _, err := st.db.ExecContext(ctx, `UPDATE sandbox_snapshots SET push_state = 'pending', created_at = ? WHERE name = ?`, []byte{1, 2, 3}, "snap-bad"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ListSnapshots(ctx); err == nil {
			t.Fatal("ListSnapshots corrupt created_at")
		}
		if _, err := st.ListSnapshotsPendingPush(ctx); err == nil {
			t.Fatal("ListSnapshotsPendingPush corrupt created_at")
		}
	})

	t.Run("templates", func(t *testing.T) {
		st := newTestStore(t)
		if err := st.CreateTemplate(ctx, sampleTemplate("tpl-bad")); err != nil {
			t.Fatal(err)
		}
		// Put the row into every filtered list's WHERE before corrupting the timestamp.
		if _, err := st.db.ExecContext(ctx, `
			UPDATE firecracker_templates
			SET status = ?, push_state = 'pending', ready_at = ?, created_at = ?
			WHERE id = ?
		`, string(models.TemplateStatusReady), now.Add(-time.Hour), []byte{1, 2, 3}, "tpl-bad"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ListTemplates(ctx); err == nil {
			t.Fatal("ListTemplates corrupt")
		}
		if _, err := st.ListTemplatesPendingPush(ctx); err == nil {
			t.Fatal("ListTemplatesPendingPush corrupt")
		}
		if _, err := st.db.ExecContext(ctx, `UPDATE firecracker_templates SET status = ? WHERE id = ?`, string(models.TemplateStatusUnhealthy), "tpl-bad"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ListUnhealthyTemplates(ctx); err == nil {
			t.Fatal("ListUnhealthyTemplates corrupt")
		}
		if _, err := st.db.ExecContext(ctx, `
			UPDATE firecracker_templates SET status = ?, ready_at = ? WHERE id = ?
		`, string(models.TemplateStatusReady), now.Add(-time.Hour), "tpl-bad"); err != nil {
			t.Fatal(err)
		}
		// created_at still corrupt from earlier — ReadyBefore scans it.
		if _, err := st.ListTemplatesReadyBefore(ctx, now); err == nil {
			t.Fatal("ListTemplatesReadyBefore corrupt")
		}
		if _, err := st.ListGCEligibleTemplates(ctx, now); err == nil {
			t.Fatal("ListGCEligibleTemplates corrupt")
		}
	})

	t.Run("ports_domains_aliases_compat", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.Create(ctx, sampleSandbox("sb-p"))
		_ = st.UpsertPort(ctx, modelsExposedPort("sb-p", 8080, now))
		_ = st.AddCustomDomain(ctx, "sb-p", "p.example.com", 8080)
		snapP := modelsSandboxSnap("snap-p", "sb-p")
		_ = st.CreateSnapshot(ctx, &snapP)
		_ = st.UpsertSnapshotAlias(ctx, modelsAlias("al-p", "snap-p"))
		_ = st.UpsertCompatState(ctx, "sb-p", "e2b", `{}`)

		if _, err := st.db.ExecContext(ctx, `UPDATE exposed_ports SET created_at = ?`, []byte{9}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ListAllExposedPorts(ctx); err == nil {
			t.Fatal("ListAllExposedPorts corrupt")
		}

		st2 := newTestStore(t)
		_ = st2.Create(ctx, sampleSandbox("sb-d"))
		_ = st2.AddCustomDomain(ctx, "sb-d", "d.example.com", 80)
		if _, err := st2.db.ExecContext(ctx, `UPDATE sandbox_custom_domains SET created_at = ?`, []byte{9}); err != nil {
			t.Fatal(err)
		}
		if _, err := st2.ListCustomDomains(ctx, "sb-d"); err == nil {
			t.Fatal("ListCustomDomains corrupt")
		}
		if _, err := st2.ListAllCustomDomains(ctx); err == nil {
			t.Fatal("ListAllCustomDomains corrupt")
		}

		st3 := newTestStore(t)
		_ = st3.Create(ctx, sampleSandbox("sb-al"))
		snapAL := modelsSandboxSnap("snap-al", "sb-al")
		_ = st3.CreateSnapshot(ctx, &snapAL)
		_ = st3.UpsertSnapshotAlias(ctx, modelsAlias("alias-bad", "snap-al"))
		if _, err := st3.db.ExecContext(ctx, `UPDATE snapshot_aliases SET created_at = ?`, []byte{9}); err != nil {
			t.Fatal(err)
		}
		// Argument is facade, not snapshot name.
		if _, err := st3.ListSnapshotAliases(ctx, "e2b"); err == nil {
			t.Fatal("ListSnapshotAliases corrupt")
		}

		st4 := newTestStore(t)
		_ = st4.Create(ctx, sampleSandbox("sb-cs"))
		_ = st4.UpsertCompatState(ctx, "sb-cs", "e2b", `{}`)
		if _, err := st4.db.ExecContext(ctx, `DROP TABLE sandbox_compat_state`); err != nil {
			t.Fatal(err)
		}
		if _, err := st4.ListCompatState(ctx, "sb-cs"); err == nil {
			t.Fatal("ListCompatState after drop")
		}
	})

	t.Run("vmm_wasm", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.CreateTemplate(ctx, sampleTemplate("tpl-v"))
		_ = st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "vmm-bad", TemplateID: "tpl-v"}, now)
		if _, err := st.db.ExecContext(ctx, `UPDATE firecracker_vmm_pool SET created_at = ? WHERE id = ?`, []byte{1}, "vmm-bad"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ListFirecrackerVMMSlotsForRefill(ctx, "tpl-v"); err == nil {
			t.Fatal("ListFirecrackerVMMSlotsForRefill corrupt")
		}
		if _, err := st.GetFirecrackerVMMSlotByID(ctx, "vmm-bad"); err == nil {
			t.Fatal("GetFirecrackerVMMSlotByID corrupt")
		}

		_ = st.UpsertWasmModule(ctx, WasmModuleRecord{ID: "m-bad", ModuleRef: "r.wasm", Status: "ready", CreatedAt: now})
		if _, err := st.db.ExecContext(ctx, `UPDATE wasm_modules SET created_at = ? WHERE id = ?`, []byte{1}, "m-bad"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ListWasmModules(ctx); err == nil {
			t.Fatal("ListWasmModules corrupt")
		}
		if _, err := st.ListWasmModulesOlderThan(ctx, now.Add(time.Hour)); err == nil {
			t.Fatal("ListWasmModulesOlderThan corrupt")
		}
		// ListReadyWasmModuleRefs only projects module_ref; force a query error.
		if _, err := st.db.ExecContext(ctx, `DROP TABLE wasm_modules`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.ListReadyWasmModuleRefs(ctx); err == nil {
			t.Fatal("ListReadyWasmModuleRefs after drop")
		}
	})
}

// Small builders keep the corrupt-row tests readable without pulling models in every call.
func modelsSandboxSnap(name, src string) models.SandboxSnapshot {
	return models.SandboxSnapshot{Name: name, SourceSandboxID: src, Image: "img"}
}

func sampleTemplate(id string) *models.Template {
	return &models.Template{ID: id, Image: "img"}
}

func modelsExposedPort(sb string, port int, now time.Time) models.ExposedPort {
	return models.ExposedPort{
		SandboxID: sb, Port: port, Protocol: "http", PublicURL: "https://x", CreatedAt: now,
	}
}

func modelsAlias(alias, snap string) models.SnapshotAlias {
	return models.SnapshotAlias{Alias: alias, SnapshotName: snap, Facade: "e2b"}
}
