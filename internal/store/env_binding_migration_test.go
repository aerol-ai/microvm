package store

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestEnvBindingMigrationIsAtomicAndOneTime(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[corrupt], func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "env.db")
			cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
			if err != nil {
				t.Fatal(err)
			}
			st, err := OpenWithSecretCipher(path, cipher)
			if err != nil {
				t.Fatal(err)
			}
			legacy, err := cipher.Encrypt([]byte(`{"TOKEN":"preserved"}`))
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"a", "z"} {
				sb := testSandbox(id, nil)
				if id == "z" {
					sb.AuditIncarnationID = "existing-inc"
				}
				if err := st.CreateWithSealedEnv(ctx, sb, legacy); err != nil {
					t.Fatal(err)
				}
			}
			if corrupt {
				if err := st.PutEnv(ctx, "z", []byte("corrupt")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := st.db.Exec(`ALTER TABLE sandbox_env DROP COLUMN binding_version`); err != nil {
				t.Fatal(err)
			}
			st.Close()
			if _, err := Open(path); err == nil {
				t.Fatal("unbound rows migrated without a cipher")
			}
			st, err = OpenWithSecretCipher(path, cipher)
			if corrupt {
				if err == nil {
					st.Close()
					t.Fatal("corrupt row allowed partial upgrade")
				}
				raw, err := sql.Open("sqlite3", sqliteDSN(path))
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				var blob []byte
				var inc string
				if err := raw.QueryRow(`SELECT sealed_blob, audit_incarnation_id FROM sandbox_env JOIN sandboxes ON sandbox_id = id WHERE id = 'a'`).Scan(&blob, &inc); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(blob, legacy) || inc != "" {
					t.Fatal("failed migration changed earlier row or lifecycle")
				}
				var marked bool
				if err := raw.QueryRow(`SELECT EXISTS(SELECT 1 FROM pragma_table_info('sandbox_env') WHERE name = 'binding_version')`).Scan(&marked); err != nil || marked {
					t.Fatalf("failed migration committed marker: %v %v", marked, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"a", "z"} {
				blob, inc, _, err := st.GetEnvWithIdentity(ctx, id)
				if err != nil || inc == "" {
					t.Fatalf("identity: %q %v", inc, err)
				}
				if id == "z" && inc != "existing-inc" {
					t.Fatal("migration replaced live lifecycle")
				}
				plain, err := cipher.DecryptWithAAD(blob, secrets.EnvAAD(id, inc))
				if err != nil || string(plain) != `{"TOKEN":"preserved"}` {
					t.Fatalf("migrated env: %s %v", plain, err)
				}
				if _, err := cipher.Decrypt(blob); err == nil {
					t.Fatal("migrated env still opens without AAD")
				}
			}
			// After upgrade, restart must not silently rebind an injected
			// legacy blob. The runtime accepts only authenticated bound rows.
			if err := st.PutEnv(ctx, "a", legacy); err != nil {
				t.Fatal(err)
			}
			st.Close()
			st, err = OpenWithSecretCipher(path, cipher)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			blob, inc, _, err := st.GetEnvWithIdentity(ctx, "a")
			if err != nil || !bytes.Equal(blob, legacy) {
				t.Fatal("restart ran legacy fallback again")
			}
			if _, err := cipher.DecryptWithAAD(blob, secrets.EnvAAD("a", inc)); err == nil {
				t.Fatal("legacy downgrade accepted")
			}
		})
	}
}

func TestEnvBindingMigrationEmptyOldSchemaNeedsNoCipher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`ALTER TABLE sandbox_env DROP COLUMN binding_version`); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
}

// An env row whose sandbox is gone is unreadable by construction (every read
// selects FROM sandboxes) and has no lifecycle to bind to. FK CASCADE should
// have removed it, but a database that ever ran with foreign keys off can
// carry one. The upgrade must drop it, not refuse to boot forever on it.
func TestEnvBindingMigrationDropsOrphanedRows(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "orphan.db")
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := OpenWithSecretCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := cipher.Encrypt([]byte(`{"TOKEN":"kept"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWithSealedEnv(ctx, testSandbox("live", nil), legacy); err != nil {
		t.Fatal(err)
	}
	// Forge the orphan the way a foreign-keys-off database would carry it.
	if _, err := st.db.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO sandbox_env (sandbox_id, sealed_blob, created_at) VALUES ('ghost', ?, CURRENT_TIMESTAMP)`, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`ALTER TABLE sandbox_env DROP COLUMN binding_version`); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st, err = OpenWithSecretCipher(path, cipher)
	if err != nil {
		t.Fatalf("orphaned env row blocked startup: %v", err)
	}
	defer st.Close()

	var ghosts int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sandbox_env WHERE sandbox_id = 'ghost'`).Scan(&ghosts); err != nil {
		t.Fatal(err)
	}
	if ghosts != 0 {
		t.Fatalf("orphaned env row survived the upgrade: %d", ghosts)
	}
	// The live row is still bound and readable, and the marker committed.
	blob, inc, _, err := st.GetEnvWithIdentity(ctx, "live")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cipher.DecryptWithAAD(blob, secrets.EnvAAD("live", inc))
	if err != nil {
		t.Fatalf("live row lost its binding: %v", err)
	}
	if !bytes.Equal(plain, []byte(`{"TOKEN":"kept"}`)) {
		t.Fatalf("live env = %s", plain)
	}
	var marker int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('sandbox_env') WHERE name = 'binding_version'`).Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if marker != 1 {
		t.Fatal("binding marker did not commit alongside the orphan drop")
	}
}
