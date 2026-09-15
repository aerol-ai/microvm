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
