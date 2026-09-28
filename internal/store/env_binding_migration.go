package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// migrateEnvBinding upgrades only the pre-binding schema. The column is a
// transactionally committed format marker, not a runtime downgrade switch:
// after upgrade, no read (or subsequent restart) accepts nil-AAD ciphertext.
func migrateEnvBinding(db *sql.DB, cipher *secrets.Cipher) error {
	var bound bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pragma_table_info('sandbox_env') WHERE name = 'binding_version')`).Scan(&bound); err != nil {
		return fmt.Errorf("inspect env binding schema: %w", err)
	}
	if bound {
		return nil
	}
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	afterID := ""
	for {
		rows, err := tx.QueryContext(ctx, `SELECT sandbox_id, sealed_blob FROM sandbox_env WHERE sandbox_id > ? ORDER BY sandbox_id LIMIT ?`, afterID, legacySecretMigrationBatchSize)
		if err != nil {
			return fmt.Errorf("read env binding migration: %w", err)
		}
		type row struct {
			id   string
			blob []byte
		}
		batch := make([]row, 0, legacySecretMigrationBatchSize)
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.blob); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			break
		}
		if cipher == nil {
			return errors.New("migrate env binding: secret cipher is required")
		}
		for _, r := range batch {
			inc, err := envIncarnationForMigration(ctx, tx, r.id)
			if errors.Is(err, sql.ErrNoRows) {
				// FK CASCADE should have taken this row with its sandbox. An
				// env row with no sandbox is already unreadable — every read
				// selects FROM sandboxes — and there is no lifecycle left to
				// bind it to. Drop the dead ciphertext rather than fail every
				// future startup on a row nothing can ever open.
				if _, delErr := tx.ExecContext(ctx, `DELETE FROM sandbox_env WHERE sandbox_id = ?`, r.id); delErr != nil {
					return fmt.Errorf("drop orphaned env %q: %w", r.id, delErr)
				}
				continue
			}
			if err != nil {
				return err
			}
			aad := secrets.EnvAAD(r.id, inc)
			// A legacy plaintext-column migration just before this one may
			// already have sealed the row with AAD in the old side-table.
			if _, err := cipher.DecryptWithAAD(r.blob, aad); err == nil {
				continue
			}
			plain, err := cipher.Decrypt(r.blob)
			if err != nil {
				return fmt.Errorf("open legacy env %q for binding: %w", r.id, err)
			}
			sealed, err := cipher.EncryptWithAAD(plain, aad)
			if err != nil {
				return fmt.Errorf("bind legacy env %q: %w", r.id, err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE sandbox_env SET sealed_blob = ? WHERE sandbox_id = ?`, sealed, r.id); err != nil {
				return err
			}
		}
		afterID = batch[len(batch)-1].id
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE sandbox_env ADD COLUMN binding_version INTEGER NOT NULL DEFAULT 1 CHECK (binding_version = 1)`); err != nil {
		return err
	}
	return tx.Commit()
}

// Returns sql.ErrNoRows when the sandbox is gone; callers decide whether that
// is an orphan to drop or an impossible state for their source table.
func envIncarnationForMigration(ctx context.Context, tx *sql.Tx, sandboxID string) (string, error) {
	var inc string
	if err := tx.QueryRowContext(ctx, `SELECT audit_incarnation_id FROM sandboxes WHERE id = ?`, sandboxID).Scan(&inc); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
		return "", fmt.Errorf("read lifecycle for env migration %q: %w", sandboxID, err)
	}
	if inc != "" {
		return inc, nil
	}
	// Pre-hardening rows have no lifecycle nonce. Persist one in the same
	// transaction as the seal so later audit/bootstrap code reuses it.
	inc = rand.Text()
	_, err := tx.ExecContext(ctx, `UPDATE sandboxes SET audit_incarnation_id = ? WHERE id = ?`, inc, sandboxID)
	return inc, err
}
