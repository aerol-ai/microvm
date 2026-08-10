package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestToolboxTokenSealedAtRestAndAuthenticatedToSandbox(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	st.SetSecretCipher(cipher)

	sb := sampleSandbox("sb-toolbox-sealed")
	sb.ToolboxToken = "bearer-token-plaintext"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	var plain string
	var sealed []byte
	if err := st.db.QueryRowContext(ctx, `
		SELECT toolbox_token, toolbox_token_sealed FROM sandboxes WHERE id = ?
	`, sb.ID).Scan(&plain, &sealed); err != nil {
		t.Fatal(err)
	}
	if plain != "" || len(sealed) == 0 {
		t.Fatalf("at-rest token plaintext=%q sealed_len=%d", plain, len(sealed))
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ToolboxToken != sb.ToolboxToken {
		t.Fatalf("opened token=%q, want %q", got.ToolboxToken, sb.ToolboxToken)
	}

	sealed[len(sealed)-1] ^= 0xff
	if _, err := st.db.ExecContext(ctx, `
		UPDATE sandboxes SET toolbox_token_sealed = ? WHERE id = ?
	`, sealed, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, sb.ID); err == nil {
		t.Fatal("tampered sealed token opened successfully")
	}
}

func TestSealLegacyToolboxTokensMigratesExistingRows(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-toolbox-legacy")
	sb.ToolboxToken = "legacy-plaintext-token"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	st.SetSecretCipher(cipher)
	migrated, err := st.SealLegacyToolboxTokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if migrated != 1 {
		t.Fatalf("migrated = %d, want 1", migrated)
	}
	if again, err := st.SealLegacyToolboxTokens(ctx); err != nil || again != 0 {
		t.Fatalf("idempotent migration = %d, %v", again, err)
	}
	var plain string
	var sealed []byte
	if err := st.db.QueryRowContext(ctx, `
		SELECT toolbox_token, toolbox_token_sealed FROM sandboxes WHERE id = ?
	`, sb.ID).Scan(&plain, &sealed); err != nil {
		t.Fatal(err)
	}
	if plain != "" || len(sealed) == 0 {
		t.Fatalf("at-rest token plaintext=%q sealed_len=%d", plain, len(sealed))
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ToolboxToken != sb.ToolboxToken {
		t.Fatalf("opened token=%q, want %q", got.ToolboxToken, sb.ToolboxToken)
	}
}
