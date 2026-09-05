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
	var sealed []byte
	if err := st.db.QueryRowContext(ctx, `
		SELECT toolbox_token_sealed FROM sandboxes WHERE id = ?
	`, sb.ID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if len(sealed) == 0 {
		t.Fatal("sealed toolbox token is empty")
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
