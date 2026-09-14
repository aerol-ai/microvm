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

func TestListDoesNotDecryptToolboxTokenAndSurvivesCorruptRow(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	st.SetSecretCipher(cipher)

	good := sampleSandbox("sb-list-token-ok")
	good.ToolboxToken = "bearer-good"
	if err := st.Create(ctx, good); err != nil {
		t.Fatal(err)
	}
	bad := sampleSandbox("sb-list-token-bad")
	bad.ToolboxToken = "bearer-bad"
	if err := st.Create(ctx, bad); err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err := st.db.QueryRowContext(ctx, `
		SELECT toolbox_token_sealed FROM sandboxes WHERE id = ?
	`, bad.ID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := st.db.ExecContext(ctx, `
		UPDATE sandboxes SET toolbox_token_sealed = ? WHERE id = ?
	`, sealed, bad.ID); err != nil {
		t.Fatal(err)
	}

	listed, err := st.List(ctx)
	if err != nil {
		t.Fatalf("List failed on undecryptable toolbox token: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("List returned %d sandboxes, want 2", len(listed))
	}
	for _, sb := range listed {
		if sb.ToolboxToken != "" {
			t.Fatalf("List decrypted toolbox token for %s", sb.ID)
		}
		if len(sb.ToolboxTokenSealed) == 0 {
			t.Fatalf("List dropped sealed blob for %s", sb.ID)
		}
	}

	got, err := st.Get(ctx, good.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ToolboxToken != good.ToolboxToken {
		t.Fatalf("Get opened token=%q, want %q", got.ToolboxToken, good.ToolboxToken)
	}
	if _, err := st.Get(ctx, bad.ID); err == nil {
		t.Fatal("Get opened a tampered toolbox token")
	}
}
