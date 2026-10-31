package secrets

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// eng D8, D22: step 1 of a switch from local adds a key store's settings and
// changes nothing else. The node keeps sealing with the server key but opens
// what switched peers seal: a vault row with the Vault settings, an untagged
// AWS KMS row with the AWS KMS settings. A node without the settings names
// the key store it lacks.
func TestTwoStepSwitchFromLocal(t *testing.T) {
	ctx := ContextWithIncarnationID(context.Background(), "inc")
	c, err := NewCipherFromKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := newMemBlobStore()
	vault := startTransit(t, newFakeTransit(t))
	bag := Secrets{Env: map[string]string{"K": "v"}}
	opens := func(p Provider, sandboxID string, h Handle, nodeID string) error {
		t.Helper()
		got, err := p.Open(ctx, sandboxID, h, nodeID)
		if err == nil && got.Env["K"] != "v" {
			t.Fatalf("%s opened to %v", sandboxID, got.Env)
		}
		return err
	}

	switched, _, err := NewProvider(ctx, ProviderOptions{Name: ProviderVault, Vault: vault, Cipher: c, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	vaultRow, err := switched.Put(ctx, "sb-vault", bag, []string{"node-b"})
	if err != nil {
		t.Fatal(err)
	}
	aws, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	awsRow, err := NewKMSProvider(aws, store).Put(ctx, "sb-aws", bag, []string{"node-b"})
	if err != nil {
		t.Fatal(err)
	}

	// Step 1 with the Vault settings: an open-only client.
	w, err := NewOpenWrapper(ctx, ProviderOptions{Name: ProviderLocal, Vault: vault})
	if err != nil || w == nil {
		t.Fatalf("NewOpenWrapper with Vault settings = %v %v", w, err)
	}
	if _, err := w.Wrap(ctx, []byte("dek"), nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("the open-only client sealed: %v", err)
	}
	stepOne, _, err := NewProvider(ctx, ProviderOptions{Name: ProviderLocal, Cipher: c, Store: store, Prebuilt: w})
	if err != nil {
		t.Fatal(err)
	}
	if err := opens(stepOne, "sb-vault", vaultRow, "node-a"); err != nil {
		t.Fatalf("a vault row on a local node with Vault settings: %v", err)
	}
	// It still seals with the server key, and its own rows keep the local
	// rules, recipient check included.
	localRow, err := stepOne.Put(ctx, "sb-local", bag, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := store.Get(ctx, localRow.Ref)
	if env, err := parseEnvelope(rec.SealedPayload); err != nil || WrappedKeyBackend(env.WrappedKey) != "" || !opensLocally(env, c) {
		t.Fatalf("step 1 sealed with a key store: %v", err)
	}
	if err := opens(stepOne, "sb-local", localRow, "node-a"); err != nil {
		t.Fatalf("own local row: %v", err)
	}
	if err := opens(stepOne, "sb-local", localRow, "node-z"); !errors.Is(err, ErrRecipientDenied) {
		t.Fatalf("local row for another node = %v, want ErrRecipientDenied", err)
	}
	if err := opens(stepOne, "sb-aws", awsRow, "node-a"); !errors.Is(err, ErrProviderUnavailable) || !strings.Contains(err.Error(), "row wrapped by awskms; node configured for local") {
		t.Fatalf("an AWS KMS row on a Vault-only node = %v", err)
	}

	// Step 1 with the AWS KMS settings: the untagged row is tried with the
	// server key first, then with AWS KMS (eng D22).
	awsStepOne, _, err := NewProvider(ctx, ProviderOptions{Name: ProviderLocal, Cipher: c, Store: store,
		Prebuilt: routedWrapper(ProviderOptions{}, ProviderLocal, nil, map[string]DataKeyWrapper{ProviderAWSKMS: aws})})
	if err != nil {
		t.Fatal(err)
	}
	if err := opens(awsStepOne, "sb-aws", awsRow, "node-a"); err != nil {
		t.Fatalf("an untagged AWS KMS row on a local node with AWS settings: %v", err)
	}
	if err := opens(awsStepOne, "sb-local", localRow, "node-a"); err != nil {
		t.Fatalf("a local row on a local node with AWS settings: %v", err)
	}

	// No settings: no client, and the node names the key store it lacks.
	if w, err := NewOpenWrapper(ctx, ProviderOptions{Name: ProviderLocal}); w != nil || err != nil {
		t.Fatalf("NewOpenWrapper without settings = %v %v", w, err)
	}
	bare, _, err := NewProvider(ctx, ProviderOptions{Name: ProviderLocal, Cipher: c, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if err := opens(bare, "sb-vault", vaultRow, "node-a"); !errors.Is(err, ErrProviderUnavailable) || !strings.Contains(err.Error(), "row wrapped by vault; node configured for local") {
		t.Fatalf("a vault row on a local node without settings = %v", err)
	}
	if err := opens(bare, "sb-local", localRow, "node-a"); err != nil {
		t.Fatalf("a local row on a bare local node: %v", err)
	}

	// The token that will seal after step 2 is checked now.
	f := newFakeTransit(t)
	f.caps = []any{"create", "update"}
	if _, err := NewOpenWrapper(ctx, ProviderOptions{Name: ProviderLocal, Vault: startTransit(t, f)}); !IsVaultPolicyError(err) {
		t.Fatalf("a token that may create keys = %v", err)
	}
}
