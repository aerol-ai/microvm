package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// prefixed wraps through inner and tags its output, like Vault ("vault:vN:")
// or the PKCS#11 helper ("p11:1:<len><label>").
type prefixed struct {
	tag   string
	inner *FakeKMS
}

func (p *prefixed) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	w, err := p.inner.Wrap(ctx, dek, encCtx)
	return append([]byte(p.tag), w...), err
}

func (p *prefixed) Unwrap(ctx context.Context, w []byte, encCtx map[string]string) ([]byte, error) {
	return p.inner.Unwrap(ctx, bytes.TrimPrefix(w, []byte(p.tag)), encCtx)
}

func rewrapBinding(id string) SealBinding {
	return SealBinding{SandboxID: id, IncarnationID: "inc", Ref: FormatRef(id, "inc", RefVersion), Version: RefVersion, Generation: 1}
}

func sealWith(t *testing.T, w DataKeyWrapper, b SealBinding) []byte {
	t.Helper()
	sealed, err := SealRawEnvelopeWrappedBound([]byte(`{"env":{"K":"v"}}`), []string{"n1"}, b, func(dek []byte) ([]byte, error) {
		return w.Wrap(context.Background(), dek, EncryptionContextForBinding(b))
	})
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestWrappedKeyVersion(t *testing.T) {
	for in, want := range map[string]string{
		"vault:v7:abc": "vault:v7",
		"p11:1:\x05kek-b" + strings.Repeat("x", 30): "p11:kek-b",
		"p11:1:\x00": "",
		"\x01opaque": "",
	} {
		if got := WrappedKeyVersion([]byte(in)); got != want {
			t.Fatalf("WrappedKeyVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// §11, §12: which rows the sweep moves.
func TestClassifyRow(t *testing.T) {
	cipher, _ := NewCipherFromKey(bytes.Repeat([]byte{2}, 32))
	fake, _ := NewFakeKMS()
	b := rewrapBinding("sb")
	localRow, err := SealRawEnvelopeBound(cipher, []byte(`{}`), []string{"n1"}, b)
	if err != nil {
		t.Fatal(err)
	}
	kmsRow := sealWith(t, fake, b)
	v1 := sealWith(t, &prefixed{tag: "vault:v1:", inner: fake}, b)
	v3 := sealWith(t, &prefixed{tag: "vault:v3:", inner: fake}, b)
	labelA := sealWith(t, &prefixed{tag: "p11:1:\x05kek-a", inner: fake}, b)
	cases := []struct {
		name     string
		row      []byte
		provider string
		current  string
		want     RowState
	}{
		{"local row, still local", localRow, "local", "", RowCurrent},
		{"local row under a key store", localRow, "awskms", "", RowStale},
		{"local row under vault", localRow, "vault", "vault:v2", RowStale},
		{"aws kms row", kmsRow, "awskms", "", RowCurrent},
		{"aws kms row under vault (unsupported switch)", kmsRow, "vault", "vault:v2", RowForeign},
		{"older vault version", v1, "vault", "vault:v2", RowStale},
		{"newer than the current read", v3, "vault", "vault:v2", RowCurrent},
		{"same vault version", v1, "vault", "vault:v1", RowCurrent},
		{"old pkcs11 label", labelA, "pkcs11", "p11:kek-b", RowStale},
		{"vault row on a pkcs11 node", v1, "pkcs11", "p11:kek-b", RowForeign},
	}
	for _, tc := range cases {
		got, err := ClassifyRow(tc.row, cipher, tc.provider, tc.current)
		if err != nil || got != tc.want {
			t.Fatalf("%s: %v %v, want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := ClassifyRow([]byte("junk"), cipher, "vault", ""); err == nil {
		t.Fatal("junk classified")
	}
}

func TestRewrapEnvelope(t *testing.T) {
	ctx := context.Background()
	cipher, _ := NewCipherFromKey(bytes.Repeat([]byte{2}, 32))
	fake, _ := NewFakeKMS()
	b := rewrapBinding("sb")
	v2 := &prefixed{tag: "vault:v2:", inner: fake}

	// local → vault.
	localRow, _ := SealRawEnvelopeBound(cipher, []byte(`{"env":{"K":"v"}}`), []string{"n1"}, b)
	moved, err := RewrapEnvelope(ctx, localRow, cipher, v2)
	if err != nil {
		t.Fatal(err)
	}
	if !SameEnvelopeContent(localRow, moved) || bytes.Equal(localRow, moved) {
		t.Fatal("rewrap changed the content or nothing")
	}
	if plain, err := OpenRawEnvelopeExternalBound(moved, b, func(w []byte) ([]byte, error) {
		return v2.Unwrap(ctx, w, EncryptionContextForBinding(b))
	}); err != nil || string(plain) != `{"env":{"K":"v"}}` {
		t.Fatalf("moved row = %q %v", plain, err)
	}
	// vault v1 → v2 through the same key store.
	both := &prefixed{tag: "vault:v1:", inner: fake}
	old := sealWith(t, both, b)
	if _, err := RewrapEnvelope(ctx, old, nil, &versionMover{from: both, to: v2}); err != nil {
		t.Fatal(err)
	}
	// A wrapped key that opens to the wrong key is refused before writing.
	if _, err := RewrapEnvelope(ctx, old, nil, &versionMover{from: &badKey{}, to: v2}); err == nil {
		t.Fatal("a data key that does not open the payload was rewrapped")
	}
	// A revoked server key stops the rewrap instead of falling through.
	cipher.Revoke()
	if _, err := RewrapEnvelope(ctx, localRow, cipher, v2); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("revoked = %v", err)
	}
	if _, err := RewrapEnvelope(ctx, []byte("junk"), nil, v2); err == nil {
		t.Fatal("junk rewrapped")
	}
	failing := &versionMover{from: both, to: &failingWrap{}}
	if _, err := RewrapEnvelope(ctx, old, nil, failing); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("wrap failure = %v", err)
	}
	if _, err := RewrapEnvelope(ctx, old, nil, &versionMover{from: &failingWrap{}, to: v2}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("unwrap failure = %v", err)
	}
}

type versionMover struct{ from, to DataKeyWrapper }

func (m *versionMover) Wrap(ctx context.Context, dek []byte, e map[string]string) ([]byte, error) {
	return m.to.Wrap(ctx, dek, e)
}
func (m *versionMover) Unwrap(ctx context.Context, w []byte, e map[string]string) ([]byte, error) {
	return m.from.Unwrap(ctx, w, e)
}

type badKey struct{}

func (badKey) Wrap(context.Context, []byte, map[string]string) ([]byte, error) { return nil, nil }
func (badKey) Unwrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return bytes.Repeat([]byte{9}, 32), nil
}

type failingWrap struct{}

func (failingWrap) Wrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, ErrProviderUnavailable
}
func (failingWrap) Unwrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, ErrProviderUnavailable
}

func TestSameEnvelopeContent(t *testing.T) {
	fake, _ := NewFakeKMS()
	b := rewrapBinding("sb")
	a := sealWith(t, fake, b)
	var env sealedSecretsEnvelope
	_ = json.Unmarshal(a, &env)
	env.WrappedKey = []byte("vault:v9:other")
	env.Recipients = []string{"n1", "n1"}
	rewrapped, _ := json.Marshal(env)
	if !SameEnvelopeContent(a, rewrapped) || !SameEnvelopeContent(a, a) {
		t.Fatal("same content not recognized")
	}
	env.Payload = append([]byte{0}, env.Payload...)
	changed, _ := json.Marshal(env)
	if SameEnvelopeContent(a, changed) || SameEnvelopeContent(a, []byte("x")) || SameEnvelopeContent([]byte("x"), a) {
		t.Fatal("different content called the same")
	}
}

// §12 open order: an untagged row opens with the server key first (local
// rules, recipient check included), then with AWS KMS.
func TestKMSProviderOpensLocalRowsFirst(t *testing.T) {
	ctx := ContextWithIncarnationID(context.Background(), "inc")
	cipher, _ := NewCipherFromKey(bytes.Repeat([]byte{2}, 32))
	fake, _ := NewFakeKMS()
	blobs := newMemBlobStore()
	localHandle, err := NewLocalProvider(cipher, blobs).Put(ctx, "sb-local", Secrets{Registry: &models.RegistryAuth{Password: "local"}}, []string{"n1"})
	if err != nil {
		t.Fatal(err)
	}
	kmsHandle, err := NewKMSProvider(fake, blobs).Put(ctx, "sb-kms", Secrets{Registry: &models.RegistryAuth{Password: "kms"}}, []string{"n1"})
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := NewProvider(ctx, ProviderOptions{Name: "awskms", Cipher: cipher, Store: blobs, Prebuilt: fake})
	if err != nil {
		t.Fatal(err)
	}
	if bag, err := p.Open(ctx, "sb-local", localHandle, "n1"); err != nil || bag.Registry.Password != "local" {
		t.Fatalf("local row = %+v %v", bag, err)
	}
	if _, err := p.Open(ctx, "sb-local", localHandle, "n2"); !errors.Is(err, ErrRecipientDenied) {
		t.Fatalf("local row, not a recipient = %v", err)
	}
	if bag, err := p.Open(ctx, "sb-kms", kmsHandle, "anyone"); err != nil || bag.Registry.Password != "kms" {
		t.Fatalf("kms row = %+v %v", bag, err)
	}
	cipher.Revoke()
	if _, err := p.Open(ctx, "sb-kms", kmsHandle, "n1"); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("untagged row with the server key dropped = %v", err)
	}
}

func TestCurrentKeyVersionChain(t *testing.T) {
	ctx := context.Background()
	fake, _ := NewFakeKMS()
	aws, err := NewWrapper(ctx, ProviderOptions{Name: "awskms", Wrapper: fake})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := CurrentKeyVersion(ctx, aws); ok || err != nil {
		t.Fatalf("aws kms = %v %v, want no versions", ok, err)
	}
	if _, ok, _ := CurrentKeyVersion(ctx, fake); ok {
		t.Fatal("a bare wrapper has versions")
	}
	api := &scriptedVault{replies: []scriptedReply{
		capsReply([]string{"update"}, []string{"update"}),
		{status: 200, resp: vaultResponse{Data: map[string]any{"latest_version": float64(4)}}},
		{status: 403, resp: vaultResponse{Errors: []string{"permission denied"}}},
		{status: 200, resp: vaultResponse{Data: map[string]any{}}},
	}}
	vlt := newVaultWithAPI(api, "transit", "k")
	w := NewLimitedWrapper(NewRouter(ProviderVault, vlt, nil), 2, nil)
	if err := vlt.ensurePolicy(ctx); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := CurrentKeyVersion(ctx, w); !ok || err != nil || v != "vault:v4" {
		t.Fatalf("vault = %q %v %v", v, ok, err)
	}
	if api.paths[1] != "transit/keys/k" {
		t.Fatalf("read path = %v", api.paths)
	}
	if _, _, err := CurrentKeyVersion(ctx, w); !errors.Is(err, ErrProviderDenied) {
		t.Fatalf("no read grant = %v", err)
	}
	if _, _, err := CurrentKeyVersion(ctx, w); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("no latest_version = %v", err)
	}
	var nilRouter *Router
	if _, err := nilRouter.CurrentKeyVersion(ctx); !errors.Is(err, errNoKeyVersions) {
		t.Fatal("nil router")
	}
	api.replies = []scriptedReply{{err: ErrProviderUnavailable}}
	if _, _, err := CurrentKeyVersion(ctx, w); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatal("transport error")
	}
	bg, cancel := context.WithCancel(ContextForBackground(ctx))
	cancel()
	full := NewLimitedWrapper(NewRouter(ProviderVault, vlt, nil), 1, nil).(*limitedWrapper)
	for i := 0; i < backgroundSlots; i++ {
		full.background <- struct{}{}
	}
	if _, _, err := CurrentKeyVersion(bg, full); !errors.Is(err, ErrProviderThrottled) {
		t.Fatalf("no background slot = %v", err)
	}
}
