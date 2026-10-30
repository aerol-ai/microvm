package secrets

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// tagWrapper is a DataKeyWrapper that prefixes its output with a tag, the way
// Vault ("vault:v1:") and the PKCS#11 helper ("p11:") do.
type tagWrapper struct {
	tag    string
	unwrap int
}

func (w *tagWrapper) Wrap(_ context.Context, dek []byte, _ map[string]string) ([]byte, error) {
	return append([]byte(w.tag), dek...), nil
}

func (w *tagWrapper) Unwrap(_ context.Context, wrapped []byte, _ map[string]string) ([]byte, error) {
	w.unwrap++
	return []byte(strings.TrimPrefix(string(wrapped), w.tag)), nil
}

func TestWrappedKeyBackend(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"vault:v1:abc", ProviderVault},
		{"p11:1:xyz", ProviderPKCS11},
		{"\x01\x02opaque-kms-blob", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := WrappedKeyBackend([]byte(tc.in)); got != tc.want {
			t.Fatalf("WrappedKeyBackend(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A node still sealing with one provider opens rows whose tag names another
// provider it has settings for: the two-step switch (eng D8). Untagged rows go
// to AWS KMS whenever AWS KMS is configured (eng D22).
func TestRouterOpensByTag(t *testing.T) {
	ctx := context.Background()
	vault := &tagWrapper{tag: "vault:v1:"}
	aws := &tagWrapper{tag: ""}
	r := NewRouter(ProviderAWSKMS, aws, map[string]DataKeyWrapper{ProviderVault: vault, ProviderPKCS11: nil})

	sealed, err := r.Wrap(ctx, []byte("dek"), nil)
	if err != nil || string(sealed) != "dek" {
		t.Fatalf("Wrap = %q %v, want the sealing provider's output", sealed, err)
	}
	if got, err := r.Unwrap(ctx, []byte("vault:v1:dek"), nil); err != nil || string(got) != "dek" || vault.unwrap != 1 {
		t.Fatalf("vault row = %q %v (vault unwraps %d)", got, err, vault.unwrap)
	}
	if got, err := r.Unwrap(ctx, []byte("dek"), nil); err != nil || string(got) != "dek" || aws.unwrap != 1 {
		t.Fatalf("untagged row = %q %v (aws unwraps %d)", got, err, aws.unwrap)
	}
	_, err = r.Unwrap(ctx, []byte("p11:1:dek"), nil)
	if !errors.Is(err, ErrProviderUnavailable) || !strings.Contains(err.Error(), "row wrapped by pkcs11; node configured for awskms") {
		t.Fatalf("p11 row without settings = %v", err)
	}
}

func TestRouterUntaggedWithoutAWS(t *testing.T) {
	r := NewRouter(ProviderVault, &tagWrapper{tag: "vault:v1:"}, nil)
	if _, err := r.Unwrap(context.Background(), []byte("opaque"), nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("untagged row on a vault-only node = %v", err)
	}
}

func TestRouterNil(t *testing.T) {
	var r *Router
	if _, err := r.Wrap(context.Background(), []byte("d"), nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("nil Wrap = %v", err)
	}
	if _, err := r.Unwrap(context.Background(), []byte("d"), nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("nil Unwrap = %v", err)
	}
	if _, err := NewRouter(ProviderAWSKMS, nil, nil).Wrap(context.Background(), []byte("d"), nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("no seal wrapper = %v", err)
	}
}

// OV7: a revoke or a retired version must survive envelope opening, so the
// HTTP layer can answer 503 key_revoked instead of a decrypt failure.
func TestEnvelopeKeepsKeyStoreClasses(t *testing.T) {
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	binding := SealBinding{SandboxID: "sb", IncarnationID: "inc", Ref: FormatRef("sb", "inc", RefVersion), Version: RefVersion, Generation: 1}
	sealed, err := SealRawEnvelopeWrappedBound([]byte("plain"), []string{"n1"}, binding, func(dek []byte) ([]byte, error) {
		return fake.Wrap(context.Background(), dek, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, class := range []error{ErrKeyRevoked, ErrKeyVersionRetired, ErrProviderDenied} {
		_, err := OpenRawEnvelopeExternalBound(sealed, binding, func([]byte) ([]byte, error) { return nil, class })
		if !errors.Is(err, class) || errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("class %v became %v", class, err)
		}
	}
	_, err = OpenRawEnvelopeExternalBound(sealed, binding, func([]byte) ([]byte, error) { return nil, errors.New("bad tag") })
	if !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("an unclassed unwrap error must stay a decrypt failure, got %v", err)
	}
}

// OV7 end to end through the provider: a row sealed while the key was live,
// opened after the key owner revoked it, reports the revoke.
func TestKMSProviderOpenReportsRevoke(t *testing.T) {
	ctx := ContextWithIncarnationID(context.Background(), "inc-1")
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	blobs := newMemBlobStore()
	h, err := NewKMSProvider(fake, blobs).Put(ctx, "sb", Secrets{Registry: &models.RegistryAuth{Password: "p"}}, []string{"n"})
	if err != nil {
		t.Fatal(err)
	}
	revoked := &scriptWrapper{errs: []error{ErrKeyRevoked}}
	p := NewKMSProvider(NewLimitedWrapper(NewRouter(ProviderAWSKMS, revoked, nil), 2, nil), blobs)
	_, err = p.Open(ctx, "sb", h, "n")
	if !errors.Is(err, ErrKeyRevoked) || errors.Is(err, ErrDecryptFailed) || revoked.calls != 1 {
		t.Fatalf("open after revoke = %v (calls %d)", err, revoked.calls)
	}
}

// pkg/daemon hands the running PKCS#11 helper in as opts.PKCS11: it seals
// for a pkcs11 node and opens p11 rows on any other node that has it.
func TestNewWrapperPKCS11(t *testing.T) {
	ctx := context.Background()
	helper := &tagWrapper{tag: "p11:1:"}
	if _, err := NewWrapper(ctx, ProviderOptions{Name: "pkcs11"}); err == nil || !strings.Contains(err.Error(), "helper is not running") {
		t.Fatalf("pkcs11 without a helper = %v", err)
	}
	w, err := NewWrapper(ctx, ProviderOptions{Name: "pkcs11", PKCS11: helper})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := w.Wrap(ctx, []byte("dek"), nil)
	if err != nil || WrappedKeyBackend(sealed) != ProviderPKCS11 {
		t.Fatalf("Wrap = %q %v", sealed, err)
	}
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	aws, err := NewWrapper(ctx, ProviderOptions{Name: "awskms", Wrapper: fake, PKCS11: helper})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := aws.Unwrap(ctx, sealed, nil); err != nil || string(got) != "dek" {
		t.Fatalf("awskms node opening a p11 row = %q %v", got, err)
	}
}
