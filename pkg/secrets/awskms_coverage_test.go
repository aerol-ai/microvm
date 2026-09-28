package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestAWSKMSWrapUnwrapErrorAndContextBranches(t *testing.T) {
	ctx := context.Background()
	if _, err := (*AWSKMS)(nil).Wrap(ctx, []byte("dek"), nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("nil wrap = %v", err)
	}
	if _, err := (*AWSKMS)(nil).Unwrap(ctx, []byte("w"), nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("nil unwrap = %v", err)
	}

	empty := &stubKMS{}
	a := NewAWSKMSWithClient(empty, "alias/test")
	if _, err := a.Wrap(ctx, []byte("dek"), map[string]string{"k": "v"}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("empty ciphertext = %v", err)
	}
	if _, err := a.Unwrap(ctx, []byte("w"), map[string]string{"k": "v"}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("empty plaintext = %v", err)
	}

	fail := &stubKMS{encryptErr: stubAPIError{code: "AccessDeniedException"}, decryptErr: stubAPIError{code: "ThrottlingException"}}
	a = NewAWSKMSWithClient(fail, "alias/test")
	if _, err := a.Wrap(ctx, []byte("dek"), nil); !errors.Is(err, ErrProviderDenied) {
		t.Fatalf("denied wrap = %v", err)
	}
	if _, err := a.Unwrap(ctx, []byte("w"), nil); !errors.Is(err, ErrProviderThrottled) {
		t.Fatalf("throttled unwrap = %v", err)
	}

	if err := mapAWSKMSError(nil); err != nil {
		t.Fatalf("nil map = %v", err)
	}
	if !errors.Is(mapAWSKMSError(&types.NotFoundException{}), ErrProviderDenied) {
		t.Fatal("NotFound must map to denied")
	}
	if !errors.Is(mapAWSKMSError(&types.DisabledException{}), ErrProviderUnavailable) {
		t.Fatal("Disabled must map to unavailable")
	}
	if !errors.Is(mapAWSKMSError(errors.New("other")), ErrProviderUnavailable) {
		t.Fatal("unknown must map to unavailable")
	}
}

func TestNewAWSKMSAndProviderFactoryGaps(t *testing.T) {
	ctx := context.Background()
	if _, err := NewAWSKMS(ctx, "  "); err == nil {
		t.Fatal("empty key id must fail")
	}
	// Default AWS chain may or may not be present; either outcome covers NewAWSKMS.
	if kms, err := NewAWSKMS(ctx, "alias/test"); err == nil && kms == nil {
		t.Fatal("NewAWSKMS succeeded with a nil client")
	}

	if _, _, err := NewProvider(ctx, ProviderOptions{}); err == nil {
		t.Fatal("missing store must fail")
	}
	store := newMemBlobStore()
	if _, _, err := NewProvider(ctx, ProviderOptions{Name: "vault", Store: store}); err == nil {
		t.Fatal("vault must be rejected")
	}
	if _, _, err := NewProvider(ctx, ProviderOptions{Name: "unknown", Store: store}); err == nil {
		t.Fatal("unknown provider must fail")
	}
	if _, _, err := NewProvider(ctx, ProviderOptions{Name: "local", Store: store}); err == nil {
		t.Fatal("local without cipher must fail")
	}
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	if p, w, err := NewProvider(ctx, ProviderOptions{Name: "awskms", Store: store, Wrapper: fake}); err != nil || p == nil || w == nil {
		t.Fatalf("awskms with wrapper = %v %v %v", p, w, err)
	}
	if _, _, err := NewProvider(ctx, ProviderOptions{Name: "awskms", Store: store, AWSKMSKeyID: ""}); err == nil {
		t.Fatal("awskms without wrapper/key must fail")
	}
}
