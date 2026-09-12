package secrets

import (
	"context"
	"errors"
	"testing"
)

func TestFakeKMSInjectedFailuresAndCanary(t *testing.T) {
	ctx := context.Background()
	if err := CanaryWrapUnwrap(ctx, nil); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("nil canary = %v", err)
	}
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	if err := CanaryWrapUnwrap(ctx, fake); err != nil {
		t.Fatalf("canary = %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := fake.Wrap(cancelled, []byte("dek-bytes-32!!!!!!!!!!!!!!!!!"), nil); err == nil {
		t.Fatal("cancelled wrap must fail")
	}
	if _, err := fake.Unwrap(cancelled, []byte("xx"), nil); err == nil {
		t.Fatal("cancelled unwrap must fail")
	}

	fake.Throttle = true
	if _, err := fake.Wrap(ctx, []byte("dek-bytes-32!!!!!!!!!!!!!!!!!"), nil); !errors.Is(err, ErrProviderThrottled) {
		t.Fatalf("throttle = %v", err)
	}
	fake.Throttle = false
	fake.Deny = true
	if _, err := fake.Unwrap(ctx, []byte("short"), nil); !errors.Is(err, ErrProviderDenied) {
		t.Fatalf("deny = %v", err)
	}
	fake.Deny = false
	fake.Unavailable = true
	if err := CanaryWrapUnwrap(ctx, fake); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("unavailable canary = %v", err)
	}
	fake.Unavailable = false
	if _, err := fake.Unwrap(ctx, []byte("xx"), nil); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("short unwrap = %v", err)
	}
	wrapped, err := fake.Wrap(ctx, []byte("dek-bytes-32!!!!!!!!!!!!!!!!!"), map[string]string{"a": "b"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fake.Unwrap(ctx, wrapped, map[string]string{"a": "other"}); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("aad mismatch = %v", err)
	}
	if NormalizeProviderName("  LOCAL  ") != ProviderLocal {
		t.Fatal("NormalizeProviderName should lowercase")
	}
	if NormalizeProviderName("   ") != ProviderLocal {
		t.Fatal("empty provider name must default to local")
	}
}
