package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// providerContractOpts toggles provider-specific Open semantics.
type providerContractOpts struct {
	// anyNodeCanOpen is true for KMS: recipient binding is not enforced.
	anyNodeCanOpen bool
}

func testProviderContract(t *testing.T, p Provider, opts providerContractOpts) {
	t.Helper()
	ctx := context.Background()

	t.Run("put_open_round_trip", func(t *testing.T) {
		sec := Secrets{
			Registry: &models.RegistryAuth{Server: "ghcr.io", Username: "u", Password: "contract-secret"},
			MountCreds: map[string]map[string]string{
				"/data": {"AWS_SECRET_ACCESS_KEY": "shh"},
			},
		}
		h, err := p.Put(ctx, "sb-contract", sec, []string{"node-a", "node-b"})
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		if h.Ref == "" || h.Version != RefVersion {
			t.Fatalf("handle = %+v", h)
		}
		got, err := p.Open(ctx, "sb-contract", h, "node-a")
		if err != nil {
			t.Fatalf("Open owner: %v", err)
		}
		if got.Registry == nil || got.Registry.Password != "contract-secret" {
			t.Fatalf("registry = %+v", got.Registry)
		}
		if got.MountCreds["/data"]["AWS_SECRET_ACCESS_KEY"] != "shh" {
			t.Fatalf("mount creds = %+v", got.MountCreds)
		}
		// CRITICAL: peer in recipient set (local) or any node with bytes (kms).
		gotB, err := p.Open(ctx, "sb-contract", h, "node-b")
		if err != nil {
			t.Fatalf("Open peer: %v", err)
		}
		if gotB.Registry == nil || gotB.Registry.Password != "contract-secret" {
			t.Fatalf("peer registry = %+v", gotB.Registry)
		}
	})

	t.Run("empty_secrets_zero_handle", func(t *testing.T) {
		h, err := p.Put(ctx, "sb-empty", Secrets{}, []string{"node-a"})
		if err != nil {
			t.Fatalf("Put empty: %v", err)
		}
		if h != (Handle{}) {
			t.Fatalf("empty Put handle = %+v, want zero", h)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		_, err := p.Open(ctx, "sb-missing", Handle{Ref: FormatRef("missing", RefVersion), Version: RefVersion}, "node-a")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("Open missing = %v, want ErrNotFound", err)
		}
	})

	t.Run("recipient_semantics", func(t *testing.T) {
		h, err := p.Put(ctx, "sb-recip", Secrets{
			Registry: &models.RegistryAuth{Password: "p"},
		}, []string{"node-a"})
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		_, err = p.Open(ctx, "sb-recip", h, "node-outsider")
		if opts.anyNodeCanOpen {
			if err != nil {
				t.Fatalf("kms Open by non-recipient: %v (want success — WALL 2 removed)", err)
			}
			return
		}
		if !errors.Is(err, ErrRecipientDenied) {
			t.Fatalf("local Open non-recipient = %v, want ErrRecipientDenied", err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		h, err := p.Put(ctx, "sb-del-contract", Secrets{
			Registry: &models.RegistryAuth{Password: "p"},
		}, []string{"node-a"})
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := p.Delete(ctx, "sb-del-contract"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		_, err = p.Open(ctx, "sb-del-contract", h, "node-a")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("after delete = %v, want ErrNotFound", err)
		}
	})

	t.Run("empty_handle_open", func(t *testing.T) {
		got, err := p.Open(ctx, "sb", Handle{}, "node-a")
		if err != nil {
			t.Fatalf("empty handle: %v", err)
		}
		if got.Registry != nil {
			t.Fatalf("empty handle leaked registry: %+v", got.Registry)
		}
	})
}

func TestLocalProviderContract(t *testing.T) {
	p := NewLocalProvider(testCipher(t), newMemBlobStore())
	testProviderContract(t, p, providerContractOpts{anyNodeCanOpen: false})
}

func TestFakeKMSProviderContract(t *testing.T) {
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatalf("NewFakeKMS: %v", err)
	}
	p := NewKMSProvider(fake, newMemBlobStore())
	testProviderContract(t, p, providerContractOpts{anyNodeCanOpen: true})
}

func TestFakeKMSInjectedErrors(t *testing.T) {
	ctx := context.Background()
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatalf("NewFakeKMS: %v", err)
	}
	p := NewKMSProvider(fake, newMemBlobStore())
	sec := Secrets{Registry: &models.RegistryAuth{Password: "p"}}

	fake.Throttle = true
	if _, err := p.Put(ctx, "sb-t", sec, []string{"n"}); !errors.Is(err, ErrProviderThrottled) {
		t.Fatalf("throttle Put = %v", err)
	}
	fake.Throttle = false
	fake.Deny = true
	if _, err := p.Put(ctx, "sb-d", sec, []string{"n"}); !errors.Is(err, ErrProviderDenied) {
		t.Fatalf("deny Put = %v", err)
	}
	fake.Deny = false
	fake.Unavailable = true
	if _, err := p.Put(ctx, "sb-u", sec, []string{"n"}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("unavailable Put = %v", err)
	}
	fake.Unavailable = false

	h, err := p.Put(ctx, "sb-ok", sec, []string{"n"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	fake.Throttle = true
	if _, err := p.Open(ctx, "sb-ok", h, "n"); !errors.Is(err, ErrProviderThrottled) {
		t.Fatalf("throttle Open = %v", err)
	}
}

func TestCanaryWrapUnwrapFakeKMS(t *testing.T) {
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatalf("NewFakeKMS: %v", err)
	}
	if err := CanaryWrapUnwrap(context.Background(), fake); err != nil {
		t.Fatalf("CanaryWrapUnwrap: %v", err)
	}
	fake.Unavailable = true
	if err := CanaryWrapUnwrap(context.Background(), fake); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("canary unavailable = %v", err)
	}
}

func TestNewProviderFactory(t *testing.T) {
	ctx := context.Background()
	store := newMemBlobStore()
	c := testCipher(t)

	p, w, err := NewProvider(ctx, ProviderOptions{Name: ProviderLocal, Cipher: c, Store: store})
	if err != nil || p == nil || w != nil {
		t.Fatalf("local: p=%v w=%v err=%v", p, w, err)
	}

	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatalf("fake: %v", err)
	}
	p, w, err = NewProvider(ctx, ProviderOptions{Name: ProviderAWSKMS, AWSKMSKeyID: "alias/test", Store: store, Wrapper: fake})
	if err != nil || p == nil || w == nil {
		t.Fatalf("awskms: p=%v w=%v err=%v", p, w, err)
	}

	_, _, err = NewProvider(ctx, ProviderOptions{Name: ProviderVault, Store: store})
	if err == nil {
		t.Fatal("vault should be not-implemented")
	}
	_, _, err = NewProvider(ctx, ProviderOptions{Name: "bogus", Store: store, Cipher: c})
	if err == nil {
		t.Fatal("bogus provider should fail")
	}
}
