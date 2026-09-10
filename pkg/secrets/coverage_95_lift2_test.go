package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
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

func TestLocalProviderRemainingBranches(t *testing.T) {
	ctx := ContextWithIncarnationID(context.Background(), "inc-1")
	sec := Secrets{Registry: &models.RegistryAuth{Password: "p"}}
	c := testCipher(t)

	if _, err := (*LocalProvider)(nil).Put(ctx, "sb", sec, []string{"n"}); err == nil {
		t.Fatal("nil local put")
	}
	if _, err := NewLocalProvider(c, nil).Put(ctx, "sb", sec, []string{"n"}); err == nil {
		t.Fatal("nil store put")
	}
	if _, err := NewLocalProvider(c, newMemBlobStore()).Put(ctx, "", sec, []string{"n"}); err == nil {
		t.Fatal("empty sandbox put")
	}
	if _, err := NewLocalProvider(c, newMemBlobStore()).Put(context.Background(), "sb", sec, []string{"n"}); err == nil {
		t.Fatal("missing incarnation put")
	}
	if _, err := NewLocalProvider(c, nextErrStore{}).Put(ctx, "sb", sec, []string{"n"}); err == nil {
		t.Fatal("next-generation fail must surface")
	}
	if _, err := NewLocalProvider(c, errBlobStore{putErr: errors.New("put fail")}).Put(ctx, "sb", sec, []string{"n"}); err == nil {
		t.Fatal("put fail must surface")
	}

	store := newMemBlobStore()
	p := NewLocalProvider(c, store)
	putCtx := ContextWithPutOutbox(ctx, "inc-1", []string{"peer"})
	putCtx = ContextWithRetiredRecipients(putCtx, []string{"old"})
	h, err := p.Put(putCtx, "sb-local", sec, []string{"n"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := (*LocalProvider)(nil).Open(ctx, "sb-local", h, "n"); err == nil {
		t.Fatal("nil open")
	}
	if _, err := p.Open(ctx, "", h, "n"); err == nil {
		t.Fatal("empty sandbox open")
	}
	missing := Handle{Ref: FormatRef("sb-missing", "inc-1", RefVersion), Version: RefVersion, SealGeneration: 1}
	if _, err := p.Open(ctx, "sb-missing", missing, "n"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing row = %v", err)
	}
	if _, err := NewLocalProvider(c, errBlobStore{getErr: errors.New("get boom")}).Open(ctx, "sb-local", h, "n"); err == nil {
		t.Fatal("get error must surface")
	}
	if _, err := NewLocalProvider(c, errBlobStore{getErr: ErrNotFound}).Open(ctx, "sb-local", h, "n"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not found = %v", err)
	}

	rec, _ := store.Get(ctx, h.Ref)
	rec.Version = 99
	_ = store.Put(ctx, *rec)
	if _, err := p.Open(ctx, "sb-local", h, "n"); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("version mismatch = %v", err)
	}
	rec.Version = h.Version
	rec.SandboxID = "other"
	_ = store.Put(ctx, *rec)
	if _, err := p.Open(ctx, "sb-local", h, "n"); err == nil {
		t.Fatal("sandbox mismatch")
	}
	rec.SandboxID = "sb-local"
	rec.SealGeneration = 0
	_ = store.Put(ctx, *rec)
	if _, err := p.Open(ctx, "sb-local", h, "n"); err == nil {
		t.Fatal("generation required")
	}
	rec.SealGeneration = h.SealGeneration + 1
	_ = store.Put(ctx, *rec)
	if _, err := p.Open(ctx, "sb-local", h, "n"); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("gen mismatch = %v", err)
	}

	if _, err := EnvelopeRecipients(nil); err == nil {
		t.Fatal("empty recipients")
	}
	if _, err := EnvelopeRecipients([]byte("{")); err == nil {
		t.Fatal("bad json recipients")
	}
	if _, err := EnvelopeRecipients([]byte(`{"version":4}`)); err == nil {
		t.Fatal("missing payload recipients")
	}
	if _, err := EnvelopeRecipients([]byte(`{"version":3,"payload":"YQ=="}`)); err == nil {
		t.Fatal("bad version recipients")
	}
	if _, err := ParseRef("not-a-ref"); err == nil {
		t.Fatal("bad prefix")
	}
	if _, err := ParseRef("cluster-secret://sandbox/sb/v1"); err == nil {
		t.Fatal("missing incarnation")
	}
	if _, err := ParseRef("cluster-secret://sandbox/sb/i/inc"); err == nil {
		t.Fatal("missing version")
	}
	if _, err := ParseRef("cluster-secret://sandbox/sb/i/inc/vnope"); err == nil {
		t.Fatal("bad version")
	}
	if _, err := OpenRawEnvelopeExternalBound([]byte("{}"), testBinding(), nil); err == nil {
		t.Fatal("nil unwrap")
	}

	// KMS Open mismatch arms (version / sandbox / generation / nil wrapper).
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	kmsStore := newMemBlobStore()
	kp := NewKMSProvider(fake, kmsStore)
	kh, err := kp.Put(ctx, "sb-kms", sec, []string{"n"})
	if err != nil {
		t.Fatal(err)
	}
	krec, _ := kmsStore.Get(ctx, kh.Ref)
	krec.Version = 99
	_ = kmsStore.Put(ctx, *krec)
	if _, err := kp.Open(ctx, "sb-kms", kh, "n"); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("kms version = %v", err)
	}
	krec.Version = kh.Version
	krec.SandboxID = "other"
	_ = kmsStore.Put(ctx, *krec)
	if _, err := kp.Open(ctx, "sb-kms", kh, "n"); err == nil {
		t.Fatal("kms sandbox mismatch")
	}
	krec.SandboxID = "sb-kms"
	krec.SealGeneration = 0
	_ = kmsStore.Put(ctx, *krec)
	if _, err := kp.Open(ctx, "sb-kms", kh, "n"); err == nil {
		t.Fatal("kms generation required")
	}
	krec.SealGeneration = kh.SealGeneration + 3
	_ = kmsStore.Put(ctx, *krec)
	if _, err := kp.Open(ctx, "sb-kms", kh, "n"); !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("kms gen mismatch = %v", err)
	}
	krec.SealGeneration = kh.SealGeneration
	_ = kmsStore.Put(ctx, *krec)
	if _, err := NewKMSProvider(nil, kmsStore).Open(ctx, "sb-kms", kh, "n"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("kms nil wrapper = %v", err)
	}
	if _, err := NewKMSProvider(fake, errBlobStore{getErr: errors.New("get boom")}).Open(ctx, "sb-kms", kh, "n"); err == nil {
		t.Fatal("kms get error")
	}
	openRaw, err := OpenRawEnvelopeExternalBound(krec.SealedPayload, SealBinding{
		SandboxID: "sb-kms", IncarnationID: "inc-1", Ref: kh.Ref, Version: RefVersion, Generation: kh.SealGeneration,
	}, func(wrapped []byte) ([]byte, error) {
		return nil, ErrProviderThrottled
	})
	if openRaw != nil || !errors.Is(err, ErrProviderThrottled) {
		t.Fatalf("external unwrap sentinel = %v %v", openRaw, err)
	}
	wrongGen := testBinding()
	wrongGen.Generation = 99
	if _, err := OpenRawEnvelopeExternalBound(krec.SealedPayload, wrongGen, func([]byte) ([]byte, error) { return []byte("x"), nil }); err == nil {
		t.Fatal("generation mismatch open")
	}
	wrongInc := testBinding()
	wrongInc.SandboxID = "sb-kms"
	wrongInc.Ref = kh.Ref
	wrongInc.IncarnationID = "other"
	wrongInc.Generation = kh.SealGeneration
	if _, err := OpenRawEnvelopeExternalBound(krec.SealedPayload, wrongInc, func([]byte) ([]byte, error) { return []byte("x"), nil }); err == nil {
		t.Fatal("incarnation mismatch open")
	}
}

type nextErrStore struct{}

func (nextErrStore) Put(context.Context, SecretBlob) error            { return nil }
func (nextErrStore) Get(context.Context, string) (*SecretBlob, error) { return nil, ErrNotFound }
func (nextErrStore) DeleteForSandbox(context.Context, string) error   { return nil }
func (nextErrStore) NextSealGeneration(context.Context, string) (int64, error) {
	return 0, errors.New("next fail")
}
