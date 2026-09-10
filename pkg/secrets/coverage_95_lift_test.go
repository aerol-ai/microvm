package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestEnvelopeBindingAndInvalidSeals(t *testing.T) {
	if _, err := EnvelopeBinding(nil); err == nil {
		t.Fatal("empty payload must fail")
	}
	if _, err := EnvelopeBinding([]byte("{")); err == nil {
		t.Fatal("invalid json must fail")
	}
	if _, err := EnvelopeBinding([]byte(`{"version":4}`)); err == nil {
		t.Fatal("missing payload must fail")
	}
	if _, err := EnvelopeBinding([]byte(`{"version":3,"payload":"YQ=="}`)); err == nil {
		t.Fatal("unsupported version must fail")
	}
	if _, err := EnvelopeBinding([]byte(`{"version":4,"payload":"YQ=="}`)); err == nil {
		t.Fatal("incomplete binding must fail")
	}

	c := testCipher(t)
	binding := testBinding()
	sealed, err := SealEnvelopeBound(c, Secrets{Env: map[string]string{"K": "V"}}, []string{"node-a"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := EnvelopeBinding(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if fields.SandboxID != "sb-1" || fields.IncarnationID != "inc-1" || fields.Version != EnvelopeVersion || fields.Generation != 1 {
		t.Fatalf("binding = %+v", fields)
	}

	if _, err := SealEnvelopeBound(nil, Secrets{Env: map[string]string{"K": "V"}}, []string{"node-a"}, binding); err == nil {
		t.Fatal("nil cipher must fail")
	}
	if _, err := SealRawEnvelopeBound(nil, []byte("x"), []string{"node-a"}, binding); err == nil {
		t.Fatal("nil cipher raw seal must fail")
	}
	if _, err := SealRawEnvelopeWrappedBound([]byte("x"), []string{"node-a"}, binding, nil); err == nil {
		t.Fatal("nil wrap must fail")
	}
	if _, err := SealRawEnvelopeWrappedBound([]byte("x"), nil, binding, func([]byte) ([]byte, error) { return []byte("w"), nil }); err == nil {
		t.Fatal("empty recipients must fail")
	}
	if _, err := SealRawEnvelopeWrappedBound([]byte("x"), []string{"*"}, binding, func([]byte) ([]byte, error) { return []byte("w"), nil }); err == nil {
		t.Fatal("wildcard recipient must fail")
	}
	badBind := binding
	badBind.Generation = 0
	if _, err := SealRawEnvelopeWrappedBound([]byte("x"), []string{"node-a"}, badBind, func([]byte) ([]byte, error) { return []byte("w"), nil }); err == nil {
		t.Fatal("invalid generation must fail")
	}
	if _, err := SealRawEnvelopeWrappedBound([]byte("x"), []string{"node-a"}, binding, func([]byte) ([]byte, error) {
		return nil, errors.New("wrap failed")
	}); err == nil {
		t.Fatal("wrap failure must surface")
	}

	if got, err := OpenEnvelopeBound(c, nil, "node-a", binding); err != nil || got.Env != nil {
		t.Fatalf("empty open = %+v %v", got, err)
	}
	if _, err := OpenEnvelopeBound(c, []byte("not-json"), "node-a", binding); err == nil {
		t.Fatal("bad open must fail")
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

func TestKMSProviderErrorBranches(t *testing.T) {
	ctx := ContextWithIncarnationID(context.Background(), "inc-1")
	sec := Secrets{Registry: &models.RegistryAuth{Password: "p"}}

	if _, err := (*KMSProvider)(nil).Put(ctx, "sb", sec, []string{"n"}); err == nil {
		t.Fatal("nil provider put must fail")
	}
	fake, err := NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKMSProvider(nil, newMemBlobStore()).Put(ctx, "sb", sec, []string{"n"}); err == nil {
		t.Fatal("nil wrapper put must fail")
	}
	if _, err := NewKMSProvider(fake, nil).Put(ctx, "sb", sec, []string{"n"}); err == nil {
		t.Fatal("nil store put must fail")
	}
	if _, err := NewKMSProvider(fake, newMemBlobStore()).Put(ctx, "", sec, []string{"n"}); err == nil {
		t.Fatal("empty sandbox put must fail")
	}
	if _, err := NewKMSProvider(fake, newMemBlobStore()).Put(context.Background(), "sb", sec, []string{"n"}); err == nil {
		t.Fatal("missing incarnation put must fail")
	}
	if _, err := NewKMSProvider(fake, errBlobStore{putErr: errors.New("next fail")}).Put(ctx, "sb", sec, []string{"n"}); err == nil {
		t.Fatal("store next/put failure must surface")
	}

	p := NewKMSProvider(fake, newMemBlobStore())
	if got, err := p.Open(ctx, "sb", Handle{}, "n"); err != nil || got.Env != nil {
		t.Fatalf("empty handle open = %+v %v", got, err)
	}
	if _, err := (*KMSProvider)(nil).Open(ctx, "sb", Handle{Ref: "x", Version: 1, SealGeneration: 1}, "n"); err == nil {
		t.Fatal("nil store open must fail")
	}
	if _, err := p.Open(ctx, "", Handle{Ref: FormatRef("sb", "inc-1", RefVersion), Version: RefVersion, SealGeneration: 1}, "n"); err == nil {
		t.Fatal("empty sandbox open must fail")
	}
	if _, err := p.Open(ctx, "sb", Handle{Ref: FormatRef("sb", "inc-1", RefVersion), Version: RefVersion, SealGeneration: 1}, "n"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing row = %v", err)
	}
	if err := (*KMSProvider)(nil).Delete(ctx, "sb"); err != nil {
		t.Fatalf("nil delete = %v", err)
	}
	if err := p.Delete(ctx, "sb"); err != nil {
		t.Fatalf("delete empty = %v", err)
	}
	if err := mapProviderWrapError(nil); err != nil {
		t.Fatalf("nil map = %v", err)
	}
	if !errors.Is(mapProviderWrapError(ErrProviderThrottled), ErrProviderThrottled) {
		t.Fatal("throttled sentinel must pass through")
	}
	if err := mapProviderWrapError(errors.New("other")); err == nil || err.Error() != "other" {
		t.Fatalf("other map = %v", err)
	}

	// Outbox / retired recipient context fields on Put.
	store := newMemBlobStore()
	p = NewKMSProvider(fake, store)
	putCtx := ContextWithPutOutbox(ctx, "inc-1", []string{"peer-b"})
	putCtx = ContextWithRetiredRecipients(putCtx, []string{"old"})
	h, err := p.Put(putCtx, "sb-outbox", sec, []string{"n"})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := store.Get(ctx, h.Ref)
	if err != nil || rec.OutboxRecipients == nil || rec.RetiredRecipients == nil {
		t.Fatalf("outbox fields missing: %+v %v", rec, err)
	}

	// Corrupt stored JSON after a good put to hit unmarshal failure.
	good, err := p.Put(ctx, "sb-badjson", sec, []string{"n"})
	if err != nil {
		t.Fatal(err)
	}
	row, _ := store.Get(ctx, good.Ref)
	var env sealedSecretsEnvelope
	if err := json.Unmarshal(row.SealedPayload, &env); err != nil {
		t.Fatal(err)
	}
	// Swap payload for valid AEAD of non-JSON so Open unwraps then unmarshal fails.
	// Easier: overwrite SealedPayload with a still-valid envelope of "{".
	bind := SealBinding{SandboxID: "sb-badjson", IncarnationID: "inc-1", Ref: good.Ref, Version: RefVersion, Generation: good.SealGeneration}
	broken, err := SealRawEnvelopeWrappedBound([]byte("{"), []string{"n"}, bind, func(dek []byte) ([]byte, error) {
		return fake.Wrap(ctx, dek, EncryptionContextForBinding(bind))
	})
	if err != nil {
		t.Fatal(err)
	}
	row.SealedPayload = broken
	if err := store.Put(ctx, *row); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Open(ctx, "sb-badjson", good, "n"); err == nil {
		t.Fatal("expected unmarshal failure")
	}
}
