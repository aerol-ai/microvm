package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// sealedPair seals one secret and returns it plus a rewrap of it under
// another key store: same content, different WrappedKey.
func sealedPair(t *testing.T, ref string, gen int64) (sealed, rewrapped []byte) {
	t.Helper()
	ctx := context.Background()
	parsed, err := secrets.ParseRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	binding := secrets.SealBinding{SandboxID: parsed.SandboxID, IncarnationID: parsed.IncarnationID, Ref: ref, Version: secrets.RefVersion, Generation: gen}
	a, _ := secrets.NewFakeKMS()
	b, _ := secrets.NewFakeKMS()
	sealed, err = secrets.SealRawEnvelopeWrappedBound([]byte(`{"env":{"K":"v"}}`), []string{"a"}, binding, func(dek []byte) ([]byte, error) {
		return a.Wrap(ctx, dek, secrets.EncryptionContextForBinding(binding))
	})
	if err != nil {
		t.Fatal(err)
	}
	// Move the data key from a to b: open with a, rewrap with b.
	moved := &movingKMS{from: a, to: b}
	if rewrapped, err = secrets.RewrapEnvelope(ctx, sealed, nil, moved); err != nil {
		t.Fatal(err)
	}
	return sealed, rewrapped
}

type movingKMS struct{ from, to *secrets.FakeKMS }

func (m *movingKMS) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	return m.to.Wrap(ctx, dek, encCtx)
}
func (m *movingKMS) Unwrap(ctx context.Context, w []byte, encCtx map[string]string) ([]byte, error) {
	return m.from.Unwrap(ctx, w, encCtx)
}

// eng D3/D20: a peer copy of one generation that differs only in WrappedKey
// (the sender's own rewrap) is the same secret: idempotent, and the bytes
// already on disk stay. A different payload is still a conflict.
func TestPutClusterSecretIgnoresWrappedKey(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	ref := secrets.FormatRef("sb-rw", "inc-rw", secrets.RefVersion)
	mine, theirs := sealedPair(t, ref, 2)
	now := time.Now().UTC()
	rec := ClusterSecretRecord{Ref: ref, SandboxID: "sb-rw", Version: 1, Recipients: []string{"a"}, SealedPayload: mine, SealGeneration: 2, CreatedAt: now, UpdatedAt: now}
	if _, err := st.PutClusterSecret(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rec.SealedPayload = theirs
	if _, err := st.PutClusterSecret(ctx, rec); err != nil {
		t.Fatalf("same secret, other wrapped key = %v, want idempotent", err)
	}
	got, err := st.GetClusterSecret(ctx, ref)
	if err != nil || !bytes.Equal(got.SealedPayload, mine) {
		t.Fatal("a peer copy replaced this node's own bytes")
	}
	other, _ := sealedPair(t, ref, 2)
	rec.SealedPayload = other
	if _, err := st.PutClusterSecret(ctx, rec); !errors.Is(err, ErrClusterSecretPayloadConflict) {
		t.Fatalf("different payload = %v, want conflict", err)
	}
}

// The sweep's compare-and-swap: it writes only over the exact row it read.
func TestRewrapClusterSecretCompareAndSwap(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	ref := secrets.FormatRef("sb-cas", "inc-cas", secrets.RefVersion)
	old, rewrapped := sealedPair(t, ref, 3)
	now := time.Now().UTC()
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-cas", Version: 1, Recipients: []string{"a"}, SealedPayload: old, SealGeneration: 3, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.RewrapClusterSecret(ctx, ref, 2, old, rewrapped); ok || err != nil {
		t.Fatalf("wrong generation = %v %v, want skipped", ok, err)
	}
	if ok, err := st.RewrapClusterSecret(ctx, ref, 3, rewrapped, rewrapped); ok || err != nil {
		t.Fatalf("stale bytes = %v %v, want skipped", ok, err)
	}
	if ok, err := st.RewrapClusterSecret(ctx, ref, 3, old, rewrapped); !ok || err != nil {
		t.Fatalf("rewrap = %v %v", ok, err)
	}
	got, _ := st.GetClusterSecret(ctx, ref)
	if !bytes.Equal(got.SealedPayload, rewrapped) || got.SealGeneration != 3 {
		t.Fatal("rewrap not stored")
	}
	other, _ := sealedPair(t, ref, 3)
	if _, err := st.RewrapClusterSecret(ctx, ref, 3, rewrapped, other); !errors.Is(err, ErrClusterSecretPayloadConflict) {
		t.Fatalf("content change = %v, want refused", err)
	}
	if ok, err := st.RewrapClusterSecret(ctx, "cluster-secret://sandbox/none/i/x/v1", 1, old, rewrapped); ok || err != nil {
		t.Fatalf("missing row = %v %v", ok, err)
	}
}
