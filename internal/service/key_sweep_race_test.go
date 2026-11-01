package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// racingKeyStore runs race once, from inside the key-store call of the
// sweep's rewrap of ref: after the sweep read the row and before its
// compare-and-swap (plans/customer-key-custody.md Section 4, async ordering 2).
type racingKeyStore struct {
	*transitLike
	ref  string
	once sync.Once
	race func()
}

func (r *racingKeyStore) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	if encCtx["aerolvm.ref"] == r.ref {
		r.once.Do(r.race)
	}
	return r.transitLike.Wrap(ctx, dek, encCtx)
}

// wrapAt wraps under one key version, as a peer that has not swept yet does.
func (tl *transitLike) wrapAt(ctx context.Context, v int, dek []byte, encCtx map[string]string) ([]byte, error) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	w, err := tl.keys[v].Wrap(ctx, dek, encCtx)
	return append([]byte(fmt.Sprintf("vault:v%d:", v)), w...), err
}

type sweepRace struct {
	svc *Service
	tl  *transitLike
	p   secrets.Provider
	id  string
	ref string
	inc context.Context
}

// Section 4, async ordering 2: a writer that lands while the sweep waits on
// the key store wins. The sweep never overwrites the writer's row, never
// brings a deleted row back, and leaves the row to the next pass. The
// writer takes the sandbox's secret lock as the real paths do, which also
// proves the sweep does not hold it across the key-store call.
func TestSweepLosesToRacingWriters(t *testing.T) {
	cases := []struct {
		name  string
		write func(e sweepRace) error
		// gone: the writer removes the row. tomb: and leaves a delete fence.
		gone, tomb bool
		// sweepWins: the writer keeps the bytes the sweep read (a
		// same-generation peer copy, eng D20), so the sweep's write stands.
		sweepWins bool
	}{
		{
			name: "new put",
			write: func(e sweepRace) error {
				_, err := e.p.Put(e.inc, e.id, secrets.Secrets{Env: map[string]string{"K": "replaced"}}, []string{"node-a"})
				return err
			},
		},
		{
			name: "repair reseal",
			write: func(e sweepRace) error {
				_, err := e.p.Put(e.inc, e.id, secrets.Secrets{Env: map[string]string{"K": e.id}}, []string{"node-a", "node-b"})
				return err
			},
		},
		{
			// A peer that has not swept yet sends the next generation, still
			// on the old key version: the next pass moves it.
			name: "peer copy, newer generation",
			write: func(e sweepRace) error {
				binding := secrets.SealBinding{SandboxID: e.id, IncarnationID: "inc", Ref: e.ref, Version: secrets.RefVersion, Generation: 2}
				sealed, err := secrets.SealRawEnvelopeWrappedBound([]byte(`{"env":{"K":"peer"}}`), []string{"node-a", "node-b"}, binding, func(dek []byte) ([]byte, error) {
					return e.tl.wrapAt(context.Background(), 1, dek, secrets.EncryptionContextForBinding(binding))
				})
				if err != nil {
					return err
				}
				now := time.Now().UTC()
				_, err = e.svc.store.PutClusterSecret(context.Background(), store.ClusterSecretRecord{Ref: e.ref, SandboxID: e.id, Version: 1, Recipients: []string{"node-a", "node-b"}, SealedPayload: sealed, SealGeneration: 2, CreatedAt: now, UpdatedAt: now})
				return err
			},
		},
		{
			// A peer that already swept sends the same generation under the
			// new version: same content, so the store keeps the bytes on disk.
			name: "peer copy, same generation",
			write: func(e sweepRace) error {
				rec, err := e.svc.store.GetClusterSecret(context.Background(), e.ref)
				if err != nil {
					return err
				}
				peer, err := secrets.RewrapEnvelope(context.Background(), rec.SealedPayload, e.svc.cipher, e.tl)
				if err != nil {
					return err
				}
				rec.SealedPayload = peer
				_, err = e.svc.store.PutClusterSecret(context.Background(), *rec)
				return err
			},
			sweepWins: true,
		},
		{
			name: "originator delete",
			write: func(e sweepRace) error {
				rec, err := e.svc.store.GetClusterSecret(context.Background(), e.ref)
				if err != nil {
					return err
				}
				return e.svc.retireStaleSecretRow(context.Background(), *rec, "inc")
			},
			gone: true, tomb: true,
		},
		{
			name: "lifecycle delete",
			write: func(e sweepRace) error {
				return e.svc.store.DeleteClusterSecretRowsForIncarnation(context.Background(), e.id, "inc")
			},
			gone: true,
		},
		{
			name: "reseal retirement",
			write: func(e sweepRace) error {
				return e.svc.store.RetireClusterSecretGeneration(context.Background(), e.id, "inc", 1)
			},
			gone: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, tl, refs := sweepHarness(t, 1)
			ctx := context.Background()
			p, _, err := secrets.NewProvider(ctx, secrets.ProviderOptions{Name: "vault", Cipher: svc.cipher, Store: newSecretBlobStore(svc.store), Prebuilt: tl})
			if err != nil {
				t.Fatal(err)
			}
			ref := refs[0]
			parsed, _ := secrets.ParseRef(ref)
			e := sweepRace{svc: svc, tl: tl, p: p, id: parsed.SandboxID, ref: ref, inc: secrets.ContextWithIncarnationID(ctx, "inc")}
			read, err := svc.store.GetClusterSecret(ctx, ref)
			if err != nil {
				t.Fatal(err)
			}
			tl.rotate(t)

			var written []byte
			raced := false
			rk := &racingKeyStore{transitLike: tl, ref: ref}
			rk.race = func() {
				raced = true
				done := make(chan error, 1)
				go func() {
					unlock := lockSecretSandboxOps(e.id)
					defer unlock()
					done <- tc.write(e)
				}()
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("racing writer: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("the sweep holds the sandbox's secret lock across the key-store call")
				}
				if rec, err := svc.store.GetClusterSecret(ctx, ref); err == nil {
					written = rec.SealedPayload
				}
			}
			svc.SetKeyStoreWrapper(rk)
			before := keyRowsRewrapped.Value()
			stale, err := svc.SweepKeys(ctx)
			if err != nil || !raced {
				t.Fatalf("sweep = %v, raced %v", err, raced)
			}

			rec, gerr := svc.store.GetClusterSecret(ctx, ref)
			switch {
			case tc.gone:
				if !errors.Is(gerr, store.ErrNotFound) {
					t.Fatalf("the sweep brought a deleted row back: %v", gerr)
				}
			case gerr != nil:
				t.Fatal(gerr)
			case tc.sweepWins:
				if !bytes.Equal(written, read.SealedPayload) {
					t.Fatal("a same-generation peer copy replaced the bytes on disk (eng D20)")
				}
				if v := rowVersion(t, svc, ref); v != "vault:v2" || rec.SealGeneration != 1 {
					t.Fatalf("row on %q gen %d, want the sweep's rewrap", v, rec.SealGeneration)
				}
			default:
				if !bytes.Equal(rec.SealedPayload, written) {
					t.Fatalf("the sweep overwrote the writer's row (gen %d)", rec.SealGeneration)
				}
			}
			// The local row converts either way; the raced row is moved only
			// when the sweep won, and otherwise counts stale until the next pass.
			wantMoved, wantStale := int64(1), 1
			if tc.sweepWins {
				wantMoved, wantStale = 2, 0
			}
			if got := keyRowsRewrapped.Value() - before; got != wantMoved || stale != wantStale {
				t.Fatalf("rewrapped %d, stale %d; want %d, %d", got, stale, wantMoved, wantStale)
			}
			if tc.tomb {
				if g, err := svc.store.ClusterSecretTombGenerationForIncarnation(ctx, e.id, "inc"); err != nil || g <= 0 {
					t.Fatalf("delete fence = %d %v", g, err)
				}
			}

			// The next pass: a deleted row stays deleted, the writer's row
			// ends on the current version with its generation.
			if stale, err := svc.SweepKeys(ctx); err != nil || stale != 0 {
				t.Fatalf("next pass = %d %v", stale, err)
			}
			after, aerr := svc.store.GetClusterSecret(ctx, ref)
			if tc.gone {
				if !errors.Is(aerr, store.ErrNotFound) {
					t.Fatalf("the next pass brought a deleted row back: %v", aerr)
				}
				return
			}
			if aerr != nil {
				t.Fatal(aerr)
			}
			if v := rowVersion(t, svc, ref); v != "vault:v2" || after.SealGeneration != rec.SealGeneration {
				t.Fatalf("after the next pass: %q gen %d, want vault:v2 gen %d", v, after.SealGeneration, rec.SealGeneration)
			}
			if !secrets.SameEnvelopeContent(after.SealedPayload, rec.SealedPayload) {
				t.Fatal("the next pass changed the writer's content")
			}
		})
	}
}
