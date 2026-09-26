package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func putHolders(t *testing.T, st *store.Store, sb *models.Sandbox, recipients []string, gen int64) {
	t.Helper()
	rec := store.ClusterSecretRecord{
		Ref:            secrets.FormatRef(sb.ID, sb.AuditIncarnationID, secrets.RefVersion),
		SandboxID:      sb.ID,
		Version:        secrets.RefVersion,
		Recipients:     recipients,
		SealedPayload:  []byte("sealed-bytes-not-plaintext"),
		SealGeneration: gen,
	}
	if _, err := st.PutClusterSecret(context.Background(), rec); err != nil {
		t.Fatalf("PutClusterSecret: %v", err)
	}
}

func TestSecretHoldersReportsRecipientSet(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	sb := seedSandbox(t, st, "sb-holders", models.SandboxStatusStarted, 1, 1024)
	// Deliberately unsorted, with a blank entry: callers compare two reads for
	// equality, so the view must normalise rather than make every caller do it.
	putHolders(t, st, sb, []string{"node-c", "node-a", "", "node-b"}, 7)

	got, err := svc.SecretHoldersForSandbox(ctx, sb.ID)
	if err != nil {
		t.Fatalf("SecretHoldersForSandbox() error = %v", err)
	}
	if len(got.Holders) != 3 || got.Holders[0] != "node-a" || got.Holders[2] != "node-c" {
		t.Fatalf("holders = %v, want sorted [node-a node-b node-c]", got.Holders)
	}
	if got.SealGeneration != 7 {
		t.Errorf("seal generation = %d, want 7 — without it a caller cannot tell a reseal from no change", got.SealGeneration)
	}
	if got.SandboxID != sb.ID || got.IncarnationID != sb.AuditIncarnationID {
		t.Errorf("identity = %s/%s, want %s/%s", got.SandboxID, got.IncarnationID, sb.ID, sb.AuditIncarnationID)
	}
	if got.Ref == "" {
		t.Error("ref is empty; audit records reference secrets by ref, so correlation needs it")
	}
}

// An UNKNOWN sandbox must 404, while a KNOWN sandbox with no sealed secret
// must report an empty set. Collapsing the two would let a test for "secrets
// were removed on delete" pass against a typo'd sandbox id.
func TestSecretHoldersDistinguishesUnknownFromEmpty(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)

	if _, err := svc.SecretHoldersForSandbox(ctx, "sb-does-not-exist"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown sandbox error = %v, want store.ErrNotFound", err)
	}

	sb := seedSandbox(t, st, "sb-no-secret", models.SandboxStatusStarted, 1, 1024)
	got, err := svc.SecretHoldersForSandbox(ctx, sb.ID)
	if err != nil {
		t.Fatalf("known sandbox with no secret: %v", err)
	}
	if got.Holders == nil || len(got.Holders) != 0 {
		t.Fatalf("holders = %v, want an empty (non-nil) slice", got.Holders)
	}
}

// Outbox state is what separates a converged fan-out from one still in
// flight. Without it a caller asserting "all three nodes hold a copy" would
// be asserting against a moving target.
func TestSecretHoldersSurfacesPendingOutbox(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	sb := seedSandbox(t, st, "sb-outbox", models.SandboxStatusStarted, 1, 1024)
	putHolders(t, st, sb, []string{"node-a", "node-b"}, 3)

	// The outbox row is journalled in the SAME transaction as the sealed row,
	// so it is seeded through PutClusterSecret rather than updated after.
	pending := []string{"node-b"}
	rec := store.ClusterSecretRecord{
		Ref:                    secrets.FormatRef(sb.ID, sb.AuditIncarnationID, secrets.RefVersion),
		SandboxID:              sb.ID,
		Version:                secrets.RefVersion,
		Recipients:             []string{"node-a", "node-b"},
		SealedPayload:          []byte("sealed-bytes-not-plaintext"),
		SealGeneration:         3,
		PutOutboxIncarnationID: sb.AuditIncarnationID,
		PutOutboxRecipients:    &pending,
	}
	if _, err := st.PutClusterSecret(ctx, rec); err != nil {
		t.Fatalf("PutClusterSecret with outbox: %v", err)
	}
	got, err := svc.SecretHoldersForSandbox(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.PendingPut) != 1 || got.PendingPut[0] != "node-b" {
		t.Fatalf("pending_put = %v, want [node-b]", got.PendingPut)
	}
}

// The view must never carry the sealed payload. This is an observability
// read reachable with an operator PAT; leaking ciphertext here would make it
// a second exfiltration path for the thing the subsystem protects.
func TestSecretHoldersCarriesNoCiphertext(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	sb := seedSandbox(t, st, "sb-nopayload", models.SandboxStatusStarted, 1, 1024)
	putHolders(t, st, sb, []string{"node-a"}, 1)

	got, err := svc.SecretHoldersForSandbox(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"sealed-bytes-not-plaintext", "SealedPayload", "sealed_payload"} {
		if strings.Contains(string(blob), forbidden) {
			t.Fatalf("the holders view serialised secret material (%s): %s", forbidden, blob)
		}
	}
}

// A blank id must not reach the store as a wildcard-ish lookup. The handler
// rejects it with 400 first; this pins the service's own guard so the two
// cannot drift apart into a path where "" means "any sandbox".
func TestSecretHoldersRejectsBlankID(t *testing.T) {
	svc, _, _ := newCapacityHarness(t, nil, nil)
	for _, id := range []string{"", "   "} {
		if _, err := svc.SecretHoldersForSandbox(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("id %q: err = %v, want store.ErrNotFound", id, err)
		}
	}
}

// A store failure that is NOT "not found" must propagate, not be reported as
// an empty holder set. Returning "no holders" for a broken database would let
// a scenario conclude that secrets had been cleaned up when nothing was read.
func TestSecretHoldersPropagatesStoreFailure(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	sb := seedSandbox(t, st, "sb-broken-store", models.SandboxStatusStarted, 1, 1024)
	putHolders(t, st, sb, []string{"node-a"}, 1)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := svc.SecretHoldersForSandbox(ctx, sb.ID)
	if err == nil {
		t.Fatal("a closed store reported success")
	}
	if errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a broken store was reported as not-found: %v", err)
	}
}
