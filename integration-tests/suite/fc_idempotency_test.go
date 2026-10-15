//go:build integration

package suite

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

type idResponse struct {
	ID string `json:"id"`
}

// destroySandbox best-effort removes a sandbox created by a raw facade call
// (these bypass c.NewSandbox's auto-cleanup).
func destroySandbox(t *testing.T, id string) {
	if id == "" {
		return
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = fcDo(t, cctx, http.MethodDelete, "", "/v1/sandboxes/"+id, nil, nil)
	})
}

// UC-239 — v1 create with an Idempotency-Key replays the same sandbox on retry.
func TestV1CreateIdempotencyKeyReplays(t *testing.T) {
	harness.Require(t, sc, "UC-239")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	key := "uc239-" + harness.UniqueName(sc, t)
	hdr := map[string]string{"Idempotency-Key": key}
	body := map[string]any{"image": "alpine:3.20"}

	st1, b1 := fcDo(t, ctx, http.MethodPost, "", "/v1/sandboxes", body, hdr)
	if st1 != http.StatusCreated {
		t.Fatalf("first create status = %d, want 201; body=%s", st1, string(b1))
	}
	var first idResponse
	fcDecode(t, b1, &first)
	destroySandbox(t, first.ID)

	st2, b2 := fcDo(t, ctx, http.MethodPost, "", "/v1/sandboxes", body, hdr)
	if st2 != http.StatusCreated {
		t.Fatalf("replay create status = %d, want 201; body=%s", st2, string(b2))
	}
	var second idResponse
	fcDecode(t, b2, &second)

	if first.ID == "" || second.ID != first.ID {
		t.Fatalf("replay id = %q, want the first id %q (idempotency key must replay)", second.ID, first.ID)
	}
}

// UC-240 — v1 create without an Idempotency-Key makes two distinct sandboxes.
func TestV1CreateNoKeyIsNotIdempotent(t *testing.T) {
	harness.Require(t, sc, "UC-240")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	body := map[string]any{"image": "alpine:3.20"}

	st1, b1 := fcDo(t, ctx, http.MethodPost, "", "/v1/sandboxes", body, nil)
	st2, b2 := fcDo(t, ctx, http.MethodPost, "", "/v1/sandboxes", body, nil)
	if st1 != http.StatusCreated || st2 != http.StatusCreated {
		t.Fatalf("create statuses = %d / %d, want 201/201", st1, st2)
	}
	var a, b idResponse
	fcDecode(t, b1, &a)
	fcDecode(t, b2, &b)
	destroySandbox(t, a.ID)
	destroySandbox(t, b.ID)
	if a.ID == "" || a.ID == b.ID {
		t.Fatalf("keyless creates returned the same id %q; must be distinct", a.ID)
	}
}

// UC-241 — Daytona create with an Idempotency-Key replays the same sandbox.
func TestDaytonaCreateIdempotencyKeyReplays(t *testing.T) {
	harness.Require(t, sc, "UC-241")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	key := "uc241-" + harness.UniqueName(sc, t)
	hdr := map[string]string{"Idempotency-Key": key}
	body := map[string]any{"snapshot": "alpine:3.20"}

	st1, b1 := fcDo(t, ctx, http.MethodPost, "", "/daytona/sandbox", body, hdr)
	if st1 != http.StatusCreated {
		t.Fatalf("first Daytona create status = %d, want 201; body=%s", st1, string(b1))
	}
	var first idResponse
	fcDecode(t, b1, &first)
	destroySandbox(t, first.ID)

	st2, b2 := fcDo(t, ctx, http.MethodPost, "", "/daytona/sandbox", body, hdr)
	if st2 != http.StatusCreated {
		t.Fatalf("replay Daytona create status = %d, want 201; body=%s", st2, string(b2))
	}
	var second idResponse
	fcDecode(t, b2, &second)
	if first.ID == "" || second.ID != first.ID {
		t.Fatalf("Daytona replay id = %q, want %q", second.ID, first.ID)
	}
}

// UC-242 — v1 cluster create with an Idempotency-Key places the sandbox once:
// the retry hits the reservation-conflict replay and resolves to the same id
// and the same placement owner.
func TestV1ClusterCreateIdempotencyPlacesOnce(t *testing.T) {
	harness.Require(t, sc, "UC-242")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	key := "uc242-" + harness.UniqueName(sc, t)
	hdr := map[string]string{"Idempotency-Key": key}
	body := map[string]any{"image": "alpine:3.20"}

	st1, b1 := fcDo(t, ctx, http.MethodPost, "", "/v1/sandboxes", body, hdr)
	if st1 != http.StatusCreated {
		t.Fatalf("first create status = %d, want 201; body=%s", st1, string(b1))
	}
	var first idResponse
	fcDecode(t, b1, &first)
	destroySandbox(t, first.ID)

	st2, b2 := fcDo(t, ctx, http.MethodPost, "", "/v1/sandboxes", body, hdr)
	if st2 != http.StatusCreated {
		t.Fatalf("replay create status = %d, want 201; body=%s", st2, string(b2))
	}
	var second idResponse
	fcDecode(t, b2, &second)
	if first.ID == "" || second.ID != first.ID {
		t.Fatalf("cluster replay id = %q, want %q (reservation-conflict replay)", second.ID, first.ID)
	}
	// Both calls must resolve to the SAME placement owner — i.e. the retry did
	// not place a second sandbox on another node.
	owner, err := c.OwnerNodeID(ctx, first.ID)
	if err != nil || owner == "" {
		t.Fatalf("no placement owner for the idempotent sandbox %s: %v", first.ID, err)
	}
}
