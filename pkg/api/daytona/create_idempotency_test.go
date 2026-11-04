package daytona

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// daytonaCreateWithKey POSTs a create through the single-node handler,
// optionally carrying an Idempotency-Key, and returns the decoded response.
func daytonaCreateWithKey(t *testing.T, h *handlers, key string) (sandboxResponse, int) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(`{"snapshot":"alpine:3.20"}`))
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	h.createSandbox(rr, req)
	var resp sandboxResponse
	if rr.Code == http.StatusCreated {
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode create response: %v; body=%s", err, rr.Body.String())
		}
	}
	return resp, rr.Code
}

func countSandboxes(t *testing.T, env *daytonaContractEnv) int {
	t.Helper()
	all, err := env.store.List(context.Background())
	if err != nil {
		t.Fatalf("store.List: %v", err)
	}
	return len(all)
}

// A retried Daytona create carrying the same Idempotency-Key must replay the
// first sandbox rather than build a second one. On the pre-fix code the create
// minted a fresh id each call, so the store would hold two sandboxes — this
// test fails there.
func TestDaytonaCreateSandbox_IdempotencyKeyReplays(t *testing.T) {
	env := newDaytonaContractEnv(t)
	h := &handlers{deps: Deps{Service: env.service, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}

	first, code := daytonaCreateWithKey(t, h, "key-abc")
	if code != http.StatusCreated {
		t.Fatalf("first create status = %d, want 201", code)
	}
	if n := countSandboxes(t, env); n != 1 {
		t.Fatalf("after first create, sandbox count = %d, want 1", n)
	}

	second, code := daytonaCreateWithKey(t, h, "key-abc")
	if code != http.StatusCreated {
		t.Fatalf("replay status = %d, want 201", code)
	}
	if n := countSandboxes(t, env); n != 1 {
		t.Fatalf("after replay, sandbox count = %d, want 1 (replay must not build a second sandbox)", n)
	}
	if first.ID == "" || second.ID != first.ID {
		t.Fatalf("replay id = %q, want the first id %q", second.ID, first.ID)
	}
}

// Distinct keys (and no key) stay independent: the mechanism is opt-in and does
// not collapse deliberately distinct creates.
func TestDaytonaCreateSandbox_DistinctKeysStayIndependent(t *testing.T) {
	env := newDaytonaContractEnv(t)
	h := &handlers{deps: Deps{Service: env.service, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}

	a, _ := daytonaCreateWithKey(t, h, "k1")
	b, _ := daytonaCreateWithKey(t, h, "k2")
	c, _ := daytonaCreateWithKey(t, h, "")
	if a.ID == b.ID || a.ID == c.ID || b.ID == c.ID {
		t.Fatalf("distinct/keyless creates collided: %q %q %q", a.ID, b.ID, c.ID)
	}
	if n := countSandboxes(t, env); n != 3 {
		t.Fatalf("sandbox count = %d, want 3", n)
	}
}
