package runloop

import "testing"

// Runloop's create id is the dedupe key (and the base of its create ledger),
// and the request_idempotency ledger carries no owner column — so the owner is
// folded into the id hash. Two tenants sending an identical create body must
// get different ids, or the second would replay the first tenant's devbox (D13).
func TestDevboxIDForRequestIsOwnerNamespaced(t *testing.T) {
	body := []byte(`{"name":"box"}`)
	acme := devboxIDForRequest("acme", "req-1", body)
	globex := devboxIDForRequest("globex", "req-1", body)
	if acme == globex {
		t.Fatalf("same devbox id for different owners: %q", acme)
	}
	// Stable for the same owner + request (so a retry dedupes).
	if again := devboxIDForRequest("acme", "req-1", body); again != acme {
		t.Fatalf("devbox id not stable for the same owner: %q vs %q", acme, again)
	}
}
