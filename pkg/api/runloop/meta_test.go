package runloop

import (
	"bytes"
	"testing"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// Runloop's create id is the dedupe key (and the base of its create ledger),
// and the request_idempotency ledger carries no owner column — so the owner is
// folded into the id hash. Two tenants sending an identical create body must
// get different ids, or the second would replay the first tenant's devbox (D13).
func TestDevboxIDForRequestIsOwnerNamespaced(t *testing.T) {
	c, err := secrets.NewCipherRing([]secrets.RingKey{{ID: 0, Key: bytes.Repeat([]byte{1}, 32), Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	id := func(owner string) string {
		t.Helper()
		ids, err := devboxIDsForRequest(ringDigester{c}, owner, "req-1", []byte(`{"name":"box"}`), false)
		if err != nil {
			t.Fatal(err)
		}
		return ids.current
	}
	acme, globex := id("acme"), id("globex")
	if acme == globex {
		t.Fatalf("same devbox id for different owners: %q", acme)
	}
	// Stable for the same owner + request (so a retry dedupes).
	if again := id("acme"); again != acme {
		t.Fatalf("devbox id not stable for the same owner: %q vs %q", acme, again)
	}
}
