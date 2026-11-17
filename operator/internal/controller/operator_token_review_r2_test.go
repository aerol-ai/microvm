package controller

// Round-2 review repro (issue #1349): the sweep has no age grace. A leader
// that has just started sweeps at once (sweptAt is per process), from its
// own view of the Secret. A token the previous leader made a moment ago and
// is still storing (a leader-election overlap, a slow Secret write) is not
// in that view, so it is revoked; the previous leader's write then makes a
// revoked token the current one, and with every server host-scoped there is
// no admin-token fallback until the 2-minute settle and a re-check re-mint.
// FAILS on 94253e75d.

import (
	"strconv"
	"testing"
	"time"
)

func TestReviewR2SweepRevokesAFreshTokenNotYetStored(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	cur := tokenSecret("avm_cur", "tok_cur", start.Add(-time.Hour), start.Add(29*24*time.Hour))
	r, api, _, _, _ := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t), hostServerPod("prod-server-0", true), cur)
	// The previous leader made this one a second ago and is writing it to
	// the Secret now.
	api.liveTokens = map[string]string{"tok_cur": "aerolvm-operator-1", "tok_9": operatorTokenName(start.Add(-time.Second))}
	reconcileCluster(t, r) // this leader's first pass: sweeps at once
	if revoked(api)["tok_9"] {
		t.Errorf("the sweep revoked tok_9, made %s ago and not yet in this leader's view of the Secret: give the sweep an age grace (skip tokens younger than the revoke wait plus some margin)", strconv.Itoa(1)+"s")
	}
}
