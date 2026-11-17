package controller

// Review repros for the operator's own admin API token (issue #1349).
// Each test states the behaviour a reviewer expects; each FAILS on
// 0e6d04535.

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
)

func revoked(api *fakeAPI) map[string]bool {
	out := map[string]bool{}
	for _, c := range api.calls("revoke") {
		out[c.id] = true
	}
	return out
}

// A token replaced twice inside the five-minute wait: the first replacement
// (tok_old -> tok_1, rotation) is followed by a refusal of tok_1 two to five
// minutes later (a lagging server, a restore), which re-mints tok_2 through
// the port-forward. storeOperatorToken's first switch case keeps only
// tok_1 as previous_id, so tok_old (role admin, every team, ~9 days left)
// is never revoked.
func TestReviewDoubleReplaceLeavesOldTokenLive(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	old := tokenSecret("avm_old", "tok_old", start.Add(-21*24*time.Hour), start.Add(9*24*time.Hour))
	// A server running the template's settings refuses tok_1 (an old one's
	// refusal no longer re-mints: TestOperatorTokenNotReplacedOnAnOldServersWord).
	r, api, _, cl, now := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t), hostServerPod("prod-server-0", true), old)
	reconcileCluster(t, r) // rotation: tok_1 current, tok_old to revoke at +5m
	if sec := readTokenSecret(t, cl); sec["id"] != "tok_1" || sec["previous_id"] != "tok_old" {
		t.Fatalf("after rotation: %v", sec)
	}
	api.whoami = func(c Credentials) error {
		if c.Token == "avm_secret_1" {
			return &aerolapi.Error{Status: http.StatusUnauthorized, Reason: "unauthorized"}
		}
		return nil
	}
	*now = now.Add(3 * time.Minute)
	reconcileCluster(t, r) // tok_1 refused for > 2m: tok_2 minted, previous_id = tok_1
	t.Logf("after the re-mint: %v", readTokenSecret(t, cl))
	for i := 0; i < 4; i++ {
		*now = now.Add(10 * time.Minute)
		reconcileCluster(t, r)
	}
	got := revoked(api)
	if !got["tok_1"] {
		t.Fatalf("tok_1 not revoked: %v", got)
	}
	if !got["tok_old"] {
		t.Errorf("tok_old (admin, every team, live until %s) was never revoked: revoked %v", start.Add(9*24*time.Hour).Format(time.RFC3339), got)
	}
}

// Turning enterprise mode off (server template no longer host-scoped) while
// a replaced token waits for its revoke: ensureOperatorToken returns before
// revokeReplaced, so the replaced admin token is never revoked.
func TestReviewEnterpriseOffNeverRevokesReplacedToken(t *testing.T) {
	start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	sec := tokenSecret("avm_cur", "tok_cur", start, start.Add(30*24*time.Hour),
		"previous_id", "tok_prev", "previous_revoke_at", start.Add(5*time.Minute).Format(time.RFC3339))
	r, api, _, _, now := tokenRig(t, bootstrapped(testCluster()), adminSecret(), templates(t), serverPod("prod-server-0", true), sec)
	*now = now.Add(10 * time.Minute)
	reconcileCluster(t, r)
	if !revoked(api)["tok_prev"] {
		t.Errorf("tok_prev, past its revoke time, was never revoked once the servers stopped being host-scoped")
	}
}

// Turning identity and enterprise mode on together on a running install:
// until every old server is replaced, some servers (identity off) answer
// every API token 401, so WhoAmI over the Service keeps failing. The
// operator re-mints every ~2.5 minutes, inside the five-minute revoke wait,
// and each re-mint overwrites previous_id: admin tokens pile up unrevoked.
func TestReviewMixedIdentityWindowLeaksTokens(t *testing.T) {
	r, api, _, _, now := tokenRig(t, bootstrapped(testCluster()), adminSecret(), hostScopedTemplates(t), serverPod("prod-server-0", true))
	oldServersLeft := true
	api.whoami = func(Credentials) error {
		if oldServersLeft {
			return &aerolapi.Error{Status: http.StatusUnauthorized, Reason: "unauthorized"}
		}
		return nil
	}
	for i := 0; i < 40; i++ { // 20 minutes of reconciles, 30 s apart
		reconcileCluster(t, r)
		*now = now.Add(30 * time.Second)
	}
	oldServersLeft = false
	for i := 0; i < 40; i++ {
		reconcileCluster(t, r)
		*now = now.Add(30 * time.Second)
	}
	created := api.calls("create")
	got := revoked(api)
	var live []string
	for i := range created[:len(created)-1] { // every token but the current one
		id := "tok_" + strconv.Itoa(i+1)
		if !got[id] {
			live = append(live, id)
		}
	}
	if len(live) > 0 {
		t.Errorf("%d admin tokens made, %d revoked; never revoked (each live for 30 days): %v", len(created), len(got), live)
	}
}
