//go:build integration

package suite

// Keyed digests on a live cluster (UC-366). Two values derived from request
// bodies that carry secrets are HMACs under the server key: the Runloop
// devbox id (from x-request-id and the create body) and the exec record's
// body digest. Unit tests prove the derivation; this proves what only a
// real cluster can: every node derives the same value, so a retry through
// another node still finds its devbox and one command reads the same in
// every owner's audit, and a real daemon records a keyed digest rather than
// silently none.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

var (
	keyedDigestShape = regexp.MustCompile(`^hmac:[0-9]+:[0-9a-f]{64}$`)
	devboxIDShape    = regexp.MustCompile(`^sb-[0-9a-f]{16}$`)
)

// runloopCreateAt creates a devbox through base and returns its id.
func runloopCreateAt(t *testing.T, ctx context.Context, base string, body map[string]any, requestID string) string {
	t.Helper()
	st, b := fcDo(t, ctx, http.MethodPost, base, "/runloop/v1/devboxes", body, map[string]string{"X-Request-Id": requestID})
	if st != http.StatusOK && st != http.StatusCreated {
		t.Fatalf("runloop create through %s = %d; body=%s", base, st, b)
	}
	var dv idResponse
	fcDecode(t, b, &dv)
	if !devboxIDShape.MatchString(dv.ID) {
		t.Fatalf("runloop create through %s returned id %q, want sb-<16 hex>", base, dv.ID)
	}
	destroySandbox(t, dv.ID)
	return dv.ID
}

// UC-366 — keyed digests agree across nodes.
func TestKeyedDigestsAgreeAcrossNodes(t *testing.T) {
	harness.Require(t, sc, "UC-366")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	t.Run("a Runloop create retried through another node gets the same devbox", func(t *testing.T) {
		targets := identityTargets(t)
		if len(targets.Nodes) < 2 {
			t.Skip("needs two nodes")
		}
		a, b := targets.Nodes[0], targets.Nodes[1]
		harness.RequireNodeSSH(t, a)
		harness.RequireNodeSSH(t, b)
		baseA, baseB := nodeBase(t, a), nodeBase(t, b)

		requestID := "uc366-" + harness.UniqueName(sc, t)
		name := "uc366-" + harness.UniqueName(sc, t)
		body := func(secret string) map[string]any {
			return map[string]any{"name": name, "environment_variables": map[string]string{"UC366_SECRET": secret}}
		}
		secret := secretValue(t, "366")
		first := runloopCreateAt(t, ctx, baseA, body(secret), requestID)
		retry := runloopCreateAt(t, ctx, baseB, body(secret), requestID)
		if retry != first {
			t.Fatalf("the same create retried through %s got devbox %s, through %s %s: the nodes derive different ids", b.Name, retry, a.Name, first)
		}
		if other := runloopCreateAt(t, ctx, baseB, body(secretValue(t, "366b")), requestID); other == first {
			t.Fatalf("a create with another env value under the same x-request-id got the first devbox %s", first)
		}
	})

	t.Run("one exec body has one keyed digest on every owner", func(t *testing.T) {
		c := client(t)
		byOwner := map[string]string{} // owner node → a sandbox it runs
		for i := 0; i < 6 && len(byOwner) < 2; i++ {
			sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
			waitRunning(t, sb)
			if owner := resolvePlacementOwner(t, c, sb.ID); owner != "" {
				if _, seen := byOwner[owner]; !seen {
					byOwner[owner] = sb.ID
				}
			}
		}
		if len(byOwner) < 2 {
			t.Skipf("every sandbox landed on one node (%v); the comparison needs two owners", byOwner)
		}

		secret := secretValue(t, "366exec")
		body := map[string]any{"command": "echo uc366", "env": map[string]string{"UC366_SECRET": secret}}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		plain := sha256.Sum256(raw)
		digests := map[string]string{}
		for owner, id := range byOwner {
			if st, b := fcDo(t, ctx, http.MethodPost, "", execPath(id), body, nil); st != http.StatusOK {
				t.Fatalf("exec on %s (owner %s) = %d %s", id, owner, st, b)
			}
			var digest string
			awaitSandboxAudit(t, operatorAPI(), id, auditlog.KindAPI, "", "the exec record", func(evs []auditlog.Event) bool {
				for _, ev := range evs {
					if harness.RouteOf(ev) == routeExec && ev.Request.Digest != "" {
						digest = ev.Request.Digest
						return true
					}
				}
				return false
			})
			if !keyedDigestShape.MatchString(digest) || strings.Contains(digest, hex.EncodeToString(plain[:])) {
				t.Fatalf("the exec record on owner %s holds digest %q, want hmac:<key id>:<64 hex> and not the plain SHA-256 %x", owner, digest, plain)
			}
			harness.AssertNoPlaintext(t, "the exec record's digest", digest, secret)
			digests[owner] = digest
		}
		var want string
		for owner, digest := range digests {
			if want == "" {
				want = digest
			} else if digest != want {
				t.Fatalf("one exec body has two digests across owners: %v (owner %s differs)", digests, owner)
			}
		}
	})
}
