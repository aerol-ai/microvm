package identity

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// staleLookup wraps a TokenSet with a switchable freshness, the way a
// mirror that lost the server tier answers.
type staleLookup struct {
	TokenSet
	stale atomic.Bool
	calls atomic.Int64
}

func (s *staleLookup) LookupToken(id string) (TokenRecord, bool, bool) {
	s.calls.Add(1)
	rec, found, _ := s.TokenSet.LookupToken(id)
	return rec, found, !s.stale.Load()
}

func wantReason(t *testing.T, err error, want controlplane.RejectReason) {
	t.Helper()
	ce, ok := controlplane.AsCredentialError(err)
	if !ok || ce.Kind != controlplane.PrincipalToken || ce.Reason != want {
		t.Fatalf("err = %v, want token refusal %q", err, want)
	}
}

// TestTokenAuthenticator is one table over every outcome of the apiToken
// authenticator: the checksum comes before any lookup, unknown and revoked
// look alike, expiry is enforced at check time, and the stale-mirror rule
// (D16) refuses everything but metrics.read.
func TestTokenAuthenticator(t *testing.T) {
	lookup := &staleLookup{}
	live, liveRec := mint(t, "ci-deploy", "payments", controlplane.RoleRunner)
	expired, expiredRec := mint(t, "old", "payments", controlplane.RoleRunner)
	expiredRec.ExpiresAt = testNow.Add(-time.Second)
	revoked, revokedRec := mint(t, "gone", "payments", controlplane.RoleRunner)
	unknown, _ := mint(t, "never", "payments", controlplane.RoleRunner)
	lookup.Put(liveRec)
	lookup.Put(expiredRec)
	lookup.Put(revokedRec)
	lookup.Delete(revokedRec.ID)
	wrongSecret := identitywire.APIToken{ID: live.ID, Secret: unknown.Secret}
	// The live token with its last checksum character changed: always a
	// different character, so the checksum never holds by chance.
	plain := live.Plaintext()
	last := byte('0')
	if plain[len(plain)-1] == '0' {
		last = '1'
	}
	brokenChecksum := plain[:len(plain)-1] + string(last)

	var logs bytes.Buffer
	a := NewTokenAuthenticator(lookup, slog.New(slog.NewTextHandler(&logs, nil)))
	a.now = func() time.Time { return testNow }

	cases := []struct {
		name       string
		bearer     string
		perm       controlplane.Permission
		stale      bool
		unmatched  bool
		reason     controlplane.RejectReason
		wantStale  bool
		wantLookup bool
		ok         bool
	}{
		{name: "not a token", bearer: "pat-token", unmatched: true},
		{name: "jwt shaped", bearer: "eyJ.a.b", unmatched: true},
		{name: "malformed: no lookup", bearer: "avm_nope", reason: controlplane.RejectMalformed},
		{name: "checksum broken: no lookup", bearer: brokenChecksum, reason: controlplane.RejectMalformed},
		{name: "live", bearer: live.Plaintext(), perm: controlplane.PermSandboxRead, ok: true, wantLookup: true},
		{name: "unknown id", bearer: unknown.Plaintext(), reason: controlplane.RejectUnknownOrRevoked, wantLookup: true},
		{name: "revoked", bearer: revoked.Plaintext(), reason: controlplane.RejectUnknownOrRevoked, wantLookup: true},
		{name: "right id, wrong secret", bearer: wrongSecret.Plaintext(), reason: controlplane.RejectUnknownOrRevoked, wantLookup: true},
		{name: "expired", bearer: expired.Plaintext(), reason: controlplane.RejectExpired, wantLookup: true},
		{name: "stale mirror refuses sandbox.read", bearer: live.Plaintext(), perm: controlplane.PermSandboxRead, stale: true, wantStale: true, wantLookup: true},
		{name: "stale mirror refuses an unknown route", bearer: live.Plaintext(), stale: true, wantStale: true, wantLookup: true},
		{name: "stale mirror refuses unknown tokens as stale too", bearer: unknown.Plaintext(), perm: controlplane.PermSandboxExec, stale: true, wantStale: true, wantLookup: true},
		{name: "stale mirror accepts metrics.read", bearer: live.Plaintext(), perm: controlplane.PermMetricsRead, stale: true, ok: true, wantLookup: true},
		{name: "stale metrics.read still checks the secret", bearer: wrongSecret.Plaintext(), perm: controlplane.PermMetricsRead, stale: true, reason: controlplane.RejectUnknownOrRevoked, wantLookup: true},
		{name: "stale metrics.read still checks expiry", bearer: expired.Plaintext(), perm: controlplane.PermMetricsRead, stale: true, reason: controlplane.RejectExpired, wantLookup: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookup.stale.Store(tc.stale)
			before := lookup.calls.Load()
			r := httptest.NewRequest("GET", "/v1/x", nil)
			if tc.perm != "" {
				r = r.WithContext(controlplane.ContextWithRoutePermission(r.Context(), tc.perm))
			}
			access, matched, err := a.Authenticate(r, tc.bearer)
			if lookedUp := lookup.calls.Load() > before; lookedUp != tc.wantLookup {
				t.Fatalf("lookup happened = %v, want %v", lookedUp, tc.wantLookup)
			}
			switch {
			case tc.unmatched:
				if matched || err != nil {
					t.Fatalf("matched=%v err=%v for a non-token bearer", matched, err)
				}
			case tc.ok:
				if !matched || err != nil || access.Principal.ID != liveRec.ID || access.Role != controlplane.RoleRunner || access.Team() != "payments" {
					t.Fatalf("access=%+v matched=%v err=%v", access, matched, err)
				}
			case tc.wantStale:
				if !matched || !errors.Is(err, controlplane.ErrIdentityStale) {
					t.Fatalf("matched=%v err=%v, want ErrIdentityStale", matched, err)
				}
			default:
				if !matched {
					t.Fatal("an avm_ bearer is always matched")
				}
				wantReason(t, err, tc.reason)
			}
		})
	}
}

// A stale accept is counted every time and logged at most once a minute.
func TestTokenAuthenticatorStaleAcceptAccounting(t *testing.T) {
	lookup := &staleLookup{}
	tok, rec := mint(t, "scrape", controlplane.FleetTeam, controlplane.RoleViewer)
	lookup.Put(rec)
	lookup.stale.Store(true)
	var logs bytes.Buffer
	a := NewTokenAuthenticator(lookup, slog.New(slog.NewTextHandler(&logs, nil)))
	now := testNow
	a.now = func() time.Time { return now }
	r := httptest.NewRequest("GET", "/v1/metrics", nil)
	r = r.WithContext(controlplane.ContextWithRoutePermission(r.Context(), controlplane.PermMetricsRead))
	before := staleAccepts.Value()
	for i := 0; i < 5; i++ {
		if _, _, err := a.Authenticate(r, tok.Plaintext()); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(61 * time.Second)
	if _, _, err := a.Authenticate(r, tok.Plaintext()); err != nil {
		t.Fatal(err)
	}
	if got := staleAccepts.Value() - before; got != 6 {
		t.Fatalf("stale accepts counted = %d, want 6", got)
	}
	if n := strings.Count(logs.String(), "stale token mirror"); n != 2 {
		t.Fatalf("stale accept logged %d times, want 2 (once a minute):\n%s", n, logs.String())
	}
	// Without a logger it still counts and never panics.
	quiet := NewTokenAuthenticator(lookup, nil)
	if _, _, err := quiet.Authenticate(r, tok.Plaintext()); err != nil {
		t.Fatal(err)
	}
}

// TestTokenSprayMakesNoServerTierCalls is the D21 spray test: 10,000
// malformed and unknown tokens against a synced mirror are all refused with
// the right reason, and the mirror's feed (the only path to the server tier)
// is never called. Malformed ones never even reach the lookup.
func TestTokenSprayMakesNoServerTierCalls(t *testing.T) {
	feed := newFakeFeed()
	_, rec := mint(t, "ci", "payments", controlplane.RoleRunner)
	feed.put(rec)
	m := NewTokenMirror(feed, MirrorConfig{Now: func() time.Time { return testNow }})
	if err := m.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	callsAfterSync := feed.calls.Load()
	counting := &countingLookup{inner: m}
	a := NewTokenAuthenticator(counting, nil)
	a.now = func() time.Time { return testNow }

	unknown := make([]string, 64)
	for i := range unknown {
		tok, _ := mint(t, "x", "payments", controlplane.RoleRunner)
		unknown[i] = tok.Plaintext()
	}
	const spray = 10000
	start := time.Now()
	malformed, notFound := 0, 0
	for i := 0; i < spray; i++ {
		bearer := unknown[i%len(unknown)]
		if i%2 == 0 {
			bearer = fmt.Sprintf("avm_%062d", i) // right length class, bad checksum and alphabet
		}
		r := httptest.NewRequest("GET", "/v1/sandboxes", nil)
		_, matched, err := a.Authenticate(r, bearer)
		ce, ok := controlplane.AsCredentialError(err)
		if !matched || !ok {
			t.Fatalf("request %d: matched=%v err=%v", i, matched, err)
		}
		switch ce.Reason {
		case controlplane.RejectMalformed:
			malformed++
		case controlplane.RejectUnknownOrRevoked:
			notFound++
		default:
			t.Fatalf("request %d: reason %q", i, ce.Reason)
		}
	}
	elapsed := time.Since(start)
	if got := feed.calls.Load() - callsAfterSync; got != 0 {
		t.Fatalf("the spray made %d server-tier calls, want 0", got)
	}
	if malformed != spray/2 || notFound != spray/2 {
		t.Fatalf("malformed=%d unknown=%d", malformed, notFound)
	}
	if counting.n.Load() != int64(notFound) {
		t.Fatalf("lookups = %d: malformed tokens must never reach the lookup", counting.n.Load())
	}
	t.Logf("%d sprayed tokens checked in %v (%.0f/s), 0 server-tier calls", spray, elapsed, float64(spray)/elapsed.Seconds())
}

type countingLookup struct {
	inner TokenLookup
	n     atomic.Int64
}

func (c *countingLookup) LookupToken(id string) (TokenRecord, bool, bool) {
	c.n.Add(1)
	return c.inner.LookupToken(id)
}
