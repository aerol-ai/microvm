package api

// Benchmarks and the CI latency budget for authenticate() (CEO review D21).
//
// Budget: p99 <= 50µs per request on the cached paths (PAT, avm_ token,
// cached JWT), measured through the whole auth middleware: credential
// extraction, the authenticator chain, the post-match steps, metrics, span
// attributes and the context attach. TestAuthenticateLatencyBudget enforces
// it in CI's coverage job (AEROLVM_SCALE_GATES=1), never under -race.
// The cold JWT path (first sight of a token: one RS256 verify, ~50µs on its
// own) has no budget; its benchmark is for trend only.
//
// The Token benchmark runs the real avm_ authenticator (T3,
// internal/identity.TokenAuthenticator) over an in-memory token index, the
// same map read a worker's mirror does: checksum, lookup, SHA-256 of the
// secret, a constant-time compare and the expiry check. The JWT benchmarks
// run the real OIDC verifier (T6) with a 10k-binding identity file (eng
// review E8): the cached path is SHA-256 of the token, an LRU hit and team
// selection over the token's own matched bindings, and must stay inside the
// budget however large the file is.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/internal/identity/identitytest"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

const authLatencyBudgetP99 = 50 * time.Microsecond

// newBenchToken mints one live runner token into a real token index and
// returns the real authenticator over it with the token's plaintext.
func newBenchToken(tb testing.TB) (*identity.TokenAuthenticator, string) {
	tb.Helper()
	tok, err := identitywire.NewAPIToken(nil)
	if err != nil {
		tb.Fatal(err)
	}
	hash := tok.SecretHash()
	var set identity.TokenSet
	set.Put(identity.TokenRecord{ID: tok.ID, Name: "ci-deploy", Role: controlplane.RoleRunner,
		OwnerRef: controlplane.TeamOwnerRef("payments"), ExpiresAt: time.Now().Add(24 * time.Hour), SecretHash: hash[:]})
	return identity.NewTokenAuthenticator(&set, nil), tok.Plaintext()
}

// benchBindings is the identity file size eng review E8 budgets for: a
// 1 MiB file holds about 10k bindings. The cached path must not scan them.
const benchBindings = 10_000

// newBenchJWT is the real OIDC verifier (T6) against an in-process test
// issuer and a 10k-binding identity file, and a token whose groups match
// twenty of those bindings. Cold disables the verified-token cache (a byte
// bound smaller than any entry), so every request verifies the RS256
// signature and scans the bindings.
func newBenchJWT(tb testing.TB, cold bool) (*identity.Verifier, string) {
	tb.Helper()
	iss := identitytest.New(tb)
	var file strings.Builder
	fmt.Fprintf(&file, "version: 1\nissuers:\n  - {name: okta, url: %q, audiences: [cli], claims: {username: email}}\nbindings:\n", iss.URL)
	for i := 0; i < benchBindings; i++ {
		fmt.Fprintf(&file, "  - {issuer: okta, group: g%d, role: runner, team: t%d}\n", i, i%500)
	}
	cfg, err := identity.Parse([]byte(file.String()))
	if err != nil {
		tb.Fatal(err)
	}
	opts := identity.VerifierOptions{HTTPClient: iss.Client()}
	if cold {
		opts.CacheBytes = 1
	}
	v := identity.NewVerifier(func() *identity.Config { return cfg }, opts)
	groups := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		groups = append(groups, "g"+strconv.Itoa(i*499))
	}
	return v, iss.Mint(tb, iss.Claims(time.Now(), "cli", "00u1ab", groups...))
}

// authBenchCase builds the middleware and request one path exercises.
func authBenchCase(tb testing.TB, path string) (http.Handler, *http.Request) {
	tb.Helper()
	var opts []ServerOption
	bearer := "pat-token"
	switch path {
	case "Token":
		tokens, token := newBenchToken(tb)
		opts = append(opts, WithCredentialAuthenticator(controlplane.PrincipalToken, tokens))
		bearer = token
	case "JWTCached", "JWTCold":
		jwt, token := newBenchJWT(tb, path == "JWTCold")
		tokens, _ := newBenchToken(tb)
		opts = append(opts,
			WithCredentialAuthenticator(controlplane.PrincipalToken, tokens),
			WithCredentialAuthenticator(controlplane.PrincipalOIDC, jwt))
		bearer = token
	}
	server := NewServer(discardLogger(), nil, nil, nil, config.Config{IdentityEnabled: true}, "pat-token", nil, opts...)
	handler := server.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/v1/sandboxes", nil)
	req.RemoteAddr = "203.0.113.7:4000"
	req.Header.Set("Authorization", "Bearer "+bearer)
	// Fail fast if the path does not authenticate: a benchmark of a 401
	// would measure the wrong thing.
	rec := httptest.NewRecorder()
	server.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		tb.Fatalf("%s: setup request got %d, want 204", path, rec.Code)
	}
	return handler, req
}

// nopWriter is a ResponseWriter that discards everything without allocating.
type nopWriter struct{ h http.Header }

func (w *nopWriter) Header() http.Header         { return w.h }
func (w *nopWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *nopWriter) WriteHeader(int)             {}

func benchmarkAuthenticate(b *testing.B, path string) {
	handler, req := authBenchCase(b, path)
	w := &nopWriter{h: http.Header{}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkAuthenticatePAT(b *testing.B)       { benchmarkAuthenticate(b, "PAT") }
func BenchmarkAuthenticateToken(b *testing.B)     { benchmarkAuthenticate(b, "Token") }
func BenchmarkAuthenticateJWTCached(b *testing.B) { benchmarkAuthenticate(b, "JWTCached") }
func BenchmarkAuthenticateJWTCold(b *testing.B)   { benchmarkAuthenticate(b, "JWTCold") }

// TestAuthenticateLatencyBudget is the D21 CI gate: p99 of the cached paths
// stays within authLatencyBudgetP99. A shared CI runner can stall any single
// sample, so each path gets three attempts and passes on the first one
// within budget; a real regression misses all three.
func TestAuthenticateLatencyBudget(t *testing.T) {
	if os.Getenv("AEROLVM_SCALE_GATES") != "1" {
		t.Skip("set AEROLVM_SCALE_GATES=1 to run the authenticate latency budget")
	}
	if raceEnabled {
		t.Skip("the race detector makes timings meaningless")
	}
	const samples = 20000
	for _, path := range []string{"PAT", "Token", "JWTCached"} {
		t.Run(path, func(t *testing.T) {
			handler, req := authBenchCase(t, path)
			w := &nopWriter{h: http.Header{}}
			for i := 0; i < 1000; i++ { // warm caches and the expvar maps
				handler.ServeHTTP(w, req)
			}
			var p99 time.Duration
			for attempt := 0; attempt < 3; attempt++ {
				durations := make([]time.Duration, samples)
				for i := range durations {
					start := time.Now()
					handler.ServeHTTP(w, req)
					durations[i] = time.Since(start)
				}
				slices.Sort(durations)
				p99 = durations[samples*99/100]
				if p99 <= authLatencyBudgetP99 {
					t.Logf("%s p99 = %v (budget %v)", path, p99, authLatencyBudgetP99)
					return
				}
			}
			t.Fatalf("%s p99 = %v over three attempts, budget %v", path, p99, authLatencyBudgetP99)
		})
	}
}
