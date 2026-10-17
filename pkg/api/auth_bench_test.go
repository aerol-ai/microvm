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
// The avm_ token and JWT authenticators arrive in T3 and T6. Until then the
// Token and JWT benchmarks run stub authenticators that do the same work the
// plan budgets for them (§6): a token is a map lookup plus SHA-256 of a
// 32-byte secret and a constant-time compare; a cached JWT is SHA-256 of the
// token and a map hit; a cold JWT verifies an RS256 signature. T3 and T6
// replace the stubs with the real authenticators and keep the same names.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

const authLatencyBudgetP99 = 50 * time.Microsecond

// benchTokenMirror does what T3's in-memory mirror lookup costs.
type benchTokenMirror struct {
	records map[string]benchTokenRecord
}

type benchTokenRecord struct {
	hash   [32]byte
	access controlplane.Access
}

func newBenchTokenMirror() (*benchTokenMirror, string) {
	const id, secret = "7Hq2aBcDeFgH", "s3cr3t-0123456789abcdefghijklmnopqrstuvwxyzAB"
	return &benchTokenMirror{records: map[string]benchTokenRecord{
		id: {hash: sha256.Sum256([]byte(secret)), access: tokenAccess("payments", controlplane.RoleRunner)},
	}}, "avm_" + id + "_" + secret
}

func (m *benchTokenMirror) Authenticate(_ *http.Request, bearer string) (controlplane.Access, bool, error) {
	rest, ok := strings.CutPrefix(bearer, "avm_")
	if !ok {
		return controlplane.Access{}, false, nil
	}
	id, secret, ok := strings.Cut(rest, "_")
	rec, found := m.records[id]
	if !ok || !found {
		return controlplane.Access{}, true, &controlplane.CredentialError{Kind: controlplane.PrincipalToken, Reason: controlplane.RejectUnknownOrRevoked}
	}
	sum := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(sum[:], rec.hash[:]) != 1 {
		return controlplane.Access{}, true, &controlplane.CredentialError{Kind: controlplane.PrincipalToken, Reason: controlplane.RejectUnknownOrRevoked}
	}
	return rec.access, true, nil
}

// benchJWT is a verifier stand-in. With a warm cache it costs what T6's
// verified-token LRU hit costs; cold, it verifies an RS256 signature.
type benchJWT struct {
	key   *rsa.PublicKey
	sig   []byte
	cold  bool
	mu    sync.Mutex
	cache map[[32]byte]controlplane.Access
}

func newBenchJWT(b testing.TB, cold bool) (*benchJWT, string) {
	b.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	signingInput := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIwMHUxYWIiLCJpc3MiOiJodHRwczovL2lkcCJ9"
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		b.Fatal(err)
	}
	j := &benchJWT{key: &priv.PublicKey, sig: sig, cold: cold, cache: map[[32]byte]controlplane.Access{}}
	jwt := signingInput + ".c2lnbmF0dXJl"
	if !cold {
		access := tokenAccess("payments", controlplane.RoleRunner)
		access.Principal = controlplane.Principal{Kind: controlplane.PrincipalOIDC, ID: "oidc:okta:00u1ab"}
		j.cache[sha256.Sum256([]byte(jwt))] = access
	}
	return j, jwt
}

func (j *benchJWT) Authenticate(_ *http.Request, bearer string) (controlplane.Access, bool, error) {
	if strings.Count(bearer, ".") != 2 {
		return controlplane.Access{}, false, nil
	}
	key := sha256.Sum256([]byte(bearer))
	if !j.cold {
		j.mu.Lock()
		access, ok := j.cache[key]
		j.mu.Unlock()
		if ok {
			return access, true, nil
		}
	}
	signingInput := bearer[:strings.LastIndexByte(bearer, '.')]
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(j.key, crypto.SHA256, digest[:], j.sig); err != nil {
		return controlplane.Access{}, true, &controlplane.CredentialError{Kind: controlplane.PrincipalOIDC, Reason: controlplane.RejectInvalidSignature}
	}
	access := tokenAccess("payments", controlplane.RoleRunner)
	access.Principal = controlplane.Principal{Kind: controlplane.PrincipalOIDC, ID: "oidc:okta:00u1ab"}
	return access, true, nil
}

// authBenchCase builds the middleware and request one path exercises.
func authBenchCase(tb testing.TB, path string) (http.Handler, *http.Request) {
	tb.Helper()
	var opts []ServerOption
	bearer := "pat-token"
	switch path {
	case "Token":
		mirror, token := newBenchTokenMirror()
		opts = append(opts, WithCredentialAuthenticator(controlplane.PrincipalToken, mirror))
		bearer = token
	case "JWTCached", "JWTCold":
		jwt, token := newBenchJWT(tb, path == "JWTCold")
		mirror, _ := newBenchTokenMirror()
		opts = append(opts,
			WithCredentialAuthenticator(controlplane.PrincipalToken, mirror),
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
