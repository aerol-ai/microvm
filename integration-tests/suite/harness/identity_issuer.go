package harness

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/aerol-ai/microvm/internal/identity/identitytest"
)

// The in-harness test issuer (plans/identity-and-access.md task T12).
//
// The AWS nodes cannot reach a process on the operator's machine, so they
// never fetch keys from this issuer: the identity file the suite pushes
// names a jwks_file (T6 reads a static JWKS instead of running discovery),
// and the suite writes that file from the same keys it signs with. The
// issuer still runs a small HTTPS server on 127.0.0.1, for the two clients
// that must discover it the way they would discover Okta: the remote-MCP
// OAuth client (UC-286, in this process) and `aerolvm login --sso --device`
// (UC-282), which runs on a node and reaches this server through an SSH
// reverse forward bound to the same port, so the issuer URL is the same on
// both sides.
//
// Keys and minting are identitytest's (T6's in-process issuer), used through
// its exported key and minting API only: its own httptest server serves no
// device or token endpoint, and is bound to a test's lifetime, while this
// issuer must outlive the first test that starts it.

// Names the test identity file uses. They are part of every principal id the
// issuer's tokens resolve to (oidc:<issuer>:<sub>), so the suite asserts on
// them.
const (
	// IssuerName is the test issuer's identity-file name.
	IssuerName = "itest"
	// K8sIssuerName plays a Kubernetes cluster issuer (UC-284): projected
	// service-account tokens, bound by a claim rather than a group.
	K8sIssuerName = "itest-k8s"
	// K8sIssuerURL never resolves: the nodes read the k8s issuer's keys
	// from K8sJWKSPath, and no client discovers it.
	K8sIssuerURL = "https://oidc.itest-k8s.invalid/clusters/itest"

	// CLIClientID and DashboardClientID are the issuer's clients; both are
	// accepted audiences, as the identity file requires.
	CLIClientID       = "aerolvm-itest-cli"
	DashboardClientID = "aerolvm-itest-dashboard"
	// WorkloadAudience is the audience of tokens the suite presents
	// directly as a bearer, the way a CI job presents its OIDC token.
	WorkloadAudience = "aerolvm-itest"
	// K8sAudience is the projected service-account token's audience.
	K8sAudience = "aerolvm-itest-k8s"
	// K8sServiceAccount is the sub a projected token carries; a claim
	// binding grants it runner on payments.
	K8sServiceAccount = "system:serviceaccount:payments:deployer"
)

// Groups the test identity file binds, and what each grants.
const (
	GroupPaymentsEng     = "payments-eng"     // runner on payments
	GroupCheckoutEng     = "checkout-eng"     // runner on checkout
	GroupPaymentsViewers = "payments-viewers" // viewer on payments
	GroupFleetViewers    = "fleet-viewers"    // viewer on *
	GroupAuditors        = "auditors"         // auditor on *
	GroupAdmins          = "platform-admins"  // admin on *
)

// Teams the identity UCs act for.
const (
	TeamPayments = "payments"
	TeamCheckout = "checkout"
)

// DeviceUser is who the issuer signs in when a device-flow login finishes:
// the test sets it before running the CLI, playing the person who opens the
// verification URL and types the code.
type DeviceUser struct {
	Sub    string
	Groups []string
}

// MCPClient is a client-credentials client the issuer knows, standing in for
// an MCP connector registered with the provider.
type MCPClient struct {
	Sub    string
	Groups []string
}

// TestIssuer is the in-harness OIDC provider.
type TestIssuer struct {
	// URL is the issuer URL, https://127.0.0.1:<port>: the iss of every
	// token it mints and the url the identity file names.
	URL string

	keys *identitytest.Issuer
	k8s  *identitytest.Issuer
	srv  *httptest.Server

	// DeviceGrants, RefreshGrants and ClientCredentialGrants count token
	// endpoint calls of each grant, so UC-282 can prove a refresh happened.
	DeviceGrants           atomic.Int32
	RefreshGrants          atomic.Int32
	ClientCredentialGrants atomic.Int32

	mu         sync.Mutex
	idTokenTTL time.Duration
	deviceUser DeviceUser
	devices    map[string]DeviceUser // device_code → user, until used
	refresh    map[string]DeviceUser // refresh_token → user
	mcpAud     map[string]bool
	mcpClients map[string]MCPClient
}

// NewTestIssuer starts the issuer with one RS256 key, and a separate RS256
// key for the k8s issuer. The server is not tied to t: the suite starts one
// issuer for the whole run, and the caller closes it.
func NewTestIssuer(t testing.TB) *TestIssuer {
	t.Helper()
	ti := &TestIssuer{
		// identitytest's key and minting methods work on a zero Issuer; only
		// New would start its own (test-scoped) server.
		keys:       &identitytest.Issuer{},
		k8s:        &identitytest.Issuer{},
		idTokenTTL: 10 * time.Minute,
		devices:    map[string]DeviceUser{},
		refresh:    map[string]DeviceUser{},
		mcpAud:     map[string]bool{},
		mcpClients: map[string]MCPClient{},
	}
	ti.keys.Rotate(t, jose.RS256)
	ti.k8s.Rotate(t, jose.RS256)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", ti.serveDiscovery)
	mux.HandleFunc("GET /jwks", ti.serveJWKS)
	mux.HandleFunc("POST /device", ti.serveDevice)
	mux.HandleFunc("POST /token", ti.serveToken)
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, _ *http.Request) {
		// The browser flow needs a person at a browser; the suite drives
		// the device flow and mints dashboard tokens directly.
		http.Error(w, "the itest issuer has no browser sign-in; use the device flow", http.StatusBadRequest)
	})
	ti.srv = httptest.NewUnstartedServer(mux)
	ti.srv.StartTLS()
	ti.URL = ti.srv.URL
	ti.keys.URL = ti.URL
	ti.k8s.URL = K8sIssuerURL
	return ti
}

// Close stops the server.
func (i *TestIssuer) Close() { i.srv.Close() }

// Client trusts the issuer's certificate and nothing else.
func (i *TestIssuer) Client() *http.Client { return i.srv.Client() }

// Port is the server's port, which the reverse forward to a node reuses.
func (i *TestIssuer) Port() string {
	return i.URL[strings.LastIndex(i.URL, ":")+1:]
}

// CertificatePEM is the server certificate, for a client on another host to
// trust (SSL_CERT_FILE for the CLI on a node).
func (i *TestIssuer) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.srv.Certificate().Raw})
}

// JWKS is the issuer's published key set: the content of IssuerJWKSPath.
func (i *TestIssuer) JWKS() []byte { return i.keys.JWKS() }

// K8sJWKS is the k8s issuer's key set: the content of K8sJWKSPath.
func (i *TestIssuer) K8sJWKS() []byte { return i.k8s.JWKS() }

// SigningKeyID is the kid new tokens carry.
func (i *TestIssuer) SigningKeyID() string { return i.keys.SigningKey().ID }

// Rotate publishes a new signing key next to the old one and signs with it
// from now on (UC-293). The caller pushes the new JWKS to the nodes.
func (i *TestIssuer) Rotate(t testing.TB) string {
	t.Helper()
	return i.keys.Rotate(t, jose.RS256).ID
}

// SetIDTokenTTL sets the lifetime of ID tokens the token endpoint issues
// (UC-282 shortens it to force a refresh).
func (i *TestIssuer) SetIDTokenTTL(d time.Duration) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.idTokenTTL = d
}

// SetDeviceUser sets who a device-flow login signs in as.
func (i *TestIssuer) SetDeviceUser(u DeviceUser) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.deviceUser = u
}

// AllowMCP registers an MCP audience the client-credentials grant may mint
// for, and a client that may ask.
func (i *TestIssuer) AllowMCP(audience, clientID string, c MCPClient) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.mcpAud[audience] = true
	i.mcpClients[clientID] = c
}

// Claims is an ID-token claim set: issued now, valid for an hour, for aud,
// with an email, a display name and groups.
func (i *TestIssuer) Claims(sub, aud string, groups ...string) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss":            i.URL,
		"sub":            sub,
		"aud":            aud,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
		"email":          sub + "@itest.aerolvm.dev",
		"email_verified": true,
		"name":           "itest " + sub,
	}
	if len(groups) > 0 {
		c["groups"] = append([]string(nil), groups...)
	}
	return c
}

// Mint signs claims with the current signing key.
func (i *TestIssuer) Mint(t testing.TB, claims map[string]any) string {
	t.Helper()
	return i.keys.Mint(t, claims)
}

// Token is a workload token for sub in groups: what a CI job would present.
func (i *TestIssuer) Token(t testing.TB, sub string, groups ...string) string {
	t.Helper()
	return i.Mint(t, i.Claims(sub, WorkloadAudience, groups...))
}

// MintUnknownKey signs claims with a key the issuer never published: a kid
// no node has, which triggers one rate-limited key refetch.
func (i *TestIssuer) MintUnknownKey(t testing.TB, claims map[string]any) string {
	t.Helper()
	key := i.keys.NewKey(t, jose.RS256)
	return i.keys.MintWith(t, claims, identitytest.MintOptions{Key: &key})
}

// MintHS256 is the HMAC-confusion attack: an HS256 token keyed with the
// published JWKS bytes.
func (i *TestIssuer) MintHS256(t testing.TB, claims map[string]any) string {
	t.Helper()
	return identitytest.MintHMAC(t, claims, i.JWKS(), i.SigningKeyID())
}

// MintNone is an alg:none token.
func MintNone(claims map[string]any) string {
	return identitytest.Unsigned(map[string]any{"alg": "none", "typ": "JWT"}, claims)
}

// K8sToken is a projected service-account token for sub (UC-284): the
// shape kubelet mounts, with the kubernetes.io claim block.
func (i *TestIssuer) K8sToken(t testing.TB, sub string) string {
	t.Helper()
	now := time.Now()
	ns, name := "", ""
	if parts := strings.Split(sub, ":"); len(parts) == 4 {
		ns, name = parts[2], parts[3]
	}
	return i.k8s.Mint(t, map[string]any{
		"iss": K8sIssuerURL,
		"sub": sub,
		"aud": []string{K8sAudience},
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      ns,
			"serviceaccount": map[string]any{"name": name, "uid": "00000000-0000-0000-0000-000000000000"},
		},
	})
}

func (i *TestIssuer) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeIssuerJSON(w, http.StatusOK, map[string]any{
		"issuer":                                i.URL,
		"authorization_endpoint":                i.URL + "/authorize",
		"token_endpoint":                        i.URL + "/token",
		"device_authorization_endpoint":         i.URL + "/device",
		"jwks_uri":                              i.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile", "groups", "offline_access"},
		"grant_types_supported": []string{
			"urn:ietf:params:oauth:grant-type:device_code", "refresh_token", "client_credentials",
		},
	})
}

func (i *TestIssuer) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(i.JWKS())
}

// serveDevice starts a device authorization (RFC 8628 §3.2). The code is
// approved at once: the person in this flow is the test.
func (i *TestIssuer) serveDevice(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("client_id") == "" {
		writeIssuerJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	code := randomHex(16)
	i.mu.Lock()
	i.devices[code] = i.deviceUser
	i.mu.Unlock()
	writeIssuerJSON(w, http.StatusOK, map[string]any{
		"device_code":      code,
		"user_code":        strings.ToUpper(randomHex(4)),
		"verification_uri": i.URL + "/activate",
		"expires_in":       300,
		"interval":         1,
	})
}

// serveToken is the token endpoint: the device-code grant and the refresh
// grant return an ID token for the CLI client, the client-credentials grant
// an access token for a registered MCP audience.
func (i *TestIssuer) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeIssuerJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	form := r.PostForm
	clientID := form.Get("client_id")
	if user, _, ok := r.BasicAuth(); ok && clientID == "" {
		clientID = user
	}
	switch form.Get("grant_type") {
	case "urn:ietf:params:oauth:grant-type:device_code":
		i.DeviceGrants.Add(1)
		i.mu.Lock()
		user, ok := i.devices[form.Get("device_code")]
		delete(i.devices, form.Get("device_code"))
		i.mu.Unlock()
		if !ok {
			writeIssuerJSON(w, http.StatusBadRequest, map[string]string{"error": "expired_token"})
			return
		}
		i.writeIDTokens(w, clientID, user)
	case "refresh_token":
		i.RefreshGrants.Add(1)
		i.mu.Lock()
		user, ok := i.refresh[form.Get("refresh_token")]
		// Rotate refresh tokens, as most providers do: a replay of the old
		// one is refused, which is what T7's refresh lock guards against.
		delete(i.refresh, form.Get("refresh_token"))
		i.mu.Unlock()
		if !ok {
			writeIssuerJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		i.writeIDTokens(w, clientID, user)
	case "client_credentials":
		i.ClientCredentialGrants.Add(1)
		aud := form.Get("resource")
		if aud == "" {
			aud = form.Get("audience")
		}
		i.mu.Lock()
		client, known := i.mcpClients[clientID]
		allowed := i.mcpAud[aud]
		i.mu.Unlock()
		if !known || !allowed {
			writeIssuerJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_target"})
			return
		}
		now := time.Now()
		claims := map[string]any{
			"iss": i.URL, "sub": client.Sub, "aud": aud,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"client_id": clientID,
		}
		if len(client.Groups) > 0 {
			claims["groups"] = client.Groups
		}
		token, err := i.mintFromHandler(claims)
		if err != nil {
			writeIssuerJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		writeIssuerJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
	default:
		writeIssuerJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (i *TestIssuer) writeIDTokens(w http.ResponseWriter, clientID string, user DeviceUser) {
	i.mu.Lock()
	ttl := i.idTokenTTL
	i.mu.Unlock()
	if clientID == "" {
		clientID = CLIClientID
	}
	claims := i.Claims(user.Sub, clientID, user.Groups...)
	claims["exp"] = time.Now().Add(ttl).Unix()
	idToken, err := i.mintFromHandler(claims)
	if err != nil {
		writeIssuerJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	refresh := randomHex(24)
	i.mu.Lock()
	i.refresh[refresh] = user
	i.mu.Unlock()
	writeIssuerJSON(w, http.StatusOK, map[string]any{
		"access_token":  randomHex(24),
		"token_type":    "Bearer",
		"expires_in":    int(ttl.Seconds()),
		"refresh_token": refresh,
		"id_token":      idToken,
	})
}

// mintFromHandler signs inside an HTTP handler, which has no testing.TB:
// identitytest's minting reports failure through one, so a recorder
// stands in and turns a failure into an error.
func (i *TestIssuer) mintFromHandler(claims map[string]any) (out string, err error) {
	rec := &failRecorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		out = i.keys.Mint(rec, claims)
	}()
	<-done
	if rec.failed {
		return "", errMintFailed
	}
	return out, nil
}

var errMintFailed = errors.New("itest issuer: signing a token failed")

// failRecorder is the testing.TB identitytest's minting reports through when
// it runs inside a handler. Embedding the interface satisfies its unexported
// method; only the methods minting calls are overridden, and Fatal ends the
// minting goroutine the way it would end a test.
type failRecorder struct {
	testing.TB
	failed bool
}

func (r *failRecorder) Helper() {}

func (r *failRecorder) Fatal(...any) {
	r.failed = true
	runtime.Goexit()
}

func (r *failRecorder) Fatalf(string, ...any) {
	r.failed = true
	runtime.Goexit()
}

func writeIssuerJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
