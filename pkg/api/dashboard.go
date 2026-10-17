package api

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"expvar"
	"net/http"
	"net/url"
	"strings"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// dashboardHTML is the single-page operator dashboard, embedded so the binary
// is fully self-contained — there is no separate static-asset shipping step
// and no risk of a stale asset on disk diverging from the daemon version.
//
//go:embed dashboard.html
var dashboardHTML []byte

// dashboardPath is where the dashboard is served. On a domain install Caddy
// forwards it from the API domain (its @api matcher lists /ui and /ui/*), so
// https://<api-domain>/ui is the redirect URI and JavaScript origin operators
// register with their identity provider (CEO review D18). The page sends
// itself back to dashboardPath after a provider sign-in.
const dashboardPath = "/ui"

// dashboardScriptSource is the CSP source that allows the page's one inline
// script: 'sha256-<base64 digest>'. It is computed from the embedded page
// when the package loads, so it can never drift from the script the page
// actually serves (plans/identity-and-access.md D19). A page edit that
// breaks the single-script shape fails every test in this package.
var dashboardScriptSource = mustScriptSource(dashboardHTML)

// googleSignIn is Google Identity Services, which the page loads for an
// issuer of kind google (CEO review D2). Its script, its stylesheet and its
// button and account-chooser frames are allowed on every response: the page
// is the same for every server, and which issuers exist is only known at
// request time.
const (
	googleSignInScript = "https://accounts.google.com/gsi/client"
	googleSignInStyle  = "https://accounts.google.com/gsi/style"
	googleSignInFrames = "https://accounts.google.com"
)

// registerDashboard mounts the dashboard page at /ui, expvar JSON metrics at
// /debug/vars, and Prometheus-compatible metrics at /v1/metrics. The page
// itself is served without auth: it carries no secrets, and sign-in happens
// in the page (an identity provider, or a pasted token), whose requests
// then carry the bearer.
//
// /v1/metrics needs metrics.read, which only roles bound to every team hold
// (CEO review D6): the aerolvm_* counters carry the whole fleet's
// operational shape (lease state, queue depths, secret decrypt failures), so
// a team-bound token or a managed tenant may not read them, but a fleet-wide
// read-only viewer token can be a Prometheus scrape credential.
// /debug/vars stays fleet.admin: expvar also exposes process internals.
func (s *Server) registerDashboard(mux apihttp.Mux) {
	mux.Handle("GET "+dashboardPath, http.HandlerFunc(s.serveDashboard))
	mux.Handle("GET "+dashboardPath+"/", http.HandlerFunc(s.serveDashboard))
	mux.Handle("GET /debug/vars", s.route(controlplane.PermFleetAdmin, expvar.Handler()))
	mux.Handle("GET /v1/metrics", s.route(controlplane.PermMetricsRead, http.HandlerFunc(s.servePrometheusMetrics)))
}

func (s *Server) serveDashboard(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", dashboardCSP(s.signInIssuers()))
	_, _ = w.Write(dashboardHTML)
}

// dashboardCSP is the page's Content-Security-Policy (CEO review D19). It is
// built per request because connect-src lists the identity providers the
// page may call (each one's discovery document and token endpoint), and the
// identity file can change at any time. Everything else is fixed:
//   - scripts: the page's own inline script by hash, and Google's sign-in
//     script; no inline event handlers, no eval;
//   - styles: 'unsafe-inline' has no hash next to it, because a hash would
//     make browsers ignore 'unsafe-inline' and block the page's style=
//     attributes; Google's stylesheet is allowed for its button;
//   - no framing of the page, no forms posting anywhere, no <base>.
func dashboardCSP(issuers []identitywire.DiscoveryIssuer) string {
	connect := []string{"'self'"}
	seen := map[string]bool{}
	for _, iss := range issuers {
		if iss.Clients.Dashboard == "" {
			// Without a dashboard client id the page never starts a
			// sign-in with this issuer, so it never calls it.
			continue
		}
		origin, ok := cspOrigin(iss.URL)
		if !ok || seen[origin] {
			continue
		}
		seen[origin] = true
		connect = append(connect, origin)
	}
	return strings.Join([]string{
		"default-src 'none'",
		"script-src " + dashboardScriptSource + " " + googleSignInScript,
		"style-src 'unsafe-inline' " + googleSignInStyle,
		"connect-src " + strings.Join(connect, " "),
		"frame-src " + googleSignInFrames,
		"img-src 'self' data:",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
	}, "; ")
}

// cspOrigin turns an issuer URL into the https origin connect-src lists.
// The identity file already requires an https URL with no user, query or
// fragment; this re-checks the host so no character that could end a CSP
// source (a space, a semicolon, a quote) is ever written into the header.
func cspOrigin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", false
	}
	for _, c := range u.Host {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == ':', c == '[', c == ']':
		default:
			return "", false
		}
	}
	return "https://" + strings.ToLower(u.Host), true
}

func mustScriptSource(page []byte) string {
	src, err := inlineScriptSource(page)
	if err != nil {
		panic(err)
	}
	return src
}

// inlineScriptSource hashes the page's single inline <script>. A browser
// hashes the element's text exactly as served, so the digest covers every
// byte between <script> and </script>.
func inlineScriptSource(page []byte) (string, error) {
	const open, closing = "<script>", "</script>"
	if n := bytes.Count(page, []byte("<script")); n != 1 {
		return "", errors.New("dashboard: the page must have exactly one <script> element")
	}
	start := bytes.Index(page, []byte(open))
	if start < 0 {
		return "", errors.New("dashboard: the page's <script> element must carry no attributes")
	}
	start += len(open)
	end := bytes.Index(page[start:], []byte(closing))
	if end < 0 {
		return "", errors.New("dashboard: the page's <script> element is not closed")
	}
	sum := sha256.Sum256(page[start : start+end])
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'", nil
}
