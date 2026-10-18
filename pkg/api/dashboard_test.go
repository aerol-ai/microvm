package api

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// exampleIssuers is the §5.5 identity file as the identity-file watcher
// publishes it: the two people-facing issuers carry client ids, and the two
// workload issuers would not even be listed (they have none). cli-only has
// a CLI client but no dashboard client.
var exampleIssuers = []identitywire.DiscoveryIssuer{
	{Name: "okta", DisplayName: "Acme Okta", Kind: identitywire.IssuerKindOIDC, URL: "https://acme.okta.com/oauth2/default",
		Clients: identitywire.DiscoveryClients{CLI: "0oa1cli", Dashboard: "0oa1dash"}},
	{Name: "google", DisplayName: "Google", Kind: identitywire.IssuerKindGoogle, URL: "https://accounts.google.com",
		Clients: identitywire.DiscoveryClients{CLI: "123-cli.apps.googleusercontent.com", Dashboard: "123-dash.apps.googleusercontent.com"}},
	{Name: "cli-only", DisplayName: "CLI only", Kind: identitywire.IssuerKindOIDC, URL: "https://cli.example.com",
		Clients: identitywire.DiscoveryClients{CLI: "c1"}},
}

func dashboardServer(identity bool, issuers func() []identitywire.DiscoveryIssuer) *Server {
	opts := []ServerOption{}
	if issuers != nil {
		opts = append(opts, WithAuthDiscovery(issuers))
	}
	return NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil,
		config.Config{IdentityEnabled: identity}, "pat-token", nil, opts...)
}

func getUI(t *testing.T, s *Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// cspDirectives splits a policy into directive name → sources.
func cspDirectives(t *testing.T, policy string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, d := range strings.Split(policy, ";") {
		fields := strings.Fields(d)
		if len(fields) == 0 {
			continue
		}
		if _, dup := out[fields[0]]; dup {
			t.Fatalf("directive %s appears twice in %q", fields[0], policy)
		}
		out[fields[0]] = fields[1:]
	}
	return out
}

// servedScript cuts the inline script out of a served page the way a
// browser sees it, independently of inlineScriptSource.
var servedScriptRE = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// TestDashboardCSP is CEO review D19: /ui sends the policy, its script hash
// matches the script actually served, and connect-src is rebuilt from the
// identity file on every request.
func TestDashboardCSP(t *testing.T) {
	t.Run("the script hash matches the served inline script", func(t *testing.T) {
		rec := getUI(t, dashboardServer(false, nil), http.MethodGet, "/ui")
		body := rec.Body.String()
		matches := servedScriptRE.FindAllStringSubmatch(body, -1)
		if len(matches) != 1 {
			t.Fatalf("served page has %d inline scripts, want 1", len(matches))
		}
		sum := sha256.Sum256([]byte(matches[0][1]))
		want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		d := cspDirectives(t, rec.Header().Get("Content-Security-Policy"))
		if got := d["script-src"]; len(got) != 2 || got[0] != want || got[1] != "https://accounts.google.com/gsi/client" {
			t.Fatalf("script-src = %v, want [%s https://accounts.google.com/gsi/client]", got, want)
		}
	})

	t.Run("the fixed directives", func(t *testing.T) {
		d := cspDirectives(t, getUI(t, dashboardServer(false, nil), http.MethodGet, "/ui").Header().Get("Content-Security-Policy"))
		want := map[string]string{
			"default-src":     "'none'",
			"style-src":       "'unsafe-inline' https://accounts.google.com/gsi/style",
			"frame-src":       "https://accounts.google.com",
			"img-src":         "'self' data:",
			"base-uri":        "'none'",
			"form-action":     "'none'",
			"frame-ancestors": "'none'",
		}
		for name, sources := range want {
			if got := strings.Join(d[name], " "); got != sources {
				t.Errorf("%s = %q, want %q", name, got, sources)
			}
		}
		for _, src := range d["style-src"] {
			if strings.HasPrefix(src, "'sha256-") || strings.HasPrefix(src, "'nonce-") {
				t.Errorf("style-src carries %s: browsers would then ignore 'unsafe-inline' and block the page's style= attributes", src)
			}
		}
		if len(d) != 9 {
			t.Errorf("policy has %d directives, want 9: %v", len(d), d)
		}
	})

	cases := []struct {
		name     string
		identity bool
		issuers  []identitywire.DiscoveryIssuer
		want     string
	}{
		{name: "identity off lists only the page's own origin", identity: false, issuers: exampleIssuers, want: "'self'"},
		{name: "identity on without an identity file", identity: true, want: "'self'"},
		{name: "the §5.5 example: the two dashboard issuers' origins", identity: true, issuers: exampleIssuers,
			want: "'self' https://acme.okta.com https://accounts.google.com"},
		{name: "one origin per provider, a bad URL never reaches the header", identity: true, issuers: []identitywire.DiscoveryIssuer{
			{Name: "a", URL: "https://login.example.com/tenant-a/v2.0", Clients: identitywire.DiscoveryClients{Dashboard: "a"}},
			{Name: "b", URL: "https://LOGIN.example.com/tenant-b/v2.0", Clients: identitywire.DiscoveryClients{Dashboard: "b"}},
			{Name: "c", URL: "http://plain.example.com", Clients: identitywire.DiscoveryClients{Dashboard: "c"}},
			{Name: "d", URL: "https://kc.example.com:8443/realms/x", Clients: identitywire.DiscoveryClients{Dashboard: "d"}},
		}, want: "'self' https://login.example.com https://kc.example.com:8443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var src func() []identitywire.DiscoveryIssuer
			if tc.issuers != nil {
				src = func() []identitywire.DiscoveryIssuer { return tc.issuers }
			}
			d := cspDirectives(t, getUI(t, dashboardServer(tc.identity, src), http.MethodGet, "/ui").Header().Get("Content-Security-Policy"))
			if got := strings.Join(d["connect-src"], " "); got != tc.want {
				t.Fatalf("connect-src = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("an identity-file reload changes the next response", func(t *testing.T) {
		var calls atomic.Int32
		s := dashboardServer(true, func() []identitywire.DiscoveryIssuer {
			if calls.Add(1) == 1 {
				return exampleIssuers[:1]
			}
			return exampleIssuers[1:2]
		})
		first := cspDirectives(t, getUI(t, s, http.MethodGet, "/ui").Header().Get("Content-Security-Policy"))["connect-src"]
		second := cspDirectives(t, getUI(t, s, http.MethodGet, "/ui").Header().Get("Content-Security-Policy"))["connect-src"]
		if strings.Join(first, " ") != "'self' https://acme.okta.com" || strings.Join(second, " ") != "'self' https://accounts.google.com" {
			t.Fatalf("connect-src across a reload = %v then %v", first, second)
		}
	})
}

// TestDashboardRoutes: /ui and everything under it serves the page with its
// headers; the page is public (route_registry_test.go's allowlist), and only
// GET is mounted.
func TestDashboardRoutes(t *testing.T) {
	s := dashboardServer(true, func() []identitywire.DiscoveryIssuer { return exampleIssuers })
	for _, path := range []string{"/ui", "/ui/", "/ui/?code=c&state=s", "/ui/anything"} {
		rec := getUI(t, s, http.MethodGet, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
		h := rec.Header()
		for name, want := range map[string]string{
			"Content-Type":           "text/html; charset=utf-8",
			"Cache-Control":          "no-store",
			"X-Content-Type-Options": "nosniff",
		} {
			if got := h.Get(name); got != want {
				t.Errorf("GET %s: %s = %q, want %q", path, name, got, want)
			}
		}
		if !strings.Contains(h.Get("Content-Security-Policy"), "connect-src 'self' https://acme.okta.com https://accounts.google.com;") {
			t.Errorf("GET %s: CSP = %q", path, h.Get("Content-Security-Policy"))
		}
		if rec.Body.String() != string(dashboardHTML) {
			t.Errorf("GET %s did not serve the embedded page", path)
		}
	}
	if rec := getUI(t, s, http.MethodPost, "/ui"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /ui = %d, want 405", rec.Code)
	}
}

func TestInlineScriptSource(t *testing.T) {
	sum := sha256.Sum256([]byte("\nlet a = 1;\n"))
	good := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	cases := []struct {
		name, page, want string
		wantErr          bool
	}{
		{name: "one script", page: "<p>x</p><script>\nlet a = 1;\n</script>", want: good},
		{name: "no script", page: "<p>x</p>", wantErr: true},
		{name: "two scripts", page: "<script>a</script><script>b</script>", wantErr: true},
		{name: "attributes", page: `<script type="module">a</script>`, wantErr: true},
		{name: "not closed", page: "<script>a", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inlineScriptSource([]byte(tc.page))
			if tc.wantErr != (err != nil) || got != tc.want {
				t.Fatalf("inlineScriptSource = %q, %v; want %q, error %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
	defer func() {
		if recover() == nil {
			t.Fatal("mustScriptSource accepted a page with no script")
		}
	}()
	mustScriptSource([]byte("<p>no script</p>"))
}

func TestCSPOrigin(t *testing.T) {
	cases := map[string]string{
		"https://acme.okta.com/oauth2/default": "https://acme.okta.com",
		"https://Accounts.Google.com":          "https://accounts.google.com",
		"https://kc.acme.dev:8443/realms/a":    "https://kc.acme.dev:8443",
		"https://[2001:db8::1]/idp":            "https://[2001:db8::1]",
		"http://acme.okta.com":                 "",
		"https://user@acme.okta.com":           "",
		"https://":                             "",
		"::not a url":                          "",
		"https://acme.okta.com%3Bx":            "",
		"https://bad_host.example.com":         "",
	}
	for raw, want := range cases {
		got, ok := cspOrigin(raw)
		if got != want || ok != (want != "") {
			t.Errorf("cspOrigin(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
}

// TestDashboardPageMarkup pins what the design review fixes in the page's
// markup and CSS (DR4, DR5, DR11–DR14), where no script decides it.
func TestDashboardPageMarkup(t *testing.T) {
	page := string(dashboardHTML)
	markup := servedScriptRE.ReplaceAllString(page, "")
	for _, c := range []struct{ why, want string }{
		{"DR4: the brand, not sandboxd", `<h1 id="box-title" tabindex="-1">AerolVM</h1>`},
		{"DR4: a visible token label", `<label class="field" for="pat-input">API token</label>`},
		{"DR4: the token hint", `<p class="hint" id="pat-hint">An avm_ token or the server's PAT.</p>`},
		{"DR4: the token disclosure", `<summary id="token-summary">Use an API token instead</summary>`},
		{"DR4: the or divider", `<div class="divider" id="or-divider" hidden>or</div>`},
		{"DR7: the switch link", `>Use a different account</button>`},
		{"DR6: the expiry banner", `<div class="banner" id="expiry-banner" role="alert" hidden>`},
		{"DR6: the banner's button", `<button type="button" id="banner-signin">Sign in again</button>`},
		{"DR9: the polite live region", `<div class="msg" id="signin-msg" aria-live="polite"></div>`},
		{"DR10: the CLI pointer's lead-in", `<p>From a terminal:</p>`},
		{"DR13: the accent focus ring", `#login :focus-visible, .banner :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }`},
		{"DR11, DR14: 40 px, full width, --muted2 edge", `#login button.sso-btn { height: 40px; width: 100%; padding: 0 12px; font-size: 14px; border-radius: 4px; border-color: var(--muted2); }`},
		{"DR14: hover stays --accent", `#login button.sso-btn:hover { border-color: var(--accent); }`},
		{"DR5: long names ellipsize", `.who-name { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }`},
		{"DR6: the banner sticks under the header however far the page scrolls", `.topbar { position: sticky; top: 0; z-index: 10; }`},
		{"DR6: the banner in the .pill.warn palette", `.banner { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 8px 16px; background: #231e10; border-bottom: 1px solid #5a4a1c; color: var(--warn); }`},
		{"DR12: the header wraps below 720 px", "@media (max-width: 719px) {\n  header { flex-wrap: wrap;"},
		{"DR12: the name narrows below 720 px", "  .who-name { max-width: 140px; }"},
		{"DR12: the banner wraps below 480 px", "@media (max-width: 479px) {\n  .banner { flex-direction: column; align-items: flex-start; }"},
		{"DR12: boxes use 16 px padding below 400 px", "@media (max-width: 399px) {\n  #login .box { padding: 16px; }"},
	} {
		if !strings.Contains(page, c.want) {
			t.Errorf("%s: page is missing %q", c.why, c.want)
		}
	}
	if strings.Contains(markup, "autofocus") {
		t.Error("the page still has an autofocus attribute; focus follows the DR13 rule instead")
	}
	if strings.Contains(markup, ">sandboxd<") {
		t.Error(`the sign-in box still says "sandboxd" (DR4)`)
	}
	// The CSP bans inline event handlers; a stray onclick= would be dead.
	if m := regexp.MustCompile(`(?i)<[^>]+\son[a-z]+\s*=`).FindString(markup); m != "" {
		t.Errorf("inline event handler in the markup: %s", m)
	}
}

// TestDashboardPageLogic runs the page's sign-in logic under node:
// pkg/api/testdata/dashboard_test.mjs covers button filtering and labels,
// the token disclosure, header pills, the no-access screen, the focus rule,
// renewal single-flight, view save and restore, sign-out, the prompt choice,
// token handling and the DR9 wording (task T8). The page's functions touch
// no DOM, so plain node runs them; no browser and no network.
//
// Node is installed on the CI runners; a machine without it skips this
// test, and `node --test` can run the file by hand (see its header).
func TestDashboardPageLogic(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; the page-logic tests need it")
	}
	matches := servedScriptRE.FindSubmatch(dashboardHTML)
	if matches == nil {
		t.Fatal("no inline script in the page")
	}
	script := filepath.Join(t.TempDir(), "dashboard-inline.js")
	if err := os.WriteFile(script, matches[1], 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, "--test", filepath.Join("testdata", "dashboard_test.mjs"))
	cmd.Env = append(os.Environ(), "DASHBOARD_SCRIPT="+script, "NODE_OPTIONS=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node --test testdata/dashboard_test.mjs: %v\n%s", err, out)
	}
	if !regexp.MustCompile(`(?m)^# fail 0$`).Match(out) || !regexp.MustCompile(`(?m)^# pass [1-9]`).Match(out) {
		t.Fatalf("node reported no passing run:\n%s", out)
	}
}
