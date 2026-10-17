package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// apiToken registers a fresh avm_ token named name with the fake sandboxd,
// expiring at exp, and returns its plaintext.
func (w *ssoWorld) apiToken(t *testing.T, name string, exp time.Time) (plain, id string) {
	t.Helper()
	tok, err := identitywire.NewAPIToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	w.server.set(func(s *fakeSandboxd) {
		s.tokens[tok.Plaintext()] = models.WhoAmI{
			Principal: models.WhoAmIPrincipal{Kind: "token", ID: tok.ID, Name: name},
			Role:      "runner", Team: "payments", ExpiresAt: &exp,
		}
	})
	return tok.Plaintext(), tok.ID
}

// TestTokenExpiryWarning is D8 and D15: an API token from the environment
// (the CI case) with 6 days left gets DR15's warning on stderr, one with 8
// days gets none; the expiry costs one whoami per token per day, from no
// cache and never from a fresh one; and stdout, --json included, is the
// same with or without the warning.
func TestTokenExpiryWarning(t *testing.T) {
	w := newSSOWorld(t)
	w.server.upstream.AddSandbox(models.Sandbox{Name: "box"})
	h := w.h
	soon, soonID := w.apiToken(t, "ci-deploy", day0.Add(6*24*time.Hour))
	later, _ := w.apiToken(t, "nightly", day0.Add(8*24*time.Hour))
	h.env["SB_API_URL"] = w.server.URL

	h.env["SB_PAT_TOKEN"] = soon
	if code := h.run("list"); code != exitOK {
		t.Fatalf("list = %d %q", code, h.stderr.String())
	}
	checkGolden(t, "token-expiring.golden", h.stderr.String())
	if got := w.server.whoamis(); got != 1 {
		t.Fatalf("no cache: %d whoami calls, want 1", got)
	}
	cache := filepath.Join(h.env["XDG_CACHE_HOME"], "aerolvm", "token-"+soonID+".json")
	b, err := os.ReadFile(cache)
	if err != nil || strings.Contains(string(b), soon) || !strings.Contains(string(b), `"name": "ci-deploy"`) {
		t.Fatalf("cache %s = %s, %v (it must hold the expiry, never the token)", cache, b, err)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(cache); info.Mode().Perm() != 0o600 {
			t.Fatalf("cache mode = %v", info.Mode().Perm())
		}
	}
	listText := h.stdout.String()

	// Cached: the warning again, and no request.
	if code := h.run("list"); code != exitOK || h.stdout.String() != listText || !strings.Contains(h.stderr.String(), `the API token "ci-deploy" expires in 6 days`) {
		t.Fatalf("cached list = %d %q", code, h.stderr.String())
	}
	if got := w.server.whoamis(); got != 1 {
		t.Fatalf("cached: %d whoami calls, want still 1", got)
	}
	// --json stdout is the same with the warning as without it.
	if code := h.run("list", "--json"); code != exitOK || !strings.Contains(h.stderr.String(), "warning:") {
		t.Fatalf("list --json = %d %q", code, h.stderr.String())
	}
	withWarning := h.stdout.String()
	h.env["SB_PAT_TOKEN"] = agenttoolstest.Token
	if code := h.run("list", "--json"); code != exitOK || h.stderr.String() != "" || h.stdout.String() != withWarning {
		t.Fatalf("--json stdout differs with the warning:\n%s\nvs\n%s (stderr %q)", withWarning, h.stdout.String(), h.stderr.String())
	}

	// 8 days left: no warning, after its own one whoami.
	h.env["SB_PAT_TOKEN"] = later
	if code := h.run("list"); code != exitOK || h.stderr.String() != "" || h.stdout.String() != listText {
		t.Fatalf("8 days = %d %q", code, h.stderr.String())
	}
	if got := w.server.whoamis(); got != 2 {
		t.Fatalf("a second token: %d whoami calls, want 2", got)
	}

	// A day later the cache is stale: one more whoami for the first token,
	// through the alias variable this time.
	w.clock.Set(day0.Add(25 * time.Hour))
	delete(h.env, "SB_PAT_TOKEN")
	h.env["SB_API_TOKEN"] = soon
	if code := h.run("list"); code != exitOK || !strings.Contains(h.stderr.String(), "expires in 4 days") {
		t.Fatalf("a day later = %d %q", code, h.stderr.String())
	}
	if got := w.server.whoamis(); got != 3 {
		t.Fatalf("stale cache: %d whoami calls, want 3", got)
	}
}

// TestSavedTokenExpiry: a saved avm_ token's expiry is read at login (one
// whoami), and later commands use the cache.
func TestSavedTokenExpiry(t *testing.T) {
	w := newSSOWorld(t)
	w.server.upstream.AddSandbox(models.Sandbox{Name: "box"})
	h := w.h
	soon, _ := w.apiToken(t, "laptop", day0.Add(36*time.Hour))
	h.app.stdinIsTTY = false
	h.app.stdin = strings.NewReader(soon)
	if code := h.run("login", w.server.URL, "--token-stdin"); code != exitOK {
		t.Fatalf("login = %d %q", code, h.stderr.String())
	}
	if !strings.Contains(h.stderr.String(), `aerolvm: warning: the API token "laptop" expires in 1 day (2026-10-19). Ask an admin for a new one before then.`) || w.server.whoamis() != 1 {
		t.Fatalf("login = %q (%d whoami)", h.stderr.String(), w.server.whoamis())
	}
	if code := h.run("get", "box"); code != exitOK || w.server.whoamis() != 1 || !strings.Contains(h.stderr.String(), "expires in 1 day") {
		t.Fatalf("get = %d %q (%d whoami)", code, h.stderr.String(), w.server.whoamis())
	}
	// A day later the cache is stale; whoami refreshes it from its own
	// answer (one call, not two), so the next command needs none.
	w.clock.Set(day0.Add(30 * time.Hour))
	if code := h.run("whoami"); code != exitOK || w.server.whoamis() != 2 || !strings.Contains(h.stderr.String(), "expires in less than a day (2026-10-19)") {
		t.Fatalf("whoami = %d %q (%d whoami)", code, h.stderr.String(), w.server.whoamis())
	}
	if code := h.run("get", "box"); code != exitOK || w.server.whoamis() != 2 || !strings.Contains(h.stderr.String(), "expires in less than a day (2026-10-19)") {
		t.Fatalf("hours left = %d %q (%d whoami)", code, h.stderr.String(), w.server.whoamis())
	}
	// Past expiry the server refuses the token; no warning is printed.
	w.clock.Set(day0.Add(40 * time.Hour))
	h.run("get", "box")
	if strings.Contains(h.stderr.String(), "warning:") {
		t.Fatalf("an expired token warned: %q", h.stderr.String())
	}
}

func TestCheckTokenExpiryIsQuietOnTrouble(t *testing.T) {
	w := newSSOWorld(t)
	h := w.h
	soon, id := w.apiToken(t, "ci", day0.Add(2*24*time.Hour))
	conn := connection{apiURL: w.server.URL, token: soon}
	cacheDir, _ := h.app.cacheDir()
	cache := filepath.Join(cacheDir, "token-"+id+".json")

	// whoami fails: no warning, no cache, and the command goes on.
	w.server.set(func(s *fakeSandboxd) { s.whoamiCode = 500 })
	h.app.checkTokenExpiry(context.Background(), nil, conn, false)
	if h.stderr.String() != "" {
		t.Fatalf("stderr = %q", h.stderr.String())
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatal("a failed whoami was cached")
	}
	w.server.set(func(s *fakeSandboxd) { s.whoamiCode = 0 })
	for name, entry := range map[string]string{
		"corrupt":          "{not json",
		"another server":   `{"api_url":"https://other.example.com","name":"ci","expires_at":"2026-10-30T00:00:00Z","checked_at":"2026-10-17T14:00:00Z"}`,
		"from the future":  `{"api_url":"` + w.server.URL + `","name":"ci","expires_at":"2026-10-30T00:00:00Z","checked_at":"2026-10-18T14:00:00Z"}`,
		"checked too long": `{"api_url":"` + w.server.URL + `","name":"ci","expires_at":"2026-10-30T00:00:00Z","checked_at":"2026-10-16T14:00:00Z"}`,
	} {
		if err := os.MkdirAll(cacheDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cache, []byte(entry), 0o600); err != nil {
			t.Fatal(err)
		}
		before := w.server.whoamis()
		h.stderr.Reset()
		h.app.checkTokenExpiry(context.Background(), nil, conn, false)
		if w.server.whoamis() != before+1 || !strings.Contains(h.stderr.String(), "expires in 2 days") {
			t.Errorf("%s cache: %d whoami, stderr %q", name, w.server.whoamis()-before, h.stderr.String())
		}
	}
	// No home and no cache directory: nothing to check against.
	h.env = map[string]string{}
	if _, ok := h.app.tokenExpiryPath(soon); ok {
		t.Fatal("a cache path with no home")
	}
	if _, ok := h.app.tokenExpiryPath(agenttoolstest.Token); ok {
		t.Fatal("the operator token has no expiry to cache")
	}
	h.env["HOME"] = "/home/me"
	if dir, ok := h.app.cacheDir(); !ok || dir != filepath.Join("/home/me", ".cache", "aerolvm") {
		t.Fatalf("cacheDir from HOME = %q", dir)
	}
	// A token that never expires is never warned about.
	h.stderr.Reset()
	h.app.warnExpiring(tokenExpiry{Name: "x"})
	if h.stderr.String() != "" {
		t.Fatal("warned about a token with no expiry")
	}
}

// TestWhoAmILayouts pins DR15's whoami layout for each credential: an API
// token with its name and days left, the operator token, and (in
// TestSSOLoginBrowserEndToEnd) an SSO login.
func TestWhoAmILayouts(t *testing.T) {
	w := newSSOWorld(t)
	h := w.h
	plain, _ := w.apiToken(t, "ci-deploy", time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC))
	h.env["SB_API_URL"] = w.server.URL

	h.env["SB_PAT_TOKEN"] = plain
	if code := h.run("whoami"); code != exitOK {
		t.Fatalf("whoami = %d %q", code, h.stderr.String())
	}
	checkGolden(t, "whoami-token.golden", h.stdout.String())
	if code := h.run("whoami", "--explain"); code != exitOK || !strings.HasSuffix(h.stdout.String(), "\nWhy:\n  an API token carries its own role and team; no binding is involved.\n") {
		t.Fatalf("whoami --explain for a token = %q", h.stdout.String())
	}

	h.env["SB_PAT_TOKEN"] = agenttoolstest.Token
	if code := h.run("whoami"); code != exitOK {
		t.Fatalf("whoami = %d %q", code, h.stderr.String())
	}
	checkGolden(t, "whoami-operator.golden", h.stdout.String())
	if code := h.run("whoami", "--explain"); code != exitOK || !strings.Contains(h.stdout.String(), "the server token (sandboxd's SB_PAT_TOKEN) acts as admin on all teams") {
		t.Fatalf("whoami --explain for the PAT = %q", h.stdout.String())
	}
	// --json is sandboxd's answer, unchanged.
	if code := h.run("whoami", "--json"); code != exitOK {
		t.Fatal(code)
	}
	if got := strings.TrimSpace(h.stdout.String()); got != "{\n  \"principal\": {\n    \"kind\": \"operator\",\n    \"id\": \"operator\",\n    \"name\": \"operator\"\n  },\n  \"role\": \"admin\",\n  \"team\": \"*\"\n}" {
		t.Fatalf("whoami --json = %s", got)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"whoami", "extra"}, `unexpected argument "extra"`},
		{[]string{"whoami", "--nope"}, "nope"},
	} {
		if code := h.run(tc.args...); code != exitUsage || !strings.Contains(h.stderr.String(), tc.want) {
			t.Errorf("%v = %d %q", tc.args, code, h.stderr.String())
		}
	}
	h.env["SB_PAT_TOKEN"] = "wrong"
	if code := h.run("whoami"); code != exitError || !strings.Contains(h.stderr.String(), "refused the token in SB_PAT_TOKEN") {
		t.Fatalf("whoami with a wrong token = %d %q", code, h.stderr.String())
	}
}

// TestWhoAmIExplain is D22's golden output: the binding that matched, the
// others that also matched, and only the caller's own claims, from
// sandboxd's explanation; and from the caller's own token when sandboxd
// doesn't explain.
func TestWhoAmIExplain(t *testing.T) {
	w := newSSOWorld(t)
	h := w.h
	w.seedLogin(t, day0.Add(54*time.Minute))
	// The shape pkg/api/v1's whoami sends (TestWhoAmIExplainThroughTheEdge
	// pins the server side of it).
	explain := &identitywire.WhoAmIExplain{
		BindingsApply: true,
		Matched: []identitywire.ExplainBinding{
			{Index: 3, Text: `okta group="payments-eng" -> runner/payments`, InEffect: true},
			{Index: 5, Text: `okta group="everyone" -> viewer/*`},
		},
		Claims: &identitywire.ExplainClaims{Issuer: "okta", Username: "alice@acme.com", Groups: []string{"everyone", "payments-eng"}},
	}
	w.server.set(func(s *fakeSandboxd) { s.explain = explain })
	if code := h.run("whoami", "--explain"); code != exitOK {
		t.Fatalf("whoami --explain = %d %q", code, h.stderr.String())
	}
	checkGolden(t, "whoami-explain.golden", h.stdout.String())
	if code := h.run("whoami", "--explain", "--json"); code != exitOK {
		t.Fatal(code)
	}
	var got whoAmIResponse
	h.jsonOut(&got)
	if got.Explain == nil || len(got.Explain.Matched) != 2 || got.Role != "runner" {
		t.Fatalf("whoami --explain --json = %+v", got)
	}
	if !got.Explain.BindingsApply {
		t.Fatal("bindings_apply was dropped on the way through --json")
	}

	// A managed account: sandboxd's note says where the role comes from.
	w.server.set(func(s *fakeSandboxd) {
		s.tokens["managed-token"] = models.WhoAmI{Principal: models.WhoAmIPrincipal{Kind: "controlplane", ID: "controlplane:u1", Name: "Ana"}, Role: "runner"}
	})
	h.env["SB_PAT_TOKEN"], h.env["SB_API_URL"] = "managed-token", w.server.URL
	if code := h.run("whoami", "--explain"); code != exitOK || !strings.HasSuffix(h.stdout.String(), "\nWhy:\n  binding matching doesn't apply to a controlplane credential.\n") {
		t.Fatalf("managed explain = %d %q", code, h.stdout.String())
	}
	delete(h.env, "SB_PAT_TOKEN")
	delete(h.env, "SB_API_URL")

	// A sandboxd that predates the explanation: the caller's own token.
	w.server.set(func(s *fakeSandboxd) { s.explain = nil })
	if code := h.run("whoami", "--explain"); code != exitOK {
		t.Fatalf("whoami --explain = %d %q", code, h.stderr.String())
	}
	checkGolden(t, "whoami-explain-local.golden", h.stdout.String())

	// An overage explanation says so instead of listing groups.
	w.server.set(func(s *fakeSandboxd) {
		s.explain = &identitywire.WhoAmIExplain{Claims: &identitywire.ExplainClaims{Issuer: "entra", GroupOverage: true, Roles: []string{"AerolVM.Runner"}}}
	})
	if code := h.run("whoami", "--explain"); code != exitOK || !strings.Contains(h.stdout.String(), "groups    too many to list (group overage)\n  roles     AerolVM.Runner\n") {
		t.Fatalf("overage explain = %q", h.stdout.String())
	}

	// No binding: whoami says so in DR15's words, and --explain lists the
	// claims the 403 carried.
	w.server.set(func(s *fakeSandboxd) {
		s.noBinding = &models.ErrorResponse{Error: "no role binding", Reason: "no_binding", Issuer: "okta", Name: "alice@acme.com", Groups: []string{"everyone"}}
	})
	if code := h.run("whoami", "--explain"); code != exitError ||
		h.stdout.String() != "Why:\n  no binding in this sandboxd's identity file matches your sign-in.\n\nYour sign-in carried (issuer okta):\n  username  alice@acme.com\n  groups    everyone\n" ||
		w.normalize(h.stderr.String()) != "aerolvm: signed in as alice@acme.com through Acme Okta, but no access rule on https://api.acme.dev matches your account. Ask your AerolVM admin to add one for a group you're in. Your sign-in carried: everyone.\n" {
		t.Fatalf("no binding = %d\nstdout %q\nstderr %q", code, h.stdout.String(), h.stderr.String())
	}
	if code := h.run("whoami", "--json"); code != exitError || h.stdout.String() != "" || h.errorEnvelope().HTTPStatus != 403 {
		t.Fatalf("no binding --json = %d %q", code, h.stdout.String())
	}
}

func TestAuthTokenVerb(t *testing.T) {
	w := newSSOWorld(t)
	h := w.h
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"auth"}, "expected a subcommand: token"},
		{[]string{"auth", "nope"}, `unknown subcommand "nope"`},
		{[]string{"auth", "token", "extra"}, `unexpected argument "extra"`},
		{[]string{"auth", "token", "--nope"}, "nope"},
	} {
		if code := h.run(tc.args...); code != exitUsage || !strings.Contains(h.stderr.String(), tc.want) {
			t.Errorf("%v = %d %q", tc.args, code, h.stderr.String())
		}
	}
	if code := h.run("auth", "token"); code != exitError || !strings.Contains(h.stderr.String(), "not logged in") {
		t.Fatalf("auth token logged out = %d %q", code, h.stderr.String())
	}
	// An environment token comes back as it is; --json has no expiry for it.
	h.env["SB_PAT_TOKEN"] = "pat-value"
	if code := h.run("auth", "token", "--json"); code != exitOK {
		t.Fatal(code)
	}
	var out map[string]any
	h.jsonOut(&out)
	if out["token"] != "pat-value" || out["api_url"] != defaultAPIURL || out["expires_at"] != nil {
		t.Fatalf("auth token --json = %v", out)
	}
	// An SSO login about to expire is renewed before it is printed.
	delete(h.env, "SB_PAT_TOKEN")
	old := w.seedLogin(t, day0.Add(30*time.Second))
	if code := h.run("auth", "token"); code != exitOK || strings.TrimSpace(h.stdout.String()) == old.Token || strings.TrimSpace(h.stdout.String()) != w.saved(t).Token {
		t.Fatalf("auth token = %d %q", code, h.stdout.String())
	}
}

func TestWhoAmIFormatting(t *testing.T) {
	now := day0
	at := func(d time.Duration) *time.Time { t := now.Add(d); return &t }
	for _, tc := range []struct {
		at   *time.Time
		want string
	}{
		{nil, "never"},
		{at(54 * time.Minute), "in 54m (15:04 UTC)"},
		{at(3*time.Hour + 12*time.Minute), "in 3h12m (17:22 UTC)"},
		{at(2 * time.Hour), "in 2h (16:10 UTC)"},
		{at(40 * time.Second), "in 40s (14:10 UTC)"},
		{at(25 * time.Hour), "in 1 day (2026-10-18)"},
		{at(89 * 24 * time.Hour), "in 89 days (2027-01-14)"},
		{at(-time.Minute), "expired (2026-10-17 14:09 UTC)"},
	} {
		if got := expiresLabel(now, tc.at); got != tc.want {
			t.Errorf("expiresLabel(%v) = %q, want %q", tc.at, got, tc.want)
		}
	}
	for _, tc := range []struct {
		conn connection
		who  models.WhoAmI
		want string
	}{
		{connection{}, models.WhoAmI{Principal: models.WhoAmIPrincipal{Kind: "oidc", ID: "oidc:github-actions:repo:acme/payments"}}, "github-actions"},
		{connection{}, models.WhoAmI{Principal: models.WhoAmIPrincipal{Kind: "oidc", ID: "weird"}}, "oidc"},
		{connection{}, models.WhoAmI{Principal: models.WhoAmIPrincipal{Kind: "controlplane", ID: "controlplane:u1"}}, "managed account"},
		{connection{}, models.WhoAmI{Principal: models.WhoAmIPrincipal{Kind: "node", ID: "node:n3"}}, "node"},
		{connection{}, models.WhoAmI{Principal: models.WhoAmIPrincipal{Kind: "token", ID: "tok_1"}}, `API token "tok_1"`},
	} {
		if got := viaLabel(tc.conn, tc.who); got != tc.want {
			t.Errorf("viaLabel(%+v) = %q, want %q", tc.who.Principal, got, tc.want)
		}
	}
	if teamLabel("*") != "all teams" || teamLabel("") != "-" || teamLabel("payments") != "payments" {
		t.Fatal("teamLabel")
	}
	if principalName(models.WhoAmI{}) != "-" {
		t.Fatal("principalName with nothing")
	}
	a := &app{now: func() time.Time { return now }}
	managed := a.formatExplain(connection{}, whoAmIResponse{WhoAmI: models.WhoAmI{Principal: models.WhoAmIPrincipal{Kind: "controlplane"}}})
	if !strings.Contains(managed, "managed account sets the role; no binding is involved") {
		t.Fatalf("managed explain = %q", managed)
	}
	// An ID token from the environment explains with its own issuer URL.
	jwt := jwtFor(map[string]any{"iss": "https://token.actions.githubusercontent.com", "sub": "repo:acme/payments", "exp": now.Add(time.Hour).Unix()})
	env := a.formatExplain(connection{token: jwt}, whoAmIResponse{WhoAmI: models.WhoAmI{Principal: models.WhoAmIPrincipal{Kind: "oidc", ID: "oidc:gha:repo"}}})
	if !strings.Contains(env, "(issuer https://token.actions.githubusercontent.com):\n  subject   repo:acme/payments\n  groups    (none)\n") {
		t.Fatalf("env token explain = %q", env)
	}
	var round tokenExpiry
	if err := json.Unmarshal([]byte(`{"api_url":"u","name":"n","checked_at":"2026-10-17T00:00:00Z"}`), &round); err != nil || !round.ExpiresAt.IsZero() {
		t.Fatalf("an entry with no expiry = %+v %v", round, err)
	}
}
