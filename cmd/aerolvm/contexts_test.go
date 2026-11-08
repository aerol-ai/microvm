package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Contexts (contexts.go): several logins, config.json always the current
// one, older CLIs unharmed.

func readContexts(t *testing.T, dir string) contextsFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "aerolvm", "contexts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f contextsFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func writeTestJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := writeJSONFile(path, v); err != nil {
		t.Fatal(err)
	}
}

// loginTo logs h in to url with the fake's token through --token-stdin.
func loginTo(t *testing.T, h *harness, url string, extra ...string) {
	t.Helper()
	h.app.stdinIsTTY = false
	h.app.stdin = strings.NewReader(agenttoolstest.Token)
	if code := h.run(append([]string{"login", url, "--token-stdin"}, extra...)...); code != exitOK {
		t.Fatalf("login %s = %d %q", url, code, h.stderr.String())
	}
}

func TestLoginRecordsContextsAndUseContextSwitches(t *testing.T) {
	h, path := loginHarness(t)
	dir := filepath.Dir(filepath.Dir(path))
	other := agenttoolstest.New(t)
	h.fake.AddSandbox(models.Sandbox{Name: "on-a"})
	other.AddSandbox(models.Sandbox{Name: "on-b"})

	loginTo(t, h, h.fake.URL, "--name", "a")
	if !strings.Contains(h.stderr.String(), `saved as context "a"`) {
		t.Fatalf("login note = %q", h.stderr.String())
	}
	loginTo(t, h, other.URL) // named after its host
	hostB := contextNameFor(other.URL)
	f := readContexts(t, dir)
	if f.CurrentContext != hostB || len(f.Contexts) != 2 || f.Contexts["a"].APIURL != h.fake.URL {
		t.Fatalf("contexts = %+v", f)
	}
	if got := readSaved(t, path); got.APIURL != other.URL {
		t.Fatalf("config.json = %+v, want the current context", got)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(filepath.Join(dir, "aerolvm", "contexts.json")); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("contexts.json mode = %v %v", info.Mode().Perm(), err)
		}
	}

	if code := h.run("config", "get-contexts"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	out := h.stdout.String()
	currentLine := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "*") {
			currentLine = line
		}
	}
	if !strings.Contains(out, "CURRENT") || !strings.Contains(currentLine, hostB) || strings.Contains(out, agenttoolstest.Token) {
		t.Fatalf("get-contexts = %q", out)
	}
	if code := h.run("config", "current-context"); code != exitOK || h.stdout.String() != hostB+"\n" {
		t.Fatalf("current-context = %q", h.stdout.String())
	}
	if code := h.run("list"); code != exitOK || !strings.Contains(h.stdout.String(), "on-b") {
		t.Fatalf("list on the current context = %q", h.stdout.String())
	}
	if code := h.run("config", "use-context", "a"); code != exitOK || !strings.Contains(h.stderr.String(), `switched to context "a"`) {
		t.Fatalf("use-context = %d %q", code, h.stderr.String())
	}
	if got := readSaved(t, path); got.APIURL != h.fake.URL {
		t.Fatalf("config.json after use-context = %+v", got)
	}
	if code := h.run("list"); code != exitOK || !strings.Contains(h.stdout.String(), "on-a") {
		t.Fatalf("list after use-context = %q", h.stdout.String())
	}
	// Using the current context again is a no-op; --json says which.
	if code := h.run("config", "use-context", "a", "--json"); code != exitOK || !strings.Contains(h.stdout.String(), `"current_context": "a"`) {
		t.Fatalf("use-context --json = %q", h.stdout.String())
	}
	if code := h.run("config", "get-contexts", "--json"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	var listed struct {
		Current  string       `json:"current_context"`
		Contexts []contextRow `json:"contexts"`
	}
	h.jsonOut(&listed)
	if listed.Current != "a" || len(listed.Contexts) != 2 || listed.Contexts[1].Name != "a" || !listed.Contexts[1].Current || listed.Contexts[1].Auth != "token" || listed.Contexts[0].Current {
		t.Fatalf("get-contexts --json = %+v", listed)
	}
	if code := h.run("config", "current-context", "--json"); code != exitOK || !strings.Contains(h.stdout.String(), `"a"`) {
		t.Fatalf("current-context --json = %q", h.stdout.String())
	}

	// logout forgets the current context too: the token is gone from this
	// machine, as logout promises.
	if code := h.run("logout"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	if f := readContexts(t, dir); f.CurrentContext != "" || len(f.Contexts) != 1 {
		t.Fatalf("after logout = %+v", f)
	}
	if code := h.run("config", "current-context"); code != exitError || !strings.Contains(h.stderr.String(), "no current context") {
		t.Fatalf("current-context after logout = %d %q", code, h.stderr.String())
	}
}

// An older aerolvm reads and writes only config.json. Its login is adopted
// as a context (config.json wins) and its logout forgets the current one;
// the other contexts survive both.
func TestOlderCLIEditsAreAdopted(t *testing.T) {
	h, path := loginHarness(t)
	dir := filepath.Dir(filepath.Dir(path))
	ctxPath := filepath.Join(dir, "aerolvm", "contexts.json")
	a := savedLogin{APIURL: "https://a.example.com", Token: "tok-a"}
	b := savedLogin{APIURL: "https://b.example.com", Token: "tok-b"}
	writeTestJSON(t, ctxPath, contextsFile{CurrentContext: "a", Contexts: map[string]savedLogin{"a": a, "keep": {APIURL: "https://k.example.com", Token: "k"}}})
	writeTestJSON(t, path, b) // the older CLI logged in to b

	if code := h.run("config", "current-context"); code != exitOK || h.stdout.String() != "b.example.com\n" {
		t.Fatalf("adopted current = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	f := readContexts(t, dir)
	if f.Contexts["a"].Token != "tok-a" || f.Contexts["b.example.com"].Token != "tok-b" || f.Contexts["keep"].Token != "k" {
		t.Fatalf("contexts after adoption = %+v", f)
	}
	// The older CLI renews or re-logs in to the same URL: the entry follows.
	b.Token = "tok-b2"
	writeTestJSON(t, path, b)
	if code := h.run("config", "get-contexts"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	if f := readContexts(t, dir); f.Contexts["b.example.com"].Token != "tok-b2" {
		t.Fatalf("refreshed entry = %+v", f.Contexts["b.example.com"])
	}
	// A name already taken by another URL gets a suffix.
	writeTestJSON(t, path, savedLogin{APIURL: "http://b.example.com", Token: "tok-http"})
	if code := h.run("config", "current-context"); code != exitOK || h.stdout.String() != "b.example.com-2\n" {
		t.Fatalf("suffixed name = %q", h.stdout.String())
	}
	// The older CLI logs out: config.json is gone, so is the current context.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if code := h.run("config", "get-contexts"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	f = readContexts(t, dir)
	if _, still := f.Contexts["b.example.com-2"]; still || f.CurrentContext != "" || f.Contexts["keep"].Token != "k" {
		t.Fatalf("after an older logout = %+v", f)
	}
}

// A user who never asked for contexts gets no contexts.json from ordinary
// commands; config commands create it from config.json.
func TestNoContextsFileUntilAsked(t *testing.T) {
	h, path := loginHarness(t)
	dir := filepath.Dir(filepath.Dir(path))
	writeTestJSON(t, path, savedLogin{APIURL: h.fake.URL, Token: agenttoolstest.Token})
	if code := h.run("list"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "aerolvm", "contexts.json")); !os.IsNotExist(err) {
		t.Fatalf("list made contexts.json: %v", err)
	}
	if code := h.run("config", "get-contexts"); code != exitOK || !strings.Contains(h.stdout.String(), contextNameFor(h.fake.URL)) {
		t.Fatalf("get-contexts = %q", h.stdout.String())
	}
	if f := readContexts(t, dir); f.CurrentContext != contextNameFor(h.fake.URL) {
		t.Fatalf("contexts = %+v", f)
	}
	// With nothing saved at all, there is nothing to list.
	empty, _ := loginHarness(t)
	if code := empty.run("config", "get-contexts"); code != exitOK || !strings.Contains(empty.stderr.String(), "no contexts") {
		t.Fatalf("empty get-contexts = %q", empty.stderr.String())
	}
}

// Precedence: --context, then SB_PAT_TOKEN / SB_API_URL, then
// AEROLVM_CONTEXT, then the current context.
func TestContextPrecedence(t *testing.T) {
	h, path := loginHarness(t)
	other := agenttoolstest.New(t)
	h.fake.AddSandbox(models.Sandbox{Name: "on-a"})
	other.AddSandbox(models.Sandbox{Name: "on-b"})
	loginTo(t, h, h.fake.URL, "--name", "a")
	loginTo(t, h, other.URL, "--name", "b") // current: b

	listOn := func(want string, args ...string) {
		t.Helper()
		if code := h.run(append([]string{"list"}, args...)...); code != exitOK || !strings.Contains(h.stdout.String(), want) {
			t.Fatalf("list %v = %d %q %q, want %s", args, code, h.stdout.String(), h.stderr.String(), want)
		}
	}
	listOn("on-b")
	listOn("on-a", "--context", "a")
	h.env["AEROLVM_CONTEXT"] = "a"
	listOn("on-a")
	// The SDK rule still beats AEROLVM_CONTEXT…
	h.env["SB_API_URL"], h.env["SB_PAT_TOKEN"] = other.URL, agenttoolstest.Token
	listOn("on-b")
	// …and --context beats both.
	listOn("on-a", "--context", "a")
	// SB_API_URL alone never sends a context's token elsewhere.
	delete(h.env, "SB_PAT_TOKEN")
	if code := h.run("list"); code != exitError || !strings.Contains(h.stderr.String(), "no token for "+other.URL) {
		t.Fatalf("SB_API_URL against AEROLVM_CONTEXT = %d %q", code, h.stderr.String())
	}
	delete(h.env, "SB_API_URL")
	// SB_TEAM applies to a context too, and is still validated.
	h.env["SB_TEAM"] = "Bad Team"
	if code := h.run("list", "--context", "a"); code != exitError || !strings.Contains(h.stderr.String(), "is not a team name") {
		t.Fatalf("bad SB_TEAM = %d %q", code, h.stderr.String())
	}
	h.env["SB_TEAM"] = "ml"
	conn, err := (&app{getenv: h.app.getenv, contextName: "a"}).connection()
	if err != nil || conn.team != "ml" || conn.apiURL != h.fake.URL || !strings.Contains(conn.from, `context "a" (--context)`) {
		t.Fatalf("--context connection = %+v %v", conn, err)
	}
	delete(h.env, "SB_TEAM")
	for _, tc := range []struct {
		env, flag string
	}{{"ghost", ""}, {"", "ghost"}} {
		h.env["AEROLVM_CONTEXT"] = tc.env
		args := []string{"list"}
		if tc.flag != "" {
			args = append(args, "--context", tc.flag)
		}
		if code := h.run(args...); code != exitError || !strings.Contains(h.stderr.String(), `no context named "ghost"`) {
			t.Fatalf("%+v = %d %q", tc, code, h.stderr.String())
		}
	}
	_ = path
}

func TestConfigRenameDeleteViewImport(t *testing.T) {
	h, path := loginHarness(t)
	dir := filepath.Dir(filepath.Dir(path))
	loginTo(t, h, h.fake.URL, "--name", "prod")
	other := agenttoolstest.New(t)
	loginTo(t, h, other.URL, "--name", "stg") // current: stg

	if code := h.run("config", "rename-context", "stg", "staging"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	if f := readContexts(t, dir); f.CurrentContext != "staging" || f.Contexts["staging"].APIURL != other.URL {
		t.Fatalf("after rename = %+v", f)
	}
	if code := h.run("config", "rename-context", "prod", "prod2", "--json"); code != exitOK || !strings.Contains(h.stdout.String(), `"name": "prod2"`) {
		t.Fatalf("rename --json = %q", h.stdout.String())
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"config", "rename-context", "ghost", "x"}, exitError, `no context named "ghost"`},
		{[]string{"config", "rename-context", "prod2", "staging"}, exitError, `"staging" already exists`},
		{[]string{"config", "rename-context", "prod2", "has space"}, exitUsage, "is not a context name"},
		{[]string{"config", "rename-context", "only-one"}, exitUsage, "old and the new name"},
		{[]string{"config", "use-context", "ghost"}, exitError, `no context named "ghost"`},
		{[]string{"config", "use-context"}, exitUsage, "one context name"},
		{[]string{"config", "delete-context", "ghost"}, exitError, `no context named "ghost"`},
		{[]string{"config", "delete-context"}, exitUsage, "delete-context takes one context name"},
		{[]string{"config", "current-context", "extra"}, exitUsage, "takes no arguments"},
		{[]string{"config", "get-contexts", "--nope"}, exitUsage, "nope"},
		{[]string{"config", "view", "x"}, exitUsage, "takes no arguments"},
		{[]string{"config"}, exitUsage, "expected a subcommand"},
		{[]string{"config", "frobnicate"}, exitUsage, `unknown subcommand "frobnicate"`},
		{[]string{"login", h.fake.URL, "--name", "bad name"}, exitUsage, "--name must be a context name"},
	} {
		if code := h.run(tc.args...); code != tc.code || !strings.Contains(h.stderr.String(), tc.want) {
			t.Fatalf("%v = %d %q", tc.args, code, h.stderr.String())
		}
	}

	// view never prints a token.
	if code := h.run("config", "view"); code != exitOK || !strings.Contains(h.stdout.String(), "current_context: staging") ||
		strings.Contains(h.stdout.String(), agenttoolstest.Token) || !strings.Contains(h.stdout.String(), "REDACTED") {
		t.Fatalf("view = %q", h.stdout.String())
	}
	if code := h.run("config", "view", "--json"); code != exitOK || strings.Contains(h.stdout.String(), agenttoolstest.Token) {
		t.Fatalf("view --json = %q", h.stdout.String())
	}

	// import: one login file, made current only when asked (or none is).
	adminCtx := filepath.Join(t.TempDir(), "admin-context.json")
	writeTestJSON(t, adminCtx, map[string]string{"name": "lab", "api_url": "lab.example.com", "token": "tok-lab", "team": "ml"})
	if code := h.run("config", "import", adminCtx); code != exitOK || !strings.Contains(h.stderr.String(), `imported "lab"`) {
		t.Fatalf("import = %d %q", code, h.stderr.String())
	}
	f := readContexts(t, dir)
	if f.CurrentContext != "staging" || f.Contexts["lab"].APIURL != "https://lab.example.com" || f.Contexts["lab"].Team != "ml" {
		t.Fatalf("after import = %+v", f)
	}
	if code := h.run("config", "import", adminCtx); code != exitError || !strings.Contains(h.stderr.String(), `"lab" already exists`) {
		t.Fatalf("re-import = %d %q", code, h.stderr.String())
	}
	if code := h.run("config", "import", adminCtx, "--name", "lab2", "--use", "--json"); code != exitOK || !strings.Contains(h.stdout.String(), `"current_context": "lab2"`) {
		t.Fatalf("import --use = %q %q", h.stdout.String(), h.stderr.String())
	}
	if got := readSaved(t, path); got.Token != "tok-lab" {
		t.Fatalf("config.json after import --use = %+v", got)
	}
	// A whole contexts file imports every context, never --name.
	many := filepath.Join(t.TempDir(), "contexts.json")
	writeTestJSON(t, many, contextsFile{Contexts: map[string]savedLogin{
		"x": {APIURL: "https://x.example.com", Token: "tx"}, "y": {APIURL: "https://y.example.com", Token: "ty"}}})
	if code := h.run("config", "import", many); code != exitOK || !strings.Contains(h.stderr.String(), `imported "x", "y"`) {
		t.Fatalf("import many = %d %q", code, h.stderr.String())
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	noToken := filepath.Join(t.TempDir(), "no-token.json")
	writeTestJSON(t, noToken, map[string]string{"api_url": "https://z.example.com"})
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"config", "import", many, "--name", "z"}, exitUsage, "--name names one context"},
		{[]string{"config", "import", bad}, exitUsage, "is not a JSON context file"},
		{[]string{"config", "import", noToken}, exitUsage, "needs a valid name, api_url and token"},
		{[]string{"config", "import", filepath.Join(t.TempDir(), "missing.json")}, exitError, "no such file"},
		{[]string{"config", "import"}, exitUsage, "takes one file"},
		{[]string{"config", "import", "a", "--nope"}, exitUsage, "nope"},
	} {
		if code := h.run(tc.args...); code != tc.code || !strings.Contains(h.stderr.String(), tc.want) {
			t.Fatalf("%v = %d %q", tc.args, code, h.stderr.String())
		}
	}

	// delete-context: deleting the current one removes config.json too.
	if code := h.run("config", "delete-context", "x", "--json"); code != exitOK || !strings.Contains(h.stdout.String(), `"was_current": false`) {
		t.Fatalf("delete x = %q", h.stdout.String())
	}
	if code := h.run("config", "delete-context", "lab2"); code != exitOK || !strings.Contains(h.stderr.String(), "it was the current context") {
		t.Fatalf("delete current = %d %q", code, h.stderr.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("config.json survived deleting the current context: %v", err)
	}
}

func TestContextsFileProblems(t *testing.T) {
	h, path := loginHarness(t)
	dir := filepath.Dir(filepath.Dir(path))
	ctxPath := filepath.Join(dir, "aerolvm", "contexts.json")
	if err := os.MkdirAll(filepath.Dir(ctxPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ctxPath, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.run("config", "get-contexts"); code != exitError || !strings.Contains(h.stderr.String(), "not a valid aerolvm contexts file") {
		t.Fatalf("broken file = %d %q", code, h.stderr.String())
	}
	if code := h.run("list", "--context", "x"); code != exitError {
		t.Fatal("a broken contexts file must fail a --context command")
	}
	// A context without a token is refused, never sent half a login.
	writeTestJSON(t, ctxPath, contextsFile{Contexts: map[string]savedLogin{"hollow": {APIURL: "https://h.example.com"}}})
	if code := h.run("list", "--context", "hollow"); code != exitError || !strings.Contains(h.stderr.String(), "has no URL or token") {
		t.Fatalf("hollow = %d %q", code, h.stderr.String())
	}
	// A file others can read earns ssh's warning.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(ctxPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if code := h.run("config", "get-contexts"); code != exitOK || !strings.Contains(h.stderr.String(), "can be read by other users") {
			t.Fatalf("mode warning = %d %q", code, h.stderr.String())
		}
	}
	// An unreadable path (a directory) is an error, not an empty file.
	if err := os.Remove(ctxPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ctxPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if code := h.run("config", "get-contexts"); code != exitError {
		t.Fatal("a directory for contexts.json must fail")
	}
	a := h.app
	if _, _, err := a.loadContextLogin("x"); err == nil {
		t.Fatal("loadContextLogin on a directory")
	}
	if err := a.saveContextLogin("x", savedLogin{}); err == nil {
		t.Fatal("saveContextLogin on a directory")
	}
	if err := a.forgetCurrentContext(); err == nil {
		t.Fatal("forgetCurrentContext on a directory")
	}
	// No HOME at all: every path helper says so.
	noHome := &app{getenv: func(string) string { return "" }, stderr: h.stderr, stdout: h.stdout}
	if runtime.GOOS != "windows" {
		if _, err := noHome.contextsPath(); err == nil {
			t.Fatal("contextsPath without HOME")
		}
		if _, err := noHome.openContexts(false); err == nil {
			t.Fatal("openContexts without HOME")
		}
		if _, _, err := noHome.loadContextLogin("x"); err == nil {
			t.Fatal("loadContextLogin without HOME")
		}
		if err := noHome.saveContextLogin("x", savedLogin{}); err == nil {
			t.Fatal("saveContextLogin without HOME")
		}
		if err := noHome.forgetCurrentContext(); err == nil {
			t.Fatal("forgetCurrentContext without HOME")
		}
		if _, err := noHome.saveCurrentLogin("", savedLogin{APIURL: "https://x"}); err == nil {
			t.Fatal("saveCurrentLogin without HOME")
		}
	}
	if got := contextNameFor("::bad"); got != "default" {
		t.Fatalf("contextNameFor(bad) = %q", got)
	}
	if validContextName("") || validContextName(strings.Repeat("x", 254)) || validContextName("tab\tname") || !validContextName("prod-eu") {
		t.Fatal("validContextName")
	}
}

// An SSO login in a context that is not current renews into contexts.json;
// the current one renews into config.json, as before.
func TestContextSSOSessionsRenewInTheirOwnFile(t *testing.T) {
	h, path := loginHarness(t)
	dir := filepath.Dir(filepath.Dir(path))
	ctxPath := filepath.Join(dir, "aerolvm", "contexts.json")
	sso := &ssoLogin{Issuer: "corp", ClientID: "cli", Expiry: time.Now().Add(time.Hour)}
	cur := savedLogin{APIURL: "https://cur.example.com", Token: "id-cur", SSO: sso}
	other := savedLogin{APIURL: "https://other.example.com", Token: "id-other", SSO: sso}
	writeTestJSON(t, path, cur)
	writeTestJSON(t, ctxPath, contextsFile{CurrentContext: "cur", Contexts: map[string]savedLogin{"cur": cur, "other": other}})

	conn, err := h.app.namedConnection("other", "--context")
	if err != nil || conn.sso == nil || conn.sso.context != "other" || conn.sso.path != ctxPath {
		t.Fatalf("other's session = %+v %v", conn.sso, err)
	}
	renewed := other
	renewed.Token = "id-other-2"
	if err := conn.sso.save(renewed); err != nil {
		t.Fatal(err)
	}
	got, ok, err := conn.sso.load()
	if err != nil || !ok || got.Token != "id-other-2" {
		t.Fatalf("other after renew = %+v %v %v", got, ok, err)
	}
	if readSaved(t, path).Token != "id-cur" {
		t.Fatal("renewing another context touched config.json")
	}
	conn, err = h.app.namedConnection("cur", "AEROLVM_CONTEXT")
	if err != nil || conn.sso == nil || conn.sso.context != "" || conn.sso.path != path {
		t.Fatalf("current's session = %+v %v", conn.sso, err)
	}
	if got, ok, err := conn.sso.load(); err != nil || !ok || got.Token != "id-cur" {
		t.Fatalf("current load = %+v %v %v", got, ok, err)
	}
	if rows := (&contextStore{file: readContexts(t, dir)}).rows(); rows[0].Auth != "sso" {
		t.Fatalf("rows = %+v", rows)
	}
	if code := h.run("config", "view"); code != exitOK || !strings.Contains(h.stdout.String(), "sso: corp") {
		t.Fatalf("view sso = %q", h.stdout.String())
	}
}

// Every context write that fails says so and changes nothing else.
func TestContextWritesFail(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions")
	}
	h, path := loginHarness(t)
	cfgDir := filepath.Dir(path)
	ctxPath := filepath.Join(cfgDir, "contexts.json")
	loginTo(t, h, h.fake.URL, "--name", "a")
	other := agenttoolstest.New(t)
	loginTo(t, h, other.URL, "--name", "b")
	adminCtx := filepath.Join(t.TempDir(), "admin.json")
	writeTestJSON(t, adminCtx, map[string]string{"api_url": "https://c.example.com", "token": "tc"})
	many := filepath.Join(t.TempDir(), "many.json")
	writeTestJSON(t, many, contextsFile{Contexts: map[string]savedLogin{
		"x": {APIURL: "https://x.example.com", Token: "tx"}, "y": {APIURL: "https://y.example.com", Token: "ty"}}})
	if err := os.Chmod(cfgDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfgDir, 0o700) })
	for _, args := range [][]string{
		{"config", "use-context", "a"},
		{"config", "rename-context", "a", "a2"},
		{"config", "delete-context", "a"},
		{"config", "delete-context", "b"},
		{"config", "import", adminCtx},
		{"config", "import", adminCtx, "--use"},
		{"config", "import", many},
	} {
		if code := h.run(args...); code != exitError {
			t.Fatalf("%v in a read-only directory = %d %q", args, code, h.stderr.String())
		}
	}
	h.app.stdin = strings.NewReader(agenttoolstest.Token)
	if code := h.run("login", h.fake.URL, "--token-stdin", "--name", "a"); code != exitError {
		t.Fatalf("login in a read-only directory = %d", code)
	}
	// config.json changed under us: adopting it needs a write that fails.
	if err := os.Chmod(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestJSON(t, path, savedLogin{APIURL: "https://d.example.com", Token: "td"})
	if err := os.Chmod(cfgDir, 0o500); err != nil {
		t.Fatal(err)
	}
	if code := h.run("config", "get-contexts"); code != exitError {
		t.Fatalf("adopting in a read-only directory = %d", code)
	}
	if err := os.Chmod(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// A config.json that no longer parses stops every config command.
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"get-contexts", "current-context", "view"} {
		if code := h.run("config", sub); code != exitError || !strings.Contains(h.stderr.String(), "is not a valid aerolvm login") {
			t.Fatalf("config %s with a broken config.json = %d %q", sub, code, h.stderr.String())
		}
	}
	for _, args := range [][]string{
		{"config", "use-context", "a"}, {"config", "rename-context", "a", "z"}, {"config", "delete-context", "a"}, {"config", "import", adminCtx},
	} {
		if code := h.run(args...); code != exitError {
			t.Fatalf("%v with a broken config.json = %d", args, code)
		}
	}
	// logout removes config.json, then cannot read contexts.json.
	writeTestJSON(t, path, savedLogin{APIURL: h.fake.URL, Token: agenttoolstest.Token})
	if err := os.Remove(ctxPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ctxPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if code := h.run("logout"); code != exitError {
		t.Fatalf("logout with an unreadable contexts.json = %d", code)
	}
}
