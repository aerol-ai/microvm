package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
)

// loginHarness is a harness with no SB_* variables and a private config
// directory, so only `aerolvm login` can supply credentials.
func loginHarness(t *testing.T) (*harness, string) {
	t.Helper()
	h := newHarness(t)
	delete(h.env, "SB_API_URL")
	delete(h.env, "SB_PAT_TOKEN")
	dir := t.TempDir()
	h.env["XDG_CONFIG_HOME"] = dir
	return h, filepath.Join(dir, "aerolvm", "config.json")
}

func secretIs(token string) func() (string, error) {
	return func() (string, error) { return token, nil }
}

func readSaved(t *testing.T, path string) savedLogin {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var login savedLogin
	if err := json.Unmarshal(b, &login); err != nil {
		t.Fatal(err)
	}
	return login
}

func TestLoginAsksSavesAndEveryCommandUsesIt(t *testing.T) {
	h, path := loginHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	h.app.stdinIsTTY = true
	h.app.term = fakeTerm{secret: secretIs(agenttoolstest.Token)}
	h.app.stdin = strings.NewReader(h.fake.URL + "/\n")

	if code := h.run("login"); code != exitOK {
		t.Fatalf("login = %d %q", code, h.stderr.String())
	}
	stderr := h.stderr.String()
	if !strings.Contains(stderr, "sandboxd URL [http://127.0.0.1:21212]: ") || !strings.Contains(stderr, "API token (typing is hidden): ") {
		t.Fatalf("prompts %q", stderr)
	}
	if !strings.Contains(stderr, "logged in to "+h.fake.URL+" (sandboxd fake)") || !strings.Contains(stderr, path) {
		t.Fatalf("login note %q", stderr)
	}
	if strings.Contains(stderr+h.stdout.String(), agenttoolstest.Token) {
		t.Fatal("login printed the token")
	}
	if got := readSaved(t, path); got.APIURL != h.fake.URL || got.Token != agenttoolstest.Token {
		t.Fatalf("saved %+v", got)
	}
	if runtime.GOOS != "windows" {
		for p, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
			if info, err := os.Stat(p); err != nil || info.Mode().Perm() != want {
				t.Fatalf("%s mode = %v, want %v", p, info.Mode().Perm(), want)
			}
		}
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".config-*")); len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}

	// No SB_* variables anywhere: commands run on the login.
	if code := h.run("list"); code != exitOK || !strings.Contains(h.stdout.String(), "box") {
		t.Fatalf("list on the login = %d %q", code, h.stderr.String())
	}
	if code := h.run("health"); code != exitOK || h.stdout.String() != "ok (sandboxd fake)\n" || !strings.Contains(h.stderr.String(), "with the token from "+path) {
		t.Fatalf("health = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}

	// A second login offers the saved URL; Enter keeps it.
	h.app.stdin = strings.NewReader("\n")
	if code := h.run("login"); code != exitOK || !strings.Contains(h.stderr.String(), "sandboxd URL ["+h.fake.URL+"]: ") {
		t.Fatalf("second login = %d %q", code, h.stderr.String())
	}
}

func TestLoginFromScripts(t *testing.T) {
	h, path := loginHarness(t)
	h.app.stdinIsTTY = false

	h.app.stdin = strings.NewReader("  " + agenttoolstest.Token + "\n")
	if code := h.run("login", h.fake.URL, "--token-stdin", "--json"); code != exitOK {
		t.Fatalf("--token-stdin = %d %q", code, h.stderr.String())
	}
	var out map[string]string
	h.jsonOut(&out)
	if out["api_url"] != h.fake.URL || out["config_path"] != path || out["server_version"] != "fake" {
		t.Fatalf("json = %v", out)
	}
	if got := readSaved(t, path); got.Token != agenttoolstest.Token {
		t.Fatalf("the token was saved untrimmed: %q", got.Token)
	}

	for _, tc := range []struct {
		name  string
		args  []string
		stdin string
		want  string
	}{
		{"no terminal, no --token-stdin", []string{"login", h.fake.URL}, "", "pipe it in with --token-stdin"},
		{"empty token", []string{"login", h.fake.URL, "--token-stdin"}, " \n", "the token is empty"},
		{"not an http URL", []string{"login", "ftp://files.example.com", "--token-stdin"}, "x", "is not a sandboxd URL"},
		{"two URLs", []string{"login", "a", "b"}, "", "at most one sandboxd URL"},
		{"bad flag", []string{"login", "--nope"}, "", "nope"},
	} {
		h.app.stdin = strings.NewReader(tc.stdin)
		if code := h.run(tc.args...); code != exitUsage || !strings.Contains(h.stderr.String(), tc.want) {
			t.Errorf("%s: %v = %d %q; want 2 and %q", tc.name, tc.args, code, h.stderr.String(), tc.want)
		}
	}
}

func TestLoginRefusesWhatItCannotVerify(t *testing.T) {
	h, path := loginHarness(t)
	h.app.stdinIsTTY = false
	for _, tc := range []struct {
		name, url, token, want string
	}{
		{"wrong token", h.fake.URL, "not-the-token", "refused the token"},
		{"no server", "http://127.0.0.1:1", agenttoolstest.Token, "aerolvm:"},
	} {
		h.app.stdin = strings.NewReader(tc.token)
		if code := h.run("login", tc.url, "--token-stdin"); code != exitError || !strings.Contains(h.stderr.String(), tc.want) {
			t.Errorf("%s: login = %d %q", tc.name, code, h.stderr.String())
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s: a login that failed verification was saved", tc.name)
		}
	}

	// The prompt can fail, and so can the write.
	h.app.stdinIsTTY, h.app.term, h.app.stdin = true, errTerm{}, strings.NewReader(h.fake.URL+"\n")
	if code := h.run("login"); code != exitError || !strings.Contains(h.stderr.String(), "refused to read") {
		t.Fatalf("secret prompt failure = %d %q", code, h.stderr.String())
	}
	blocker := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.env["XDG_CONFIG_HOME"] = blocker // the config dir would have to live under a file
	h.app.stdinIsTTY, h.app.stdin = false, strings.NewReader(agenttoolstest.Token)
	if code := h.run("login", h.fake.URL, "--token-stdin"); code != exitError {
		t.Fatalf("unwritable config = %d %q", code, h.stderr.String())
	}
}

func TestLoginWarnsAboutTheEnvironment(t *testing.T) {
	h, _ := loginHarness(t)
	h.app.stdinIsTTY = false
	h.env["SB_PAT_TOKEN"] = agenttoolstest.Token
	h.app.stdin = strings.NewReader(agenttoolstest.Token)
	if code := h.run("login", h.fake.URL, "--token-stdin"); code != exitOK || !strings.Contains(h.stderr.String(), "SB_PAT_TOKEN is set in this shell and takes precedence") {
		t.Fatalf("env token = %d %q", code, h.stderr.String())
	}
	delete(h.env, "SB_PAT_TOKEN")
	h.env["SB_API_URL"] = "https://elsewhere.example.com"
	h.app.stdin = strings.NewReader(agenttoolstest.Token)
	if code := h.run("login", h.fake.URL, "--token-stdin"); code != exitOK || !strings.Contains(h.stderr.String(), "SB_API_URL in this shell points at https://elsewhere.example.com") {
		t.Fatalf("env URL = %d %q", code, h.stderr.String())
	}
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"http://sandbox.example.com", true},
		{"https://sandbox.example.com", false},
		{"http://127.0.0.1:21212", false},
		{"http://localhost:21212", false},
		{"http://[::1]:21212", false},
	} {
		if got := sendsTokenInClear(tc.url); got != tc.want {
			t.Errorf("sendsTokenInClear(%q) = %v", tc.url, got)
		}
	}
}

func TestConnectionRules(t *testing.T) {
	h, path := loginHarness(t)
	if err := saveLogin(path, savedLogin{APIURL: "https://sandbox.example.com", Token: "saved-token"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		envURL, envTk string
		wantURL       string
		wantToken     string
		wantFrom      string
		wantErr       string
	}{
		{name: "the login", wantURL: "https://sandbox.example.com", wantToken: "saved-token", wantFrom: path},
		{name: "the login, same URL spelled differently", envURL: "HTTPS://Sandbox.example.com/", wantURL: "https://sandbox.example.com", wantToken: "saved-token", wantFrom: path},
		{name: "SB_PAT_TOKEN wins", envTk: "env-token", wantURL: defaultAPIURL, wantToken: "env-token", wantFrom: "SB_PAT_TOKEN"},
		{name: "SB_PAT_TOKEN with its URL", envURL: "https://other.example.com", envTk: "env-token", wantURL: "https://other.example.com", wantToken: "env-token", wantFrom: "SB_PAT_TOKEN"},
		// The saved token must never be sent to another server.
		{name: "another server", envURL: "https://other.example.com", wantErr: "you are logged in to https://sandbox.example.com, and SB_API_URL points elsewhere"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.env["SB_API_URL"], h.env["SB_PAT_TOKEN"] = tc.envURL, tc.envTk
			conn, err := h.app.connection()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !agenttools.IsCode(err, agenttools.CodeUnauthorized) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || conn.apiURL != tc.wantURL || conn.token != tc.wantToken || conn.from != tc.wantFrom {
				t.Fatalf("connection = %+v, %v", conn, err)
			}
		})
	}

	h.env["SB_API_URL"], h.env["SB_PAT_TOKEN"] = "", ""
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		h.stderr.Reset()
		if _, err := h.app.connection(); err != nil || !strings.Contains(h.stderr.String(), "can be read by other users; run: chmod 600") {
			t.Fatalf("loose permissions: %v %q", err, h.stderr.String())
		}
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.app.connection(); err == nil || !strings.Contains(err.Error(), "is not a valid aerolvm login") {
		t.Fatalf("corrupt login: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if code := h.run("list"); code != exitError || !strings.Contains(h.stderr.String(), "not logged in") || !strings.Contains(h.stderr.String(), "aerolvm login") {
		t.Fatalf("no login = %d %q", code, h.stderr.String())
	}
	if code := h.run("mcp"); code != exitError || !strings.Contains(h.stderr.String(), "not logged in") {
		t.Fatalf("mcp with no login = %d %q", code, h.stderr.String())
	}
}

func TestLoginPath(t *testing.T) {
	a := &app{getenv: func(k string) string { return map[string]string{"HOME": "/home/me"}[k] }}
	if got, err := a.loginPath(); err != nil || got != filepath.Join("/home/me", ".config", "aerolvm", "config.json") {
		t.Fatalf("HOME path = %q, %v", got, err)
	}
	a.getenv = func(k string) string { return map[string]string{"HOME": "/home/me", "XDG_CONFIG_HOME": "/xdg"}[k] }
	if got, _ := a.loginPath(); got != filepath.Join("/xdg", "aerolvm", "config.json") {
		t.Fatalf("XDG path = %q", got)
	}
	if runtime.GOOS != "windows" {
		a.getenv = func(string) string { return "" }
		if _, err := a.loginPath(); err == nil || !strings.Contains(err.Error(), "home directory") {
			t.Fatalf("no HOME: %v", err)
		}
		h := newHarness(t)
		h.env = map[string]string{}
		if code := h.run("login"); code != exitError {
			t.Fatalf("login with no home = %d", code)
		}
		if code := h.run("logout"); code != exitError {
			t.Fatalf("logout with no home = %d", code)
		}
	}
}

func TestNormalizeAPIURL(t *testing.T) {
	for _, tc := range []struct{ in, want, err string }{
		{in: "sandbox.example.com", want: "https://sandbox.example.com"},
		{in: " https://Sandbox.Example.com/ ", want: "https://sandbox.example.com"},
		{in: "HTTP://localhost:21212", want: "http://localhost:21212"},
		{in: "localhost:21212", want: "http://localhost:21212"},
		{in: "127.0.0.1:21212/", want: "http://127.0.0.1:21212"},
		{in: "[::1]:21212", want: "http://[::1]:21212"},
		{in: "https://example.com/aerolvm/", want: "https://example.com/aerolvm"},
		{in: "", err: "empty"},
		{in: "ftp://example.com", err: "not a sandboxd URL"},
		{in: "https://user:pw@example.com", err: "not a sandboxd URL"},
		{in: "https://", err: "not a sandboxd URL"},
	} {
		got, err := normalizeAPIURL(tc.in)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("normalizeAPIURL(%q) = %q, %v; want error %q", tc.in, got, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("normalizeAPIURL(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	if sameAPIURL("https://a.example.com", "nonsense://") {
		t.Fatal("an invalid URL matched")
	}
}

func TestLogout(t *testing.T) {
	h, path := loginHarness(t)
	if code := h.run("logout"); code != exitOK || !strings.Contains(h.stderr.String(), "not logged in; nothing to do") {
		t.Fatalf("logout while logged out = %d %q", code, h.stderr.String())
	}
	if code := h.run("logout", "--json"); code != exitOK || strings.TrimSpace(h.stdout.String()) != "{\n  \"logged_out\": false\n}" {
		t.Fatalf("json logout while logged out = %q", h.stdout.String())
	}
	if code := h.run("logout", "extra"); code != exitUsage {
		t.Fatalf("logout extra = %d", code)
	}
	if code := h.run("logout", "--nope"); code != exitUsage {
		t.Fatalf("logout --nope = %d", code)
	}

	if err := saveLogin(path, savedLogin{APIURL: h.fake.URL, Token: agenttoolstest.Token}); err != nil {
		t.Fatal(err)
	}
	h.env["SB_PAT_TOKEN"] = "still-here"
	if code := h.run("logout"); code != exitOK || !strings.Contains(h.stderr.String(), "logged out of "+h.fake.URL) || !strings.Contains(h.stderr.String(), "it still works on sandboxd") || !strings.Contains(h.stderr.String(), "SB_PAT_TOKEN is still set") {
		t.Fatalf("logout = %d %q", code, h.stderr.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("logout left the login behind")
	}

	// A login that no longer parses is still removed, and --json says so.
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.run("logout", "--json"); code != exitOK || !strings.Contains(h.stdout.String(), `"logged_out": true`) {
		t.Fatalf("logout of a broken login = %d %q", code, h.stdout.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("logout left a broken login behind")
	}
}

func TestMCPConfigAfterLogin(t *testing.T) {
	h, path := loginHarness(t)
	if err := saveLogin(path, savedLogin{APIURL: h.fake.URL, Token: "secret-token-value"}); err != nil {
		t.Fatal(err)
	}
	for _, client := range mcpClients {
		if code := h.run("mcp", "config", client, "--sandbox", "my-agent"); code != exitOK {
			t.Fatalf("config %s = %d %q", client, code, h.stderr.String())
		}
		out := h.stdout.String()
		if strings.Contains(out+h.stderr.String(), "secret-token-value") || strings.Contains(out, "SB_PAT_TOKEN") || strings.Contains(out, "SB_API_URL") || strings.Contains(out, "inputs") {
			t.Fatalf("config %s after login still wires credentials:\n%s", client, out)
		}
		if !strings.Contains(out, "my-agent") || !strings.Contains(h.stderr.String(), "uses your aerolvm login") {
			t.Fatalf("config %s = %q %q", client, out, h.stderr.String())
		}
	}
	h.run("mcp", "config", "claude-code", "--sandbox", "my-agent")
	if got := h.stdout.String(); got != "claude mcp add aerolvm -- aerolvm mcp --sandbox my-agent\n" {
		t.Fatalf("claude-code config = %q", got)
	}
	// With SB_PAT_TOKEN set, that wins, and the config wires it as before.
	h.env["SB_PAT_TOKEN"] = "x"
	h.run("mcp", "config", "claude-code")
	if !strings.Contains(h.stdout.String(), `-e SB_PAT_TOKEN="$SB_PAT_TOKEN"`) {
		t.Fatalf("config with SB_PAT_TOKEN = %q", h.stdout.String())
	}
}

func TestHealthChecksTheToken(t *testing.T) {
	h := newHarness(t)
	h.env["SB_PAT_TOKEN"] = "wrong"
	if code := h.run("health"); code != exitError || !strings.Contains(h.stderr.String(), "refused the token") {
		t.Fatalf("health with a wrong token = %d %q (/health alone answers without one)", code, h.stderr.String())
	}
	h.env["SB_PAT_TOKEN"] = agenttoolstest.Token
	if code := h.run("health"); code != exitOK || !strings.Contains(h.stderr.String(), "with the token from SB_PAT_TOKEN") {
		t.Fatalf("health = %d %q", code, h.stderr.String())
	}
	h.fake.Observe(func(s *agenttoolstest.Server) { s.Close() })
	if code := h.run("health"); code != exitError {
		t.Fatalf("health against a closed server = %d", code)
	}
}

func TestSaveAndLoadFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission bits don't apply on Windows")
	}
	h, path := loginHarness(t)

	// config.json is a directory: reading it fails, and so does renaming the
	// new login over it, which leaves no temp file behind.
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := h.app.connection(); err == nil {
		t.Fatal("a config path that is a directory was read as no login")
	}
	if err := saveLogin(path, savedLogin{APIURL: "https://a.example.com", Token: "t"}); err == nil {
		t.Fatal("saving over a directory succeeded")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".config-*")); len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	// A directory nobody can write to: the temp file can't be created.
	if err := os.Chmod(filepath.Dir(path), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(path), 0o700) })
	if os.Geteuid() != 0 { // root writes anyway
		if err := saveLogin(path, savedLogin{APIURL: "https://a.example.com", Token: "t"}); err == nil {
			t.Fatal("saving into a read-only directory succeeded")
		}
	}
}

// sandboxd's 401 says only "unauthorized". Every command names the token it
// refused and how to replace it, as `aerolvm health` does.
func TestCommandsNameTheRefusedToken(t *testing.T) {
	h, path := loginHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	h.app.stdinIsTTY, h.app.stdoutIsTTY, h.app.term = true, true, fakeTerm{}
	if err := saveLogin(path, savedLogin{APIURL: h.fake.URL, Token: "revoked-since-login"}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"list"}, {"exec", "box", "--", "true"}, {"shell", "box"}} {
		if code := h.run(args...); code == exitOK ||
			!strings.Contains(h.stderr.String(), "sandboxd at "+h.fake.URL+" refused the saved token") ||
			!strings.Contains(h.stderr.String(), "hint: sign in again: aerolvm login "+h.fake.URL) {
			t.Fatalf("%v with a revoked saved token = %d %q", args, code, h.stderr.String())
		}
	}
	if code := h.run("list", "--json"); code == exitOK || !strings.Contains(h.stderr.String(), `"message":"sandboxd at `+h.fake.URL+` refused the saved token"`) {
		t.Fatalf("list --json = %d %q", code, h.stderr.String())
	}

	h.env["SB_API_URL"], h.env["SB_PAT_TOKEN"] = h.fake.URL, "wrong"
	if code := h.run("list"); code == exitOK || !strings.Contains(h.stderr.String(), "refused the token in SB_PAT_TOKEN") || !strings.Contains(h.stderr.String(), "check SB_PAT_TOKEN, or unset it") {
		t.Fatalf("list with a wrong SB_PAT_TOKEN = %d %q", code, h.stderr.String())
	}

	// Other failures keep their own words.
	h.env["SB_PAT_TOKEN"] = agenttoolstest.Token
	if code := h.run("exec", "nope", "--", "true"); code == exitOK || strings.Contains(h.stderr.String(), "refused") {
		t.Fatalf("a missing sandbox = %d %q", code, h.stderr.String())
	}
}
