package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// defaultAPIURL is the local setup's address, the SDKs' default too.
const defaultAPIURL = "http://127.0.0.1:21212"

// maxTokenBytes bounds --token-stdin, so a mistaken pipe can't fill memory.
const maxTokenBytes = 64 << 10

// savedLogin is the file `aerolvm login` writes: one sandboxd and its token.
type savedLogin struct {
	APIURL string `json:"api_url"`
	Token  string `json:"token"`
}

// connection is the sandboxd and token a command uses, and where the token
// came from: "SB_PAT_TOKEN", or the path of the saved login.
type connection struct {
	apiURL string
	token  string
	from   string
	saved  bool
}

// loginPath is where `aerolvm login` keeps its file: $XDG_CONFIG_HOME/aerolvm,
// else %AppData%\aerolvm on Windows and ~/.config/aerolvm elsewhere (macOS
// included: CLI users look in ~/.config, not ~/Library). MCP clients start
// servers with HOME and AppData set, so a server they launch finds it too.
func (a *app) loginPath() (string, error) {
	dir := strings.TrimSpace(a.getenv("XDG_CONFIG_HOME"))
	if dir == "" && runtime.GOOS == "windows" {
		dir = strings.TrimSpace(a.getenv("AppData"))
	}
	if dir == "" {
		home := strings.TrimSpace(a.getenv("HOME"))
		if home == "" {
			return "", &agenttools.Error{
				Code:    agenttools.CodeInvalidArgument,
				Message: "can't find your home directory to keep the login in",
				Hint:    "set HOME or XDG_CONFIG_HOME",
			}
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "aerolvm", "config.json"), nil
}

// loadLogin reads the saved login. exists reports whether the file is
// there at all, so logout can remove one that no longer parses.
func (a *app) loadLogin(path string) (login savedLogin, exists bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return savedLogin{}, false, nil
	}
	if err != nil {
		return savedLogin{}, true, err
	}
	if err := json.Unmarshal(b, &login); err != nil || login.APIURL == "" || login.Token == "" {
		return savedLogin{}, true, &agenttools.Error{
			Code:    agenttools.CodeInvalidArgument,
			Message: path + " is not a valid aerolvm login",
			Hint:    "run `aerolvm login` again to replace it",
		}
	}
	// ssh's rule: a credential others can read is worth a warning.
	if info, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		a.note("aerolvm: %s can be read by other users; run: chmod 600 %s", path, path)
	}
	return login, true, nil
}

// saveLogin writes the login readable only by its owner, through a temp
// file and a rename so a crash never leaves half a token behind.
func saveLogin(path string, login savedLogin) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once the rename succeeded
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(login); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// connection picks the sandboxd and token for a command. SB_PAT_TOKEN wins,
// as for every SDK. Otherwise the saved login is used, but only for the URL
// it was saved for: with SB_API_URL pointing at another server, the saved
// token is never sent there.
func (a *app) connection() (connection, error) {
	envURL := strings.TrimSpace(a.getenv("SB_API_URL"))
	if token := strings.TrimSpace(a.getenv("SB_PAT_TOKEN")); token != "" {
		if envURL == "" {
			envURL = defaultAPIURL
		}
		return connection{apiURL: envURL, token: token, from: "SB_PAT_TOKEN"}, nil
	}
	var login savedLogin
	var exists bool
	path, err := a.loginPath()
	if err == nil {
		if login, exists, err = a.loadLogin(path); err != nil {
			return connection{}, err
		}
	}
	switch {
	case exists && (envURL == "" || sameAPIURL(envURL, login.APIURL)):
		return connection{apiURL: login.APIURL, token: login.Token, from: path, saved: true}, nil
	case exists:
		return connection{}, &agenttools.Error{
			Code:    agenttools.CodeUnauthorized,
			Message: fmt.Sprintf("no token for %s: you are logged in to %s, and SB_API_URL points elsewhere", envURL, login.APIURL),
			Hint:    fmt.Sprintf("run `aerolvm login %s`, unset SB_API_URL, or set SB_PAT_TOKEN", envURL),
		}
	}
	return connection{}, &agenttools.Error{
		Code:    agenttools.CodeUnauthorized,
		Message: "not logged in",
		Hint:    "run `aerolvm login`, or set SB_API_URL and SB_PAT_TOKEN",
	}
}

// normalizeAPIURL accepts what people type. A bare host gets https://, or
// http:// for a loopback address, since the local setup serves plain HTTP.
func normalizeAPIURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("the sandboxd URL is empty")
	}
	if !strings.Contains(s, "://") {
		if bare, err := url.Parse("//" + s); err == nil && isLoopback(bare.Hostname()) {
			s = "http://" + s
		} else {
			s = "https://" + s
		}
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("%q is not a sandboxd URL; give one like https://sandbox.example.com", strings.TrimSpace(raw))
	}
	u.Host = strings.ToLower(u.Host)
	return strings.TrimRight(u.String(), "/"), nil
}

func sameAPIURL(a, b string) bool {
	na, errA := normalizeAPIURL(a)
	nb, errB := normalizeAPIURL(b)
	return errA == nil && errB == nil && na == nb
}

// sendsTokenInClear reports a plain-HTTP URL off this machine: the local
// setup is HTTP on loopback, but a remote sandboxd should be HTTPS.
func sendsTokenInClear(apiURL string) bool {
	u, err := url.Parse(apiURL)
	return err == nil && u.Scheme == "http" && !isLoopback(u.Hostname())
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// verifyToken proves the token works. /health needs no token, so it sends
// one authenticated read: the first sandbox of one page, nothing more.
func verifyToken(ctx context.Context, tools *agenttools.Tools, apiURL string) error {
	if _, _, err := tools.Client().ListPage(ctx, "", microvm.WithLimit(1)); err != nil {
		e := agenttools.Classify(err)
		if e.Code == agenttools.CodeUnauthorized || e.Code == agenttools.CodeForbidden {
			refused := *e
			refused.Message = "sandboxd at " + apiURL + " refused the token"
			refused.Hint = "check the token, then run `aerolvm login` again"
			return &refused
		}
		return e
	}
	return nil
}

// explainRefusal names the token sandboxd turned away and how to replace it.
// sandboxd's 401 says only "unauthorized", and a saved token that was
// revoked since `aerolvm login` gives no other clue that login is the fix.
func (a *app) explainRefusal(e *agenttools.Error) *agenttools.Error {
	if e == nil || e.HTTPStatus != http.StatusUnauthorized || a.conn == nil {
		return e
	}
	refused := *e
	if a.conn.saved {
		refused.Message = "sandboxd at " + a.conn.apiURL + " refused the saved token"
		refused.Hint = "sign in again: aerolvm login " + a.conn.apiURL
	} else {
		refused.Message = "sandboxd at " + a.conn.apiURL + " refused the token in SB_PAT_TOKEN"
		refused.Hint = "check SB_PAT_TOKEN, or unset it and run `aerolvm login`"
	}
	return &refused
}

func runLogin(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("login")
	var tokenStdin bool
	fs.BoolVar(&tokenStdin, "token-stdin", false, "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "login", err)
	}
	if len(pos) > 1 {
		return a.usageError(c, "login", "expected at most one sandboxd URL")
	}
	path, err := a.loginPath()
	if err != nil {
		return a.fail(c, err, exitError)
	}
	// login asks only on a terminal; --token-stdin or a pipe means a script,
	// which gets defaults instead of questions (§5.2 rule 1).
	ask := a.stdinIsTTY && !tokenStdin

	raw := ""
	if len(pos) == 1 {
		raw = pos[0]
	} else {
		suggested := strings.TrimSpace(a.getenv("SB_API_URL"))
		if suggested == "" {
			// A broken saved login is about to be replaced; ignore it here.
			if saved, _, err := a.loadLogin(path); err == nil && saved.APIURL != "" {
				suggested = saved.APIURL
			} else {
				suggested = defaultAPIURL
			}
		}
		if ask {
			fmt.Fprintf(a.stderr, "sandboxd URL [%s]: ", suggested)
			raw = readLine(a.stdin)
		}
		if strings.TrimSpace(raw) == "" {
			raw = suggested
		}
	}
	apiURL, err := normalizeAPIURL(raw)
	if err != nil {
		return a.usageError(c, "login", "%v", err)
	}

	var token string
	switch {
	case tokenStdin:
		b, err := io.ReadAll(io.LimitReader(a.stdin, maxTokenBytes))
		if err != nil {
			return a.fail(c, err, exitError)
		}
		token = string(b)
	case ask:
		fmt.Fprint(a.stderr, "API token (typing is hidden): ")
		token, err = a.term.ReadSecret()
		fmt.Fprintln(a.stderr)
		if err != nil {
			return a.fail(c, err, exitError)
		}
	default:
		return a.usageError(c, "login", "stdin is not a terminal, so there is nowhere to type the token; pipe it in with --token-stdin")
	}
	if token = strings.TrimSpace(token); token == "" {
		return a.usageError(c, "login", "the token is empty")
	}

	tools, err := a.toolsFor(c, connection{apiURL: apiURL, token: token})
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if err := verifyToken(ctx, tools, apiURL); err != nil {
		return a.fail(c, err, exitError)
	}
	version := ""
	if health, err := tools.Client().Health(ctx); err == nil {
		version = health.Version
	}
	if err := saveLogin(path, savedLogin{APIURL: apiURL, Token: token}); err != nil {
		return a.fail(c, err, exitError)
	}

	if c.json {
		a.printJSON(map[string]string{"api_url": apiURL, "config_path": path, "server_version": version})
	} else {
		a.note("aerolvm: logged in to %s (sandboxd %s). The token is saved in %s, readable only by you.", apiURL, dash(version), path)
	}
	if sendsTokenInClear(apiURL) {
		a.note("aerolvm: %s is plain HTTP, so the token crosses the network unencrypted; use https:// for a remote sandboxd", apiURL)
	}
	a.warnEnvOverrides(apiURL)
	return exitOK
}

// warnEnvOverrides says when this shell's environment will keep a login
// from being used.
func (a *app) warnEnvOverrides(apiURL string) {
	if strings.TrimSpace(a.getenv("SB_PAT_TOKEN")) != "" {
		a.note("aerolvm: SB_PAT_TOKEN is set in this shell and takes precedence; unset it to use the login")
	} else if envURL := strings.TrimSpace(a.getenv("SB_API_URL")); envURL != "" && apiURL != "" && !sameAPIURL(envURL, apiURL) {
		a.note("aerolvm: SB_API_URL in this shell points at %s, so the login isn't used here; unset it", envURL)
	}
}

func runLogout(_ context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("logout")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "logout", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "logout", "unexpected argument %q", pos[0])
	}
	path, err := a.loginPath()
	if err != nil {
		return a.fail(c, err, exitError)
	}
	// A file that no longer parses is still ours to remove.
	login, exists, _ := a.loadLogin(path)
	if !exists {
		if c.json {
			a.printJSON(map[string]any{"logged_out": false})
		} else {
			a.note("aerolvm: not logged in; nothing to do")
		}
		return exitOK
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(map[string]any{"logged_out": true, "api_url": login.APIURL})
	} else {
		a.note("aerolvm: logged out of %s. The token is forgotten on this machine only; it still works on sandboxd.", dash(login.APIURL))
	}
	if strings.TrimSpace(a.getenv("SB_PAT_TOKEN")) != "" {
		a.note("aerolvm: SB_PAT_TOKEN is still set in this shell, so commands keep working")
	}
	return exitOK
}
