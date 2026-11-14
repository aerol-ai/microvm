package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"gopkg.in/yaml.v3"
)

// Contexts: several saved logins, one current (plans/kubectl-style-cluster-
// ops.md §3.4).
//
// They live in contexts.json beside config.json. config.json keeps exactly
// its old shape and always holds the CURRENT context, so an older aerolvm,
// which reads and rewrites only config.json, keeps working and can never
// erase the other contexts. When the two files disagree (an older CLI logged
// in somewhere else, or logged out), config.json wins: the next command that
// reads contexts adopts it as a context named after its host, or forgets the
// current one.
//
// Which login a command uses, first match wins:
//
//	--context NAME ─► SB_PAT_TOKEN / SB_API_URL (the SDK rule, as before)
//	              ─► AEROLVM_CONTEXT ─► the current context (config.json)
//
// A context's token is sent only to that context's URL; SB_API_URL pointing
// elsewhere is still an error, never a reason to send it there.

// contextsFile is contexts.json. Each context is the login config.json would
// hold for it.
type contextsFile struct {
	CurrentContext string                `json:"current_context"`
	Contexts       map[string]savedLogin `json:"contexts"`
}

func (a *app) contextsPath() (string, error) {
	path, err := a.loginPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "contexts.json"), nil
}

// loadContexts reads contexts.json; a missing file is an empty one.
func (a *app) loadContexts(path string) (contextsFile, bool, error) {
	f := contextsFile{Contexts: map[string]savedLogin{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, false, nil
	}
	if err != nil {
		return f, true, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return contextsFile{Contexts: map[string]savedLogin{}}, true, &agenttools.Error{
			Code:    agenttools.CodeInvalidArgument,
			Message: path + " is not a valid aerolvm contexts file",
			Hint:    "fix or remove it; config.json still holds the current login",
		}
	}
	if f.Contexts == nil {
		f.Contexts = map[string]savedLogin{}
	}
	if info, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		a.note("aerolvm: %s can be read by other users; run: chmod 600 %s", path, path)
	}
	return f, true, nil
}

// contextStore is the two files, read and reconciled.
type contextStore struct {
	loginPath, path string
	file            contextsFile
	exists          bool
}

// openContexts reads both files and applies the "config.json wins" rule.
// With create false it never makes contexts.json where there was none, so a
// user who never asked for contexts gets no new file.
func (a *app) openContexts(create bool) (*contextStore, error) {
	loginPath, err := a.loginPath()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(filepath.Dir(loginPath), "contexts.json")
	file, exists, err := a.loadContexts(path)
	if err != nil {
		return nil, err
	}
	s := &contextStore{loginPath: loginPath, path: path, file: file, exists: exists}
	login, loggedIn, err := a.loadLogin(loginPath)
	if err != nil {
		return nil, err
	}
	changed := false
	current := s.file.CurrentContext
	switch {
	case !loggedIn && current != "":
		// An older CLI logged out: it promised the token was forgotten.
		delete(s.file.Contexts, current)
		s.file.CurrentContext, changed = "", true
	case loggedIn && current != "" && sameAPIURL(s.file.Contexts[current].APIURL, login.APIURL):
		if !sameLogin(s.file.Contexts[current], login) {
			s.file.Contexts[current], changed = login, true
		}
	case loggedIn:
		name := s.freeName(contextNameFor(login.APIURL), login.APIURL)
		s.file.Contexts[name] = login
		s.file.CurrentContext, changed = name, true
	}
	if changed && (exists || create) {
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *contextStore) save() error {
	if err := writeJSONFile(s.path, s.file); err != nil {
		return err
	}
	s.exists = true
	return nil
}

// freeName is base, or base-2, base-3… when base is taken by another URL.
func (s *contextStore) freeName(base, apiURL string) string {
	name := base
	for i := 2; ; i++ {
		existing, taken := s.file.Contexts[name]
		if !taken || sameAPIURL(existing.APIURL, apiURL) {
			return name
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
}

// login returns a context's login. The current context's comes from
// config.json, the copy SSO renewals keep up to date.
func (s *contextStore) login(a *app, name string) (savedLogin, error) {
	if name != "" && name == s.file.CurrentContext {
		login, _, err := a.loadLogin(s.loginPath)
		return login, err
	}
	login, ok := s.file.Contexts[name]
	if !ok {
		return savedLogin{}, &agenttools.Error{
			Code:    agenttools.CodeInvalidArgument,
			Message: fmt.Sprintf("no context named %q", name),
			Hint:    "run `aerolvm config get-contexts` to see them, or `aerolvm login <url> --name " + name + "`",
		}
	}
	if login.APIURL == "" || login.Token == "" {
		return savedLogin{}, &agenttools.Error{
			Code:    agenttools.CodeInvalidArgument,
			Message: fmt.Sprintf("context %q in %s has no URL or token", name, s.path),
			Hint:    "run `aerolvm login <url> --name " + name + "` to replace it",
		}
	}
	return login, nil
}

// use makes name current: config.json gets its login. The outgoing current
// context was already saved into contexts.json by openContexts.
func (s *contextStore) use(name string, login savedLogin) error {
	if err := saveLogin(s.loginPath, login); err != nil {
		return err
	}
	s.file.Contexts[name] = login
	s.file.CurrentContext = name
	return s.save()
}

func sameLogin(x, y savedLogin) bool {
	a, _ := json.Marshal(x)
	b, _ := json.Marshal(y)
	return string(a) == string(b)
}

// contextNameFor names a context after its host, with the port when there
// is one, so two local servers do not collide.
func contextNameFor(apiURL string) string {
	if u, err := url.Parse(apiURL); err == nil && u.Host != "" {
		return u.Host
	}
	return "default"
}

func validContextName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, r := range name {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// saveCurrentLogin is what a login does now: config.json as before, and the
// login recorded as the named context and made current. A previous login
// that contexts.json did not know yet is kept as a context of its own.
func (a *app) saveCurrentLogin(name string, login savedLogin) (string, error) {
	s, err := a.openContexts(true)
	if err != nil {
		return "", err
	}
	if name == "" {
		name = s.freeName(contextNameFor(login.APIURL), login.APIURL)
	}
	if err := s.use(name, login); err != nil {
		return "", err
	}
	return name, nil
}

// forgetCurrentContext is logout's half in contexts.json.
func (a *app) forgetCurrentContext() error {
	path, err := a.contextsPath()
	if err != nil {
		return err
	}
	f, exists, err := a.loadContexts(path)
	if err != nil || !exists || f.CurrentContext == "" {
		return err
	}
	delete(f.Contexts, f.CurrentContext)
	f.CurrentContext = ""
	return writeJSONFile(path, f)
}

// namedConnection is the connection for a context picked by --context or
// AEROLVM_CONTEXT. from says which, for error messages.
func (a *app) namedConnection(name, from string) (connection, error) {
	s, err := a.openContexts(false)
	if err != nil {
		return connection{}, err
	}
	login, err := s.login(a, name)
	if err != nil {
		return connection{}, err
	}
	conn := connection{apiURL: login.APIURL, token: login.Token, saved: true, team: login.Team,
		from: fmt.Sprintf("context %q (%s)", name, from)}
	if login.SSO != nil {
		if name == s.file.CurrentContext {
			conn.sso = &ssoSession{a: a, path: s.loginPath, login: login}
		} else {
			conn.sso = &ssoSession{a: a, path: s.path, context: name, login: login}
		}
	}
	return conn, nil
}

// loadContextLogin and saveContextLogin are an SSO session's storage for a
// context that is not current (ssoSession.context).
func (a *app) loadContextLogin(name string) (savedLogin, bool, error) {
	path, err := a.contextsPath()
	if err != nil {
		return savedLogin{}, false, err
	}
	f, _, err := a.loadContexts(path)
	if err != nil {
		return savedLogin{}, false, err
	}
	login, ok := f.Contexts[name]
	return login, ok, nil
}

func (a *app) saveContextLogin(name string, login savedLogin) error {
	path, err := a.contextsPath()
	if err != nil {
		return err
	}
	f, _, err := a.loadContexts(path)
	if err != nil {
		return err
	}
	f.Contexts[name] = login
	return writeJSONFile(path, f)
}

// aerolvm config …

func runConfig(ctx context.Context, a *app, args []string) int {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "get-contexts":
		return runConfigGetContexts(a, args)
	case "current-context":
		return runConfigCurrentContext(a, args)
	case "use-context", "use":
		return runConfigUseContext(a, args)
	case "rename-context":
		return runConfigRenameContext(a, args)
	case "delete-context":
		return runConfigDeleteContext(a, args)
	case "view":
		return runConfigView(a, args)
	case "import":
		return runConfigImport(a, args)
	case "":
		return a.usageError(nil, "config", "expected a subcommand: get-contexts, current-context, use-context, rename-context, delete-context, view or import")
	}
	return a.usageError(nil, "config", "unknown subcommand %q", sub)
}

// configArgs parses a config subcommand's flags and wants exactly n names.
func (a *app) configArgs(args []string, n int, what string) (*commonFlags, []string, int) {
	fs, c := a.newFlagSet("config")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return c, nil, a.flagError(c, "config", err)
	}
	if len(pos) != n {
		return c, nil, a.usageError(c, "config", "%s", what)
	}
	return c, pos, -1
}

type contextRow struct {
	Name    string `json:"name"`
	APIURL  string `json:"api_url"`
	Team    string `json:"team,omitempty"`
	Auth    string `json:"auth"`
	Current bool   `json:"current"`
}

func (s *contextStore) rows() []contextRow {
	names := make([]string, 0, len(s.file.Contexts))
	for name := range s.file.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]contextRow, 0, len(names))
	for _, name := range names {
		l := s.file.Contexts[name]
		auth := "token"
		if l.SSO != nil {
			auth = "sso"
		}
		rows = append(rows, contextRow{Name: name, APIURL: l.APIURL, Team: l.Team, Auth: auth, Current: name == s.file.CurrentContext})
	}
	return rows
}

func runConfigGetContexts(a *app, args []string) int {
	c, _, code := a.configArgs(args, 0, "get-contexts takes no arguments")
	if code >= 0 {
		return code
	}
	s, err := a.openContexts(true)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	rows := s.rows()
	if c.json {
		a.printJSON(map[string]any{"current_context": s.file.CurrentContext, "contexts": rows})
		return exitOK
	}
	if len(rows) == 0 {
		a.note("aerolvm: no contexts; run `aerolvm login <url>`")
		return exitOK
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CURRENT\tNAME\tSERVER\tTEAM\tAUTH")
	for _, r := range rows {
		mark := ""
		if r.Current {
			mark = "*"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", mark, r.Name, r.APIURL, dash(r.Team), r.Auth)
	}
	_ = tw.Flush()
	return exitOK
}

func runConfigCurrentContext(a *app, args []string) int {
	c, _, code := a.configArgs(args, 0, "current-context takes no arguments")
	if code >= 0 {
		return code
	}
	s, err := a.openContexts(true)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if s.file.CurrentContext == "" {
		return a.fail(c, &agenttools.Error{Code: agenttools.CodeNotFound, Message: "no current context", Hint: "run `aerolvm login <url>` or `aerolvm config use-context <name>`"}, exitError)
	}
	if c.json {
		a.printJSON(map[string]string{"current_context": s.file.CurrentContext})
		return exitOK
	}
	fmt.Fprintln(a.stdout, s.file.CurrentContext)
	return exitOK
}

func runConfigUseContext(a *app, args []string) int {
	c, pos, code := a.configArgs(args, 1, "use-context takes one context name")
	if code >= 0 {
		return code
	}
	s, err := a.openContexts(true)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	name := pos[0]
	if name != s.file.CurrentContext {
		login, err := s.login(a, name)
		if err != nil {
			return a.fail(c, err, exitError)
		}
		if err := s.use(name, login); err != nil {
			return a.fail(c, err, exitError)
		}
	}
	if c.json {
		a.printJSON(map[string]string{"current_context": name})
	} else {
		a.note("aerolvm: switched to context %q (%s)", name, s.file.Contexts[name].APIURL)
	}
	a.warnEnvOverrides(s.file.Contexts[name].APIURL)
	return exitOK
}

func runConfigRenameContext(a *app, args []string) int {
	c, pos, code := a.configArgs(args, 2, "rename-context takes the old and the new name")
	if code >= 0 {
		return code
	}
	from, to := pos[0], pos[1]
	if !validContextName(to) {
		return a.usageError(c, "config", "%q is not a context name: use 1 to 253 printable characters with no spaces", to)
	}
	s, err := a.openContexts(true)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	login, ok := s.file.Contexts[from]
	if !ok {
		return a.fail(c, &agenttools.Error{Code: agenttools.CodeNotFound, Message: fmt.Sprintf("no context named %q", from)}, exitError)
	}
	if _, taken := s.file.Contexts[to]; taken && to != from {
		return a.fail(c, &agenttools.Error{Code: agenttools.CodeConflict, Message: fmt.Sprintf("a context named %q already exists", to)}, exitError)
	}
	delete(s.file.Contexts, from)
	s.file.Contexts[to] = login
	if s.file.CurrentContext == from {
		s.file.CurrentContext = to
	}
	if err := s.save(); err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(map[string]string{"renamed": from, "name": to})
	} else {
		a.note("aerolvm: context %q renamed to %q", from, to)
	}
	return exitOK
}

func runConfigDeleteContext(a *app, args []string) int {
	c, pos, code := a.configArgs(args, 1, "delete-context takes one context name")
	if code >= 0 {
		return code
	}
	s, err := a.openContexts(true)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	name := pos[0]
	if _, ok := s.file.Contexts[name]; !ok {
		return a.fail(c, &agenttools.Error{Code: agenttools.CodeNotFound, Message: fmt.Sprintf("no context named %q", name)}, exitError)
	}
	delete(s.file.Contexts, name)
	wasCurrent := s.file.CurrentContext == name
	if wasCurrent {
		s.file.CurrentContext = ""
		if err := os.Remove(s.loginPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return a.fail(c, err, exitError)
		}
	}
	if err := s.save(); err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(map[string]any{"deleted": name, "was_current": wasCurrent})
		return exitOK
	}
	a.note("aerolvm: deleted context %q", name)
	if wasCurrent {
		a.note("aerolvm: it was the current context; pick another with `aerolvm config use-context <name>`")
	}
	return exitOK
}

// runConfigView prints both files' contexts with every secret redacted.
func runConfigView(a *app, args []string) int {
	c, _, code := a.configArgs(args, 0, "view takes no arguments")
	if code >= 0 {
		return code
	}
	s, err := a.openContexts(true)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	type viewContext struct {
		APIURL string `json:"api_url" yaml:"api_url"`
		Team   string `json:"team,omitempty" yaml:"team,omitempty"`
		Token  string `json:"token" yaml:"token"`
		SSO    string `json:"sso,omitempty" yaml:"sso,omitempty"`
	}
	view := struct {
		CurrentContext string                 `json:"current_context" yaml:"current_context"`
		Contexts       map[string]viewContext `json:"contexts" yaml:"contexts"`
	}{CurrentContext: s.file.CurrentContext, Contexts: map[string]viewContext{}}
	for name, l := range s.file.Contexts {
		v := viewContext{APIURL: l.APIURL, Team: l.Team, Token: "REDACTED"}
		if l.SSO != nil {
			v.SSO = l.SSO.Issuer
		}
		view.Contexts[name] = v
	}
	if c.json {
		a.printJSON(view)
		return exitOK
	}
	out, _ := yaml.Marshal(view)
	_, _ = a.stdout.Write(out)
	return exitOK
}

// importedLogin is a context file someone handed over: one login (with an
// optional name), as `sandboxd init` will write to admin-context.json, or a
// whole contexts.json.
type importedLogin struct {
	savedLogin
	Name     string                `json:"name,omitempty"`
	Contexts map[string]savedLogin `json:"contexts,omitempty"`
}

func runConfigImport(a *app, args []string) int {
	fs, c := a.newFlagSet("config")
	var name string
	var use bool
	fs.StringVar(&name, "name", "", "")
	fs.BoolVar(&use, "use", false, "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "config", err)
	}
	if len(pos) != 1 {
		return a.usageError(c, "config", "import takes one file")
	}
	b, err := os.ReadFile(pos[0])
	if err != nil {
		return a.fail(c, err, exitError)
	}
	var in importedLogin
	if err := json.Unmarshal(b, &in); err != nil {
		return a.usageError(c, "config", "%s is not a JSON context file", pos[0])
	}
	incoming := in.Contexts
	if len(incoming) == 0 {
		if name == "" {
			name = in.Name
		}
		if name == "" {
			name = contextNameFor(in.APIURL)
		}
		incoming = map[string]savedLogin{name: in.savedLogin}
	} else if name != "" {
		return a.usageError(c, "config", "--name names one context; %s holds %d", pos[0], len(incoming))
	}
	s, err := a.openContexts(true)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	names := make([]string, 0, len(incoming))
	for n, l := range incoming {
		apiURL, err := normalizeAPIURL(l.APIURL)
		if err != nil || strings.TrimSpace(l.Token) == "" || !validContextName(n) {
			return a.usageError(c, "config", "context %q in %s needs a valid name, api_url and token", n, pos[0])
		}
		if _, taken := s.file.Contexts[n]; taken {
			return a.fail(c, &agenttools.Error{Code: agenttools.CodeConflict, Message: fmt.Sprintf("a context named %q already exists", n),
				Hint: "rename or delete it first, or import with --name"}, exitError)
		}
		l.APIURL = apiURL
		incoming[n] = l
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s.file.Contexts[n] = incoming[n]
	}
	current := ""
	if (use || s.file.CurrentContext == "") && len(names) == 1 {
		current = names[0]
		if err := s.use(current, incoming[current]); err != nil {
			return a.fail(c, err, exitError)
		}
	} else if err := s.save(); err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(map[string]any{"imported": names, "current_context": s.file.CurrentContext})
		return exitOK
	}
	a.note("aerolvm: imported %s", strings.Join(quoteAll(names), ", "))
	if current != "" {
		a.note("aerolvm: %q is now the current context", current)
	}
	return exitOK
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}
