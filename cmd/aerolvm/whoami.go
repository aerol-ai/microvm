package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// aerolvm whoami, aerolvm auth token, and the API-token expiry warning
// (plans/identity-and-access.md §5.6, CEO review D8, D15 and D22, design
// review DR15).

const (
	// expiryWarnWithin: an API token closer than this to its expiry gets a
	// warning on stderr with every command (D8).
	expiryWarnWithin = 7 * 24 * time.Hour
	// expiryCheckEvery: a token's expiry is asked of sandboxd at most this
	// often; in between it comes from the cache (D15).
	expiryCheckEvery = 24 * time.Hour
	// maxExplainGroups is how many groups `whoami --explain` lists, the
	// dashboard's cap (DR8).
	maxExplainGroups = 50
)

// whoAmIResponse is GET /v1/whoami's body, with the explanation an
// explained call may add.
type whoAmIResponse struct {
	models.WhoAmI
	Explain *identitywire.WhoAmIExplain `json:"explain,omitempty"`
}

// whoAmI asks sandboxd who conn's credential is.
func (a *app) whoAmI(ctx context.Context, c *commonFlags, conn connection, explain bool) (whoAmIResponse, error) {
	path := "/v1/whoami"
	if explain {
		path += "?" + identitywire.WhoAmIExplainQuery + "=1"
	}
	var out whoAmIResponse
	err := a.callAPI(ctx, c, conn, http.MethodGet, path, nil, &out)
	return out, err
}

func runWhoAmI(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("whoami")
	var explain bool
	fs.BoolVar(&explain, "explain", false, "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "whoami", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "whoami", "unexpected argument %q", pos[0])
	}
	// prepare, not resolve: this call's own answer feeds the expiry cache.
	conn, err := a.prepare(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	who, err := a.whoAmI(ctx, c, conn, explain)
	if err != nil {
		var r *apiRefusal
		if errors.As(err, &r) && isNoBinding(r.body) {
			via := r.body.Issuer
			if conn.sso != nil {
				via = conn.sso.displayName()
			}
			claims, _ := decodeIDToken(conn.token)
			if explain && !c.json {
				fmt.Fprint(a.stdout, explainNoBinding(r.body))
			}
			return a.fail(c, noBindingError(conn.apiURL, via, claims.person(), r.body), exitError)
		}
		return a.fail(c, err, exitError)
	}
	a.recordTokenExpiry(conn, who.WhoAmI)
	if c.json {
		a.printJSON(who)
		return exitOK
	}
	fmt.Fprint(a.stdout, a.formatWhoAmI(conn, who.WhoAmI))
	if explain {
		fmt.Fprint(a.stdout, a.formatExplain(conn, who))
	}
	return exitOK
}

// principalName is the first line of whoami: the display name, else the
// stable id.
func principalName(who models.WhoAmI) string {
	if who.Principal.Name != "" {
		return who.Principal.Name
	}
	return dash(who.Principal.ID)
}

// formatWhoAmI is DR15's whoami layout: the name, then aligned rows.
func (a *app) formatWhoAmI(conn connection, who models.WhoAmI) string {
	var b strings.Builder
	b.WriteString(principalName(who) + "\n")
	row := func(k, v string) { fmt.Fprintf(&b, "%-9s%s\n", k, v) }
	row("role", dash(who.Role))
	row("team", teamLabel(who.Team))
	row("via", viaLabel(conn, who))
	row("expires", expiresLabel(a.clock(), who.ExpiresAt))
	return b.String()
}

func teamLabel(team string) string {
	if team == controlplane.FleetTeam {
		return "all teams"
	}
	return dash(team)
}

// viaLabel names the credential: the provider's display name, the API
// token's name, or the server token.
func viaLabel(conn connection, who models.WhoAmI) string {
	switch controlplane.PrincipalKind(who.Principal.Kind) {
	case controlplane.PrincipalOperator:
		return "server token"
	case controlplane.PrincipalToken:
		return `API token "` + principalName(who) + `"`
	case controlplane.PrincipalOIDC:
		if conn.sso != nil {
			return conn.sso.displayName()
		}
		// An ID token from the environment (CI): its principal id is
		// oidc:<issuer>:<sub>, and the issuer name is all the CLI knows.
		if rest, ok := strings.CutPrefix(who.Principal.ID, string(controlplane.PrincipalOIDC)+":"); ok {
			if issuer, _, ok := strings.Cut(rest, ":"); ok {
				return issuer
			}
		}
	case controlplane.PrincipalControlPlane:
		return "managed account"
	}
	return dash(who.Principal.Kind)
}

// expiresLabel is "in 54m (15:04 UTC)" within a day, "in 6 days
// (2026-10-23)" beyond, and "never" for a credential that doesn't expire.
func expiresLabel(now time.Time, at *time.Time) string {
	if at == nil {
		return "never"
	}
	left := at.Sub(now)
	switch {
	case left <= 0:
		return "expired (" + at.UTC().Format("2006-01-02 15:04 UTC") + ")"
	case left < 24*time.Hour:
		return "in " + shortDuration(left) + " (" + at.UTC().Format("15:04 UTC") + ")"
	}
	return inDays(left) + " (" + at.UTC().Format(time.DateOnly) + ")"
}

// shortDuration is "3h12m", "54m" or "40s".
func shortDuration(d time.Duration) string {
	switch {
	case d >= time.Hour:
		h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
		if m == 0 {
			return strconv.Itoa(h) + "h"
		}
		return fmt.Sprintf("%dh%dm", h, m)
	case d >= time.Minute:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	}
	return strconv.Itoa(int(d/time.Second)) + "s"
}

// inDays is "in 6 days", counting whole days left.
func inDays(left time.Duration) string {
	switch days := int(left / (24 * time.Hour)); days {
	case 0:
		return "in less than a day"
	case 1:
		return "in 1 day"
	default:
		return "in " + strconv.Itoa(days) + " days"
	}
}

// formatExplain is `whoami --explain` (D22): which binding matched, and the
// caller's own claims it was matched against. It never shows another
// principal's bindings or claims; sandboxd sends only the caller's.
func (a *app) formatExplain(conn connection, who whoAmIResponse) string {
	var b strings.Builder
	b.WriteString("\nWhy:\n")
	kind := controlplane.PrincipalKind(who.Principal.Kind)
	switch {
	case who.Explain != nil && len(who.Explain.Matched) > 0:
		for _, m := range who.Explain.Matched {
			state := "also matched"
			if m.InEffect {
				state = "matched, in effect"
			}
			fmt.Fprintf(&b, "  binding %d %s: %s\n", m.Index, state, m.Text)
		}
	case kind == controlplane.PrincipalOIDC:
		b.WriteString("  this sandboxd doesn't report which binding matched. It uses the first\n" +
			"  binding in its identity file that matches the claims below, or with a\n" +
			"  team selected, the first one for that team.\n")
	case kind == controlplane.PrincipalToken:
		b.WriteString("  an API token carries its own role and team; no binding is involved.\n")
	case kind == controlplane.PrincipalOperator:
		b.WriteString("  the server token (sandboxd's SB_PAT_TOKEN) acts as admin on all teams;\n" +
			"  no binding is involved.\n")
	default:
		fmt.Fprintf(&b, "  %s sets the role; no binding is involved.\n", viaLabel(conn, who.WhoAmI))
	}
	if who.Explain != nil && who.Explain.Claims != nil {
		cl := who.Explain.Claims
		writeClaims(&b, cl.Issuer, [][2]string{
			{"username", dash(cl.Username)},
			{"groups", groupsLabel(cl.Groups, cl.GroupOverage)},
			{"roles", groupsLabel(cl.Roles, false)},
		})
	} else if claims, ok := decodeIDToken(conn.token); ok {
		issuer := claims.Issuer
		if conn.sso != nil {
			issuer = conn.sso.issuerName()
		}
		rows := [][2]string{{"subject", dash(printable(claims.Subject))}}
		if claims.Email != "" {
			rows = append(rows, [2]string{"email", printable(claims.Email)})
		}
		rows = append(rows, [2]string{"groups", groupsLabel(claims.Groups, false)}, [2]string{"roles", groupsLabel(claims.Roles, false)})
		writeClaims(&b, issuer, rows)
	}
	return b.String()
}

// explainNoBinding is `whoami --explain` for a sign-in no binding matched:
// the claims from the 403, all the caller's own.
func explainNoBinding(body models.ErrorResponse) string {
	var b strings.Builder
	b.WriteString("Why:\n  no binding in this sandboxd's identity file matches your sign-in.\n")
	writeClaims(&b, body.Issuer, [][2]string{
		{"username", dash(body.Name)},
		{"groups", groupsLabel(body.Groups, body.Reason == controlplane.GroupOverageReason)},
	})
	return b.String()
}

func writeClaims(b *strings.Builder, issuer string, rows [][2]string) {
	fmt.Fprintf(b, "\nYour sign-in carried (issuer %s):\n", issuer)
	for _, r := range rows {
		fmt.Fprintf(b, "  %-10s%s\n", r[0], r[1])
	}
}

func groupsLabel(groups []string, overage bool) string {
	switch {
	case overage:
		return "too many to list (group overage)"
	case len(groups) == 0:
		return "(none)"
	}
	return listUpTo(groups, maxExplainGroups)
}

func runAuth(ctx context.Context, a *app, args []string) int {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "token":
		return runAuthToken(ctx, a, args)
	case "":
		return a.usageError(nil, "auth", "expected a subcommand: token")
	}
	return a.usageError(nil, "auth", "unknown subcommand %q: expected token", sub)
}

// runAuthToken prints the bearer the CLI would send, renewed first, for
// scripts and SDKs: SB_PAT_TOKEN=$(aerolvm auth token).
func runAuthToken(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("auth token")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "auth", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "auth", "unexpected argument %q", pos[0])
	}
	conn, err := a.resolve(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if !c.json {
		fmt.Fprintln(a.stdout, conn.token)
		return exitOK
	}
	out := struct {
		APIURL    string     `json:"api_url"`
		Token     string     `json:"token"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}{APIURL: conn.apiURL, Token: conn.token}
	if conn.sso != nil {
		expires := conn.sso.expiry()
		out.ExpiresAt = &expires
	}
	a.printJSON(out)
	return exitOK
}

// tokenExpiry is the cached expiry of one API token, so the warning costs at
// most one whoami a day per token (D15).
type tokenExpiry struct {
	APIURL    string    `json:"api_url"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	CheckedAt time.Time `json:"checked_at"`
}

// cacheDir is $XDG_CACHE_HOME/aerolvm, else %LocalAppData%\aerolvm on
// Windows and ~/.cache/aerolvm elsewhere (macOS too, like the config).
func (a *app) cacheDir() (string, bool) {
	dir := strings.TrimSpace(a.getenv("XDG_CACHE_HOME"))
	if dir == "" && runtime.GOOS == "windows" {
		dir = strings.TrimSpace(a.getenv("LocalAppData"))
	}
	if dir == "" {
		home := strings.TrimSpace(a.getenv("HOME"))
		if home == "" {
			return "", false
		}
		dir = filepath.Join(home, ".cache")
	}
	return filepath.Join(dir, "aerolvm"), true
}

// tokenExpiryPath is where one API token's expiry is cached, keyed by its
// id (never the secret); ok is false for a credential that isn't an API
// token: the operator token never expires, and an SSO login renews itself.
func (a *app) tokenExpiryPath(token string) (string, bool) {
	t, err := identitywire.ParseAPIToken(token)
	if err != nil {
		return "", false
	}
	dir, ok := a.cacheDir()
	if !ok {
		return "", false
	}
	return filepath.Join(dir, "token-"+t.ID+".json"), true
}

// checkTokenExpiry warns when conn's API token expires within a week (D8),
// whether it is the saved login or comes from SB_PAT_TOKEN / SB_API_TOKEN
// in CI (D15). The expiry comes from the cache when it was checked within a
// day, else from one whoami; force asks sandboxd regardless (at login). A
// failure of any kind is silent: the command's own call reports a real
// problem, and the warning is never worth failing a command for.
func (a *app) checkTokenExpiry(ctx context.Context, c *commonFlags, conn connection, force bool) {
	path, ok := a.tokenExpiryPath(conn.token)
	if !ok {
		return
	}
	var cached tokenExpiry
	fresh := false
	if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &cached) == nil {
		age := a.clock().Sub(cached.CheckedAt)
		fresh = sameAPIURL(cached.APIURL, conn.apiURL) && age >= 0 && age < expiryCheckEvery
	}
	if force || !fresh {
		who, err := a.whoAmI(ctx, c, conn, false)
		if err != nil {
			return
		}
		a.recordTokenExpiry(conn, who.WhoAmI)
		return
	}
	a.warnExpiring(cached)
}

// recordTokenExpiry caches the expiry a whoami answer gave for conn's API
// token and warns when it is close.
func (a *app) recordTokenExpiry(conn connection, who models.WhoAmI) {
	path, ok := a.tokenExpiryPath(conn.token)
	if !ok {
		return
	}
	entry := tokenExpiry{APIURL: conn.apiURL, Name: principalName(who), CheckedAt: a.clock()}
	if who.ExpiresAt != nil {
		entry.ExpiresAt = *who.ExpiresAt
	}
	_ = writeJSONFile(path, entry)
	a.warnExpiring(entry)
}

// warnExpiring is DR15's expiry line, on stderr only: never in stdout,
// --json or MCP output (D8).
func (a *app) warnExpiring(e tokenExpiry) {
	if e.ExpiresAt.IsZero() {
		return
	}
	left := e.ExpiresAt.Sub(a.clock())
	if left <= 0 || left >= expiryWarnWithin {
		return
	}
	a.note(`aerolvm: warning: the API token "%s" expires %s (%s). Ask an admin for a new one before then.`,
		e.Name, inDays(left), e.ExpiresAt.UTC().Format(time.DateOnly))
}
