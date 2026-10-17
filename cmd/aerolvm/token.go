package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// aerolvm token create|list|revoke manages scoped API tokens
// (plans/identity-and-access.md §5.4, §5.6). It calls /v1/tokens directly:
// the SDKs gain tokens.create/list/revoke in task T9. Admin only for create
// and revoke, auditor or admin for list; sandboxd decides.

// tokenRequestTimeout bounds one token call; a create is one Raft apply.
const tokenRequestTimeout = 30 * time.Second

// maxTokenResponseBytes bounds a /v1/tokens response the CLI reads.
const maxTokenResponseBytes = 16 << 20

func runToken(ctx context.Context, a *app, args []string) int {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "create":
		return runTokenCreate(ctx, a, args)
	case "list", "ls":
		return runTokenList(ctx, a, args)
	case "revoke", "rm":
		return runTokenRevoke(ctx, a, args)
	case "":
		return a.usageError(nil, "token", "expected a subcommand: create, list or revoke")
	}
	return a.usageError(nil, "token", "unknown subcommand %q: expected create, list or revoke", sub)
}

func runTokenCreate(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("token create")
	var name, role, team, expiresIn string
	fs.StringVar(&name, "name", "", "")
	fs.StringVar(&role, "role", "", "")
	fs.StringVar(&team, "team", "", "")
	fs.StringVar(&expiresIn, "expires-in", "", "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "token", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "token", "unexpected argument %q (use --name)", pos[0])
	}
	// Check what the server would refuse anyway, so a typo costs no round
	// trip and the message names the flag.
	switch {
	case !identitywire.ValidTokenName(name):
		return a.usageError(c, "token", "--name is required: 1 to 64 characters of A-Z, a-z, 0-9, '.', '_' and '-'")
	case !controlplane.Role(role).Valid():
		return a.usageError(c, "token", "--role is required: viewer, runner, auditor or admin")
	case team == "":
		return a.usageError(c, "token", "--team is required: a team name, or '*' for every team")
	case expiresIn == "":
		return a.usageError(c, "token", "--expires-in is required: every token expires (for example 90d)")
	}
	if _, err := identitywire.ParseTokenTTL(expiresIn); err != nil {
		return a.usageError(c, "token", "--expires-in must be a positive lifetime such as 90d or 720h")
	}
	var created models.CreatedAPIToken
	req := models.CreateAPITokenRequest{Name: name, Role: role, Team: team, ExpiresIn: expiresIn}
	if err := a.tokenAPI(ctx, c, http.MethodPost, "/v1/tokens", req, &created); err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(created)
		return exitOK
	}
	a.note("aerolvm: created token %s (%s, role %s on %s, expires %s).", created.ID, created.Name, created.Role,
		teamWords(created.Team), created.ExpiresAt.UTC().Format(time.RFC3339))
	a.note("aerolvm: this is the only time the token is shown; store it now.")
	fmt.Fprintln(a.stdout, created.Token)
	return exitOK
}

func runTokenList(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("token list")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "token", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "token", "unexpected argument %q", pos[0])
	}
	var list models.APITokenList
	if err := a.tokenAPI(ctx, c, http.MethodGet, "/v1/tokens", nil, &list); err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		if list.Tokens == nil {
			list.Tokens = []models.APIToken{}
		}
		a.printJSON(list)
		return exitOK
	}
	if len(list.Tokens) == 0 {
		a.note("aerolvm: no API tokens")
		return exitOK
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tROLE\tTEAM\tEXPIRES\tCREATED BY")
	for _, t := range list.Tokens {
		expires := t.ExpiresAt.UTC().Format("2006-01-02")
		if t.Expired {
			expires += " (expired)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Name, t.Role, t.Team, expires, dash(t.CreatedBy))
	}
	_ = tw.Flush()
	return exitOK
}

func runTokenRevoke(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("token revoke")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "token", err)
	}
	if len(pos) != 1 {
		return a.usageError(c, "token", "expected one token id (tok_…)")
	}
	// A pasted token is accepted too: its id is the part before the secret.
	id, ok := identitywire.APITokenIDFrom(pos[0])
	if !ok {
		return a.usageError(c, "token", "%q is not a token id: an id looks like tok_ followed by 12 letters or digits", pos[0])
	}
	if err := a.tokenAPI(ctx, c, http.MethodDelete, "/v1/tokens/"+url.PathEscape(id), nil, nil); err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(map[string]string{"revoked": id})
		return exitOK
	}
	a.note("aerolvm: revoked %s; it no longer works anywhere once every node has synced (seconds)", id)
	return exitOK
}

func teamWords(team string) string {
	if team == "*" {
		return "every team"
	}
	return "team " + team
}

// tokenAPI makes one /v1/tokens call with the CLI's connection.
func (a *app) tokenAPI(ctx context.Context, c *commonFlags, method, path string, in, out any) error {
	conn, err := a.resolve(ctx, c)
	if err != nil {
		return err
	}
	return a.callAPI(ctx, c, conn, method, path, in, out)
}

// apiRefusal is a non-2xx answer from sandboxd: the error the SDK would
// return, which agenttools classifies like any other, plus the body's
// identity fields (a 401's reason; the "no binding" 403's reason, issuer,
// name and groups).
type apiRefusal struct {
	*microvm.APIError
	body models.ErrorResponse
}

func (e *apiRefusal) Unwrap() error { return e.APIError }

// callAPI makes one /v1 call the SDK has no method for yet (the SDKs gain
// tokens and whoami in task T9). A refusal becomes the same error the SDK
// would return, so a.fail words it like every other verb's (including the
// "sign in again" hint on a 401).
func (a *app) callAPI(ctx context.Context, c *commonFlags, conn connection, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(ctx, tokenRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(conn.apiURL, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+conn.token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := a.apiHTTPClient(c, conn)
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e models.ErrorResponse
		_ = json.Unmarshal(raw, &e)
		msg := strings.TrimSpace(e.Error)
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		apiErr := &microvm.APIError{StatusCode: resp.StatusCode, Code: e.Code, Message: msg}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			apiErr.RetryAfter = time.Duration(s) * time.Second
		}
		return &apiRefusal{APIError: apiErr, body: e}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("sandboxd sent an unreadable response: %w", err)
	}
	return nil
}
