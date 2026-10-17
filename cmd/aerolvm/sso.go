package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// aerolvm login's SSO path, and the renewal of an SSO login
// (plans/identity-and-access.md §5.6). The CLI is a public OAuth client
// (L1): authorization code with PKCE and a loopback redirect (RFC 8252), or
// the device flow (RFC 8628) for an SSH session. It sends the provider's ID
// token to sandboxd as the bearer, and every node verifies it offline. The
// CLI never checks the signature itself: it reads `exp` to know when to
// renew, and the claims it shows the person.

const (
	// renewBefore: a command renews the ID token when less than this is
	// left, so no request leaves with a token about to die (§5.6).
	renewBefore = 60 * time.Second
	// ssoRequestTimeout bounds one request to a discovery document or to the
	// identity provider's token endpoint.
	ssoRequestTimeout = 30 * time.Second
	// maxDiscoveryBytes caps a discovery document, as sandboxd caps the
	// provider's (finding 5.5).
	maxDiscoveryBytes = 1 << 20
	// renewRetryAfter: after a failed renewal, a long-running command (mcp)
	// asks the provider again at most this often, not on every request.
	renewRetryAfter = time.Minute
	// lockStale: a renewal lock older than this was left by an aerolvm that
	// died mid-renewal, since one renewal is one bounded request.
	lockStale = 2 * ssoRequestTimeout
	// lockPoll is how often a waiting aerolvm looks at the lock again.
	lockPoll = 50 * time.Millisecond
)

// ssoWaitTimeout bounds how long login waits for the person to finish
// signing in, in the browser or on another device. A variable so a test
// can give up sooner.
var ssoWaitTimeout = 10 * time.Minute

// ssoLogin is what an SSO login saves next to the ID token: enough to renew
// it without another discovery round trip, and the names the CLI shows.
type ssoLogin struct {
	// Issuer is the identity-file name; DisplayName labels it (DR3).
	Issuer      string `json:"issuer"`
	DisplayName string `json:"display_name"`
	IssuerURL   string `json:"issuer_url"`
	Kind        string `json:"kind,omitempty"`
	ClientID    string `json:"client_id"`
	// ClientSecret is set only when given with --client-secret-stdin.
	// Google's desktop clients send one that Google documents as not
	// confidential; it never reaches sandboxd (§5.6, L1).
	ClientSecret string `json:"client_secret,omitempty"`
	TokenURL     string `json:"token_url"`
	RefreshToken string `json:"refresh_token,omitempty"`
	// Expiry is the ID token's exp.
	Expiry time.Time `json:"expiry"`
}

// oauthConfig is l as a public client of its provider. Client credentials
// go in the form body, the way public clients send their client_id.
func (l *ssoLogin) oauthConfig(authURL, deviceURL, redirect string, scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     l.ClientID,
		ClientSecret: l.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:       authURL,
			DeviceAuthURL: deviceURL,
			TokenURL:      l.TokenURL,
			AuthStyle:     oauth2.AuthStyleInParams,
		},
		RedirectURL: redirect,
		Scopes:      scopes,
	}
}

// ssoRequest is one `aerolvm login` through SSO.
type ssoRequest struct {
	apiURL string
	path   string
	team   string
	issuer string
	secret string
	device bool
	// canAsk: stdin is a terminal nobody has used up, so login may ask
	// which provider to use.
	canAsk bool
}

// httpStatusError is a discovery document that did not come back 200.
type httpStatusError struct {
	url    string
	status int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("%s answered %d %s", e.url, e.status, http.StatusText(e.status))
}

// getJSON reads one unauthenticated JSON document: sandboxd's sign-in
// discovery or a provider's OIDC discovery. No credential is ever sent.
func (a *app) getJSON(ctx context.Context, c *commonFlags, rawURL string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, ssoRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.providerClient(c).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &httpStatusError{url: rawURL, status: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxDiscoveryBytes {
		return fmt.Errorf("%s sent more than %d bytes", rawURL, maxDiscoveryBytes)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s sent an unreadable document: %w", rawURL, err)
	}
	return nil
}

// fetchAuthDiscovery reads sandboxd's GET /.well-known/aerolvm-auth.
func (a *app) fetchAuthDiscovery(ctx context.Context, c *commonFlags, apiURL string) (identitywire.AuthDiscovery, error) {
	var d identitywire.AuthDiscovery
	err := a.getJSON(ctx, c, apiURL+identitywire.AuthDiscoveryPath, &d)
	return d, err
}

// cliIssuers are the providers a person can sign in to the CLI with: those
// with a CLI client id, in identity-file order.
func cliIssuers(d identitywire.AuthDiscovery) []identitywire.DiscoveryIssuer {
	if !d.IdentityEnabled {
		return nil
	}
	var out []identitywire.DiscoveryIssuer
	for _, iss := range d.Issuers {
		if iss.Clients.CLI != "" && iss.URL != "" {
			out = append(out, iss)
		}
	}
	return out
}

// noSSOError answers --sso against a server with no CLI sign-in. A
// discovery document that isn't there (an older sandboxd answers 404, and
// one that isn't sandboxd anything) means no SSO; a network failure is
// reported as one.
func noSSOError(apiURL string, cause error) error {
	var status *httpStatusError
	if cause != nil && !errors.As(cause, &status) {
		var syntax *json.SyntaxError
		var typeErr *json.UnmarshalTypeError
		if !errors.As(cause, &syntax) && !errors.As(cause, &typeErr) {
			return cause
		}
	}
	return &agenttools.Error{
		Code:    agenttools.CodeInvalidArgument,
		Message: "sandboxd at " + apiURL + " offers no SSO sign-in for the CLI",
		Hint:    "sign in with an API token instead: aerolvm login " + apiURL + " --token-stdin",
	}
}

func displayName(iss identitywire.DiscoveryIssuer) string {
	if iss.DisplayName != "" {
		return iss.DisplayName
	}
	return iss.Name
}

func issuerNames(issuers []identitywire.DiscoveryIssuer) string {
	names := make([]string, 0, len(issuers))
	for _, iss := range issuers {
		names = append(names, iss.Name)
	}
	return strings.Join(names, ", ")
}

// chooseIssuer picks the provider: --issuer by name or display name, the
// only one, or the person's answer to the DR15 prompt. A non-empty problem
// is a usage error.
func (a *app) chooseIssuer(issuers []identitywire.DiscoveryIssuer, req ssoRequest) (iss identitywire.DiscoveryIssuer, problem string) {
	if req.issuer != "" {
		for _, iss := range issuers {
			if iss.Name == req.issuer || strings.EqualFold(displayName(iss), req.issuer) {
				return iss, ""
			}
		}
		return iss, fmt.Sprintf("%s has no sign-in provider %q; it offers %s", req.apiURL, req.issuer, issuerNames(issuers))
	}
	if len(issuers) == 1 {
		return issuers[0], ""
	}
	if !req.canAsk {
		return iss, fmt.Sprintf("%s offers %d sign-in providers; choose one with --issuer (%s)", req.apiURL, len(issuers), issuerNames(issuers))
	}
	var b strings.Builder
	b.WriteString("aerolvm: sign in with")
	for i, iss := range issuers {
		fmt.Fprintf(&b, "  [%d] %s", i+1, displayName(iss))
	}
	a.note("%s", b.String())
	fmt.Fprint(a.stderr, "Choose [1]: ")
	answer := strings.TrimSpace(readLine(a.stdin))
	if answer == "" {
		return issuers[0], ""
	}
	n, err := strconv.Atoi(answer)
	if err != nil || n < 1 || n > len(issuers) {
		return iss, fmt.Sprintf("%q is not one of the choices; give a number from 1 to %d, or use --issuer", answer, len(issuers))
	}
	return issuers[n-1], ""
}

// providerConfig is the part of a provider's OIDC discovery the CLI uses.
type providerConfig struct {
	Issuer                      string   `json:"issuer"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	ScopesSupported             []string `json:"scopes_supported"`
}

// providerProblem is a provider the CLI can't sign in with.
func providerProblem(name, format string, args ...any) *agenttools.Error {
	return &agenttools.Error{
		Code:    agenttools.CodeUnavailable,
		Message: name + " " + fmt.Sprintf(format, args...),
		Hint:    "try again; if it keeps failing, tell your AerolVM admin",
	}
}

// secureURL accepts https, and plain http only to this machine (a local
// development or test issuer). Provider URLs end up in a browser, in an
// `open` command and in token requests, so nothing else is allowed.
func secureURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()))
}

// fetchProviderConfig reads iss's OIDC discovery and checks that it names
// itself and only secure endpoints.
func (a *app) fetchProviderConfig(ctx context.Context, c *commonFlags, iss identitywire.DiscoveryIssuer) (providerConfig, error) {
	name := displayName(iss)
	base := strings.TrimRight(iss.URL, "/")
	if !secureURL(base) {
		return providerConfig{}, providerProblem(name, "has an issuer URL that isn't https (%s)", base)
	}
	var p providerConfig
	if err := a.getJSON(ctx, c, base+"/.well-known/openid-configuration", &p); err != nil {
		return p, providerProblem(name, "can't be reached: %v", err)
	}
	if strings.TrimRight(p.Issuer, "/") != base {
		return p, providerProblem(name, "describes itself as %q, not %q", p.Issuer, base)
	}
	for _, ep := range []string{p.AuthorizationEndpoint, p.TokenEndpoint} {
		if !secureURL(ep) {
			return p, providerProblem(name, "publishes an endpoint that isn't https (%q)", ep)
		}
	}
	if p.DeviceAuthorizationEndpoint != "" && !secureURL(p.DeviceAuthorizationEndpoint) {
		return p, providerProblem(name, "publishes an endpoint that isn't https (%q)", p.DeviceAuthorizationEndpoint)
	}
	return p, nil
}

// ssoScopes asks for an ID token naming the person, a refresh token where
// the provider offers one, and the groups claim where it is a scope.
// Google refuses offline_access; it takes access_type=offline instead.
func ssoScopes(kind string, p providerConfig) []string {
	scopes := []string{"openid", "email", "profile"}
	if kind == identitywire.IssuerKindGoogle {
		return scopes
	}
	if len(p.ScopesSupported) == 0 || slices.Contains(p.ScopesSupported, "offline_access") {
		scopes = append(scopes, "offline_access")
	}
	if slices.Contains(p.ScopesSupported, "groups") {
		scopes = append(scopes, "groups")
	}
	return scopes
}

// browserOptions: Google issues a refresh token to a desktop client only
// with access_type=offline, and reliably only on the consent screen.
func browserOptions(kind string) []oauth2.AuthCodeOption {
	if kind == identitywire.IssuerKindGoogle {
		return []oauth2.AuthCodeOption{oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent")}
	}
	return nil
}

// savedClientSecret reuses the client secret of the login being replaced,
// when it is the same provider app, so --client-secret-stdin is needed once
// (§5.6: "the CLI takes it once").
func (a *app) savedClientSecret(path, apiURL string, l *ssoLogin) string {
	old, exists, err := a.loadLogin(path)
	if err != nil || !exists || old.SSO == nil || !sameAPIURL(old.APIURL, apiURL) ||
		old.SSO.Issuer != l.Issuer || old.SSO.ClientID != l.ClientID {
		return ""
	}
	return old.SSO.ClientSecret
}

func (a *app) loginSSO(ctx context.Context, c *commonFlags, issuers []identitywire.DiscoveryIssuer, req ssoRequest) int {
	iss, problem := a.chooseIssuer(issuers, req)
	if problem != "" {
		return a.usageError(c, "login", "%s", problem)
	}
	p, err := a.fetchProviderConfig(ctx, c, iss)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	login := &ssoLogin{
		Issuer: iss.Name, DisplayName: displayName(iss), IssuerURL: strings.TrimRight(iss.URL, "/"), Kind: iss.Kind,
		ClientID: iss.Clients.CLI, ClientSecret: req.secret, TokenURL: p.TokenEndpoint,
	}
	if login.ClientSecret == "" {
		login.ClientSecret = a.savedClientSecret(req.path, req.apiURL, login)
	}
	var (
		tok   *oauth2.Token
		nonce string
	)
	if req.device {
		tok, err = a.deviceFlow(ctx, c, login, p, req.apiURL)
	} else {
		tok, nonce, err = a.browserFlow(ctx, c, login, p, req.apiURL)
	}
	if err != nil {
		return a.fail(c, err, exitError)
	}
	idToken, claims, err := idTokenFrom(tok, login.DisplayName)
	if err == nil && nonce != "" && claims.Nonce != nonce {
		// OIDC Core 3.1.3.7: the ID token must echo the nonce this sign-in
		// sent, or it was minted for another one.
		err = providerProblem(login.DisplayName, "sent an ID token for a different sign-in")
	}
	if err != nil {
		return a.fail(c, err, exitError)
	}
	login.RefreshToken = tok.RefreshToken
	login.Expiry = claims.expiry()

	conn := connection{apiURL: req.apiURL, token: idToken, team: req.team}
	who, err := a.whoAmI(ctx, c, conn, false)
	if err != nil {
		return a.fail(c, signInRefusal(req.apiURL, login.DisplayName, claims, err), exitError)
	}
	if err := saveLogin(req.path, savedLogin{APIURL: req.apiURL, Token: idToken, Team: req.team, SSO: login}); err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		// The same object a token login prints (--json unchanged, DR15).
		version := ""
		if tools, err := a.toolsFor(c, conn); err == nil {
			if health, err := tools.Client().Health(ctx); err == nil {
				version = health.Version
			}
		}
		a.printJSON(map[string]string{"api_url": req.apiURL, "config_path": req.path, "server_version": version})
	} else {
		a.note("aerolvm: logged in to %s as %s (%s) through %s. The login is saved in %s, readable only by you.",
			req.apiURL, principalName(who.WhoAmI), roleAndTeam(who.WhoAmI), login.DisplayName, req.path)
	}
	if sendsTokenInClear(req.apiURL) {
		a.note("aerolvm: %s is plain HTTP, so the token crosses the network unencrypted; use https:// for a remote sandboxd", req.apiURL)
	}
	a.warnEnvOverrides(req.apiURL)
	return exitOK
}

// roleAndTeam is the "(role runner, team payments)" of the DR15 success
// line.
func roleAndTeam(who models.WhoAmI) string {
	s := "role " + dash(who.Role)
	switch who.Team {
	case "":
	case controlplane.FleetTeam:
		s += ", all teams"
	default:
		s += ", team " + who.Team
	}
	return s
}

// callbackResult is what the provider's redirect to the loopback listener
// carried.
type callbackResult struct {
	code string
	err  string
}

// callbackHandler receives the provider's redirect. One with the wrong
// state (a stale tab, a local probe) is ignored, and login keeps waiting.
func callbackHandler(state string, results chan<- callbackResult) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/callback" || q.Get("state") != state {
			http.Error(w, "This is not the sign-in aerolvm is waiting for.", http.StatusBadRequest)
			return
		}
		res := callbackResult{code: q.Get("code"), err: q.Get("error")}
		if res.code == "" && res.err == "" {
			res.err = "no_code"
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if res.err != "" {
			fmt.Fprintln(w, "Sign-in failed. Return to the terminal for details.")
		} else {
			fmt.Fprintln(w, "You're signed in to AerolVM. You can close this tab and return to the terminal.")
		}
		select {
		case results <- res:
		default: // a second redirect for the same sign-in
		}
	})
}

// browserFlow is the authorization-code flow with PKCE and a loopback
// redirect (RFC 8252). It returns the token response and the nonce the ID
// token must echo.
func (a *app) browserFlow(ctx context.Context, c *commonFlags, login *ssoLogin, p providerConfig, apiURL string) (*oauth2.Token, string, error) {
	// RFC 8252 §7.3: a loopback IP literal on a port the OS picks; the
	// provider accepts any port for a native app's redirect.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	defer ln.Close()
	cfg := login.oauthConfig(p.AuthorizationEndpoint, "", "http://"+ln.Addr().String()+"/callback", ssoScopes(login.Kind, p))
	verifier := oauth2.GenerateVerifier()
	state, nonce := rand.Text(), rand.Text()
	opts := append([]oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)}, browserOptions(login.Kind)...)
	authURL := cfg.AuthCodeURL(state, opts...)

	results := make(chan callbackResult, 1)
	srv := &http.Server{Handler: callbackHandler(state, results), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	a.note("aerolvm: opening your browser to sign in with %s. If it doesn't open, visit: %s", login.DisplayName, authURL)
	_ = a.browser()(authURL) // the URL is printed either way

	wait, cancel := context.WithTimeout(ctx, ssoWaitTimeout)
	defer cancel()
	var res callbackResult
	select {
	case res = <-results:
	case <-wait.Done():
		return nil, "", &agenttools.Error{
			Code:    agenttools.CodeTimeout,
			Message: "gave up waiting for the sign-in in your browser",
			Hint:    "on a machine without a browser, run: aerolvm login --device " + apiURL,
		}
	}
	if res.err != "" {
		return nil, "", providerDeclined(login.DisplayName, res.err)
	}
	octx, ocancel := a.oauthContext(ctx, c, ssoRequestTimeout)
	defer ocancel()
	tok, err := cfg.Exchange(octx, res.code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, "", tokenEndpointError(login, apiURL, err)
	}
	return tok, nonce, nil
}

// deviceFlow is the device authorization grant (RFC 8628): the person
// opens a URL on any device and types a code.
func (a *app) deviceFlow(ctx context.Context, c *commonFlags, login *ssoLogin, p providerConfig, apiURL string) (*oauth2.Token, error) {
	if p.DeviceAuthorizationEndpoint == "" {
		return nil, &agenttools.Error{
			Code:    agenttools.CodeInvalidArgument,
			Message: login.DisplayName + " doesn't offer sign-in with a code (the device flow)",
			Hint:    "run `aerolvm login " + apiURL + "` on a machine with a browser",
		}
	}
	cfg := login.oauthConfig("", p.DeviceAuthorizationEndpoint, "", ssoScopes(login.Kind, p))
	octx, ocancel := a.oauthContext(ctx, c, ssoRequestTimeout)
	da, err := cfg.DeviceAuth(octx)
	ocancel()
	if err != nil {
		return nil, tokenEndpointError(login, apiURL, err)
	}
	a.note("aerolvm: to sign in, open %s and enter the code %s. Waiting…", printable(da.VerificationURI), printable(da.UserCode))
	wctx, wcancel := a.oauthContext(ctx, c, ssoWaitTimeout)
	defer wcancel()
	tok, err := cfg.DeviceAccessToken(wctx, da)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, &agenttools.Error{Code: agenttools.CodeTimeout, Message: "the sign-in code expired before anyone used it", Hint: "run the login again"}
		}
		return nil, tokenEndpointError(login, apiURL, err)
	}
	return tok, nil
}

// providerDeclined is an `error` the provider redirected back with
// (DR9's "Acme Okta didn't sign you in (access_denied)").
func providerDeclined(name, code string) *agenttools.Error {
	return &agenttools.Error{
		Code:    agenttools.CodeUnauthorized,
		Message: fmt.Sprintf("%s didn't sign you in (%s)", name, errorCode(code)),
		Hint:    "try again, or sign in with a different account",
	}
}

// tokenEndpointError words a token or device endpoint refusal.
func tokenEndpointError(login *ssoLogin, apiURL string, err error) error {
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		return err
	}
	code := errorCode(re.ErrorCode)
	switch code {
	case "access_denied", "expired_token":
		return providerDeclined(login.DisplayName, code)
	}
	if desc := printable(re.ErrorDescription); desc != "" {
		code += ": " + desc
	}
	e := &agenttools.Error{
		Code:    agenttools.CodeUnauthorized,
		Message: fmt.Sprintf("%s refused the sign-in (%s)", login.DisplayName, code),
		Hint:    "try again; if it keeps failing, tell your AerolVM admin",
	}
	if login.Kind == identitywire.IssuerKindGoogle && login.ClientSecret == "" {
		e.Hint = "Google sign-in needs the client secret your AerolVM admin gave you: aerolvm login --sso " + apiURL + " --client-secret-stdin"
	}
	return e
}

// errorCode keeps an OAuth error code printable: it comes from the
// provider, or from whoever reached the loopback listener.
func errorCode(s string) string {
	out := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' {
			return r
		}
		return -1
	}, s)
	if len(out) > 64 {
		out = out[:64]
	}
	if out == "" {
		return "unknown_error"
	}
	return out
}

// printable drops control characters (a terminal escape in a provider's
// text must not reach the terminal) and caps the length.
func printable(s string) string {
	out := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
	if r := []rune(out); len(r) > 200 {
		out = string(r[:200])
	}
	return strings.TrimSpace(out)
}

// idTokenClaims are the ID token claims the CLI reads. It never trusts
// them for access: sandboxd verifies the token on every request.
type idTokenClaims struct {
	Issuer            string    `json:"iss"`
	Subject           string    `json:"sub"`
	Exp               float64   `json:"exp"`
	Email             string    `json:"email"`
	PreferredUsername string    `json:"preferred_username"`
	Name              string    `json:"name"`
	Groups            claimList `json:"groups"`
	Roles             claimList `json:"roles"`
	Nonce             string    `json:"nonce"`
}

func (c idTokenClaims) expiry() time.Time { return time.Unix(int64(c.Exp), 0).UTC() }

// person is how the claims name the person, for messages.
func (c idTokenClaims) person() string {
	for _, s := range []string{c.Email, c.PreferredUsername, c.Name, c.Subject} {
		if s != "" {
			return printable(s)
		}
	}
	return "-"
}

// claimList is a claim that is a list of strings, or one string. Any
// other shape reads as empty rather than failing the whole token.
type claimList []string

func (l *claimList) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		if one != "" {
			*l = claimList{one}
		}
		return nil
	}
	var many []any
	if json.Unmarshal(b, &many) != nil {
		return nil
	}
	for _, v := range many {
		if s, ok := v.(string); ok {
			*l = append(*l, s)
		}
	}
	return nil
}

// decodeIDToken reads a JWT's claims without checking its signature.
func decodeIDToken(raw string) (idTokenClaims, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return idTokenClaims{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return idTokenClaims{}, false
	}
	var c idTokenClaims
	if json.Unmarshal(payload, &c) != nil {
		return idTokenClaims{}, false
	}
	return c, true
}

// idTokenFrom takes the ID token out of a token response.
func idTokenFrom(tok *oauth2.Token, name string) (string, idTokenClaims, error) {
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return "", idTokenClaims{}, providerProblem(name, "sent no ID token; ask your AerolVM admin to check that the CLI app may use the openid scope")
	}
	claims, ok := decodeIDToken(raw)
	if !ok || claims.Exp <= 0 {
		return "", idTokenClaims{}, providerProblem(name, "sent an ID token aerolvm can't read")
	}
	return raw, claims, nil
}

// signInRefusal words sandboxd's refusal of a fresh sign-in: the DR15 "no
// binding" line, a D17 401 reason with the DR9 advice, or a 503.
func signInRefusal(apiURL, via string, claims idTokenClaims, err error) error {
	var r *apiRefusal
	if !errors.As(err, &r) {
		return err
	}
	switch r.StatusCode {
	case http.StatusForbidden:
		if isNoBinding(r.body) {
			return noBindingError(apiURL, via, claims.person(), r.body)
		}
	case http.StatusUnauthorized:
		msg := "sandboxd at " + apiURL + " refused the sign-in from " + via
		if r.body.Reason != "" {
			msg += " (" + errorCode(r.body.Reason) + ")"
		}
		return &agenttools.Error{Code: agenttools.CodeUnauthorized, HTTPStatus: r.StatusCode, Message: msg, Hint: reasonHint(r.body.Reason)}
	case http.StatusServiceUnavailable:
		return &agenttools.Error{
			Code: agenttools.CodeUnavailable, HTTPStatus: r.StatusCode, Retryable: true,
			Message: "sign-in is unavailable on " + apiURL + " right now",
			Hint:    "try again in a minute, or sign in with an API token: aerolvm login " + apiURL + " --token-stdin",
		}
	}
	return err
}

// reasonHint is DR9's advice for a D17 refusal reason.
func reasonHint(reason string) string {
	switch controlplane.RejectReason(reason) {
	case controlplane.RejectNotYetValid:
		return "your computer's clock is more than a minute off; fix the clock, then sign in again"
	case controlplane.RejectWrongAudience, controlplane.RejectUnknownIssuer, controlplane.RejectTooLongLived:
		return "this server doesn't accept sign-ins from that app; ask your AerolVM admin to check the issuer in the identity file"
	}
	return "try again; if it keeps failing, tell your AerolVM admin"
}

func isNoBinding(body models.ErrorResponse) bool {
	return body.Reason == controlplane.NoBindingReason || body.Reason == controlplane.GroupOverageReason
}

// maxHintGroups is how many of the caller's groups the "no binding" line
// lists (DR15).
const maxHintGroups = 10

// noBindingError is DR15's "no binding" line, with DR8's wording for the
// overage and no-groups cases. Every name in it is the caller's own claim.
func noBindingError(apiURL, via, fallbackName string, body models.ErrorResponse) *agenttools.Error {
	name := body.Name
	if name == "" {
		name = fallbackName
	}
	msg := fmt.Sprintf("signed in as %s through %s, but no access rule on %s matches your account.", name, via, apiURL)
	switch {
	case body.Reason == controlplane.GroupOverageReason:
		msg += " Your sign-in carried too many groups to list. Ask your admin to bind an Entra app role instead."
	case len(body.Groups) == 0:
		msg += " Ask your AerolVM admin to add one for a group you're in. Your sign-in carried no groups."
	default:
		msg += " Ask your AerolVM admin to add one for a group you're in. Your sign-in carried: " + listUpTo(body.Groups, maxHintGroups) + "."
	}
	return &agenttools.Error{Code: agenttools.CodeForbidden, HTTPStatus: http.StatusForbidden, Message: msg}
}

// listUpTo joins at most max items, then says how many more there are.
func listUpTo(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + " (and " + strconv.Itoa(len(items)-max) + " more)"
}

// ssoSession renews one SSO login for the command that uses it. A command
// renews before its first call (prepare), and a long-running one (mcp, a
// shell) again before any request made with under a minute left
// (credentialTransport). The mutex keeps one renewal in flight per
// process; lockFile keeps one per machine.
type ssoSession struct {
	a    *app
	path string
	// client reaches the provider (the --debug logger when asked).
	client *http.Client

	mu    sync.Mutex
	login savedLogin
	// failedAt is the last failed renewal, zero when none failed (or one
	// succeeded since); cause is its error.
	failedAt time.Time
	cause    error
}

// token returns the ID token to send, renewed first when under a minute is
// left. On a failed renewal it still returns the old token, with the error.
func (s *ssoSession) token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.a.clock()
	if s.login.SSO.Expiry.Sub(now) >= renewBefore {
		return s.login.Token, nil
	}
	if !s.failedAt.IsZero() && now.Sub(s.failedAt) < renewRetryAfter {
		return s.login.Token, s.cause
	}
	if err := s.renew(ctx); err != nil {
		s.failedAt, s.cause = now, err
		return s.login.Token, err
	}
	s.failedAt, s.cause = time.Time{}, nil
	return s.login.Token, nil
}

// renewalFailed reports whether the last renewal failed, so the 401 that
// follows is worded as DR15's refresh failure.
func (s *ssoSession) renewalFailed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.failedAt.IsZero()
}

// displayName is the provider the login signed in through; issuerName is
// its identity-file name; expiry is the current ID token's exp.
func (s *ssoSession) displayName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.login.SSO.DisplayName
}

func (s *ssoSession) issuerName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.login.SSO.Issuer
}

func (s *ssoSession) expiry() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.login.SSO.Expiry
}

// sameLogin reports whether other is still this login (same server and
// provider app), not one that replaced it.
func (s *ssoSession) sameLogin(other savedLogin) bool {
	return other.SSO != nil && sameAPIURL(other.APIURL, s.login.APIURL) &&
		other.SSO.Issuer == s.login.SSO.Issuer && other.SSO.ClientID == s.login.SSO.ClientID
}

// renew spends the refresh token for a new ID token and saves it. Called
// with s.mu held.
func (s *ssoSession) renew(ctx context.Context) error {
	unlock, err := lockFile(ctx, s.path+".lock")
	if err != nil {
		return err
	}
	defer unlock()
	// Another aerolvm (an MCP server, a second terminal) may have renewed
	// this login while this one waited, and rotated the refresh token in
	// doing so: take its result rather than spend the old refresh token,
	// which a provider with rotation treats as theft.
	fresh, exists, err := s.a.loadLogin(s.path)
	stillSaved := err == nil && exists && s.sameLogin(fresh)
	if stillSaved {
		s.login = fresh
		if fresh.SSO.Expiry.Sub(s.a.clock()) >= renewBefore {
			return nil
		}
	}
	sso := *s.login.SSO
	if sso.RefreshToken == "" {
		return errors.New("the login holds no refresh token")
	}
	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	ctx, cancel := context.WithTimeout(context.WithValue(ctx, oauth2.HTTPClient, client), ssoRequestTimeout)
	defer cancel()
	tok, err := sso.oauthConfig("", "", "", nil).TokenSource(ctx, &oauth2.Token{RefreshToken: sso.RefreshToken, Expiry: time.Unix(1, 0)}).Token()
	if err != nil {
		return err
	}
	idToken, claims, err := idTokenFrom(tok, sso.DisplayName)
	if err != nil {
		return err
	}
	sso.RefreshToken, sso.Expiry = tok.RefreshToken, claims.expiry()
	next := s.login
	next.Token, next.SSO = idToken, &sso
	// A login replaced or removed since this command started is not brought
	// back: the renewed token then lives in this process only.
	if stillSaved {
		if err := saveLogin(s.path, next); err != nil {
			return err
		}
	}
	s.login = next
	return nil
}

// renewalFailedError is DR15's refresh-failure line.
func renewalFailedError(apiURL string) *agenttools.Error {
	return &agenttools.Error{
		Code:    agenttools.CodeUnauthorized,
		Message: fmt.Sprintf("your sign-in to %s expired and couldn't be renewed. Sign in again: aerolvm login --sso %s", apiURL, apiURL),
	}
}

// lockFile takes a lock only one process can hold: a file created with
// O_EXCL. Two aerolvm processes on one machine (an MCP server and a
// terminal) then never spend the same refresh token twice. A lock older
// than lockStale was left by an aerolvm that died mid-renewal and is taken
// over.
func lockFile(ctx context.Context, path string) (unlock func(), err error) {
	// A lock that can't even be looked at (a permissions mix-up) must not
	// hang the command: past twice the stale age, give up.
	deadline := time.Now().Add(2 * lockStale)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) > lockStale {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("another aerolvm holds %s", path)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(lockPoll):
		}
	}
}

// credentialTransport adds an SSO login's current ID token, renewed when it
// is about to expire, which the SDK (a fixed bearer) has no option for. It
// also sets the team header (D13) for the CLI's own /v1 calls (callAPI);
// the SDK sets the same header itself, WebSocket handshakes included.
type credentialTransport struct {
	base http.RoundTripper
	team string
	sso  *ssoSession
}

func (t *credentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if t.team != "" {
		r.Header.Set(identitywire.TeamHeader, t.team)
	}
	if t.sso != nil {
		// A failed renewal still sends the old token: sandboxd's 401 says
		// what happened, and explainRefusal words it (DR15).
		token, _ := t.sso.token(r.Context())
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return t.base.RoundTrip(r)
}

// apiHTTPClient is the HTTP client for calls to sandboxd. nil keeps the
// SDK's own client, so the operator token or an API token with no team and
// no --debug sends exactly the requests it always did.
func (a *app) apiHTTPClient(c *commonFlags, conn connection) *http.Client {
	var base http.RoundTripper
	if c != nil && c.debug {
		base = &debugTransport{base: http.DefaultTransport, out: a.stderr}
	}
	if conn.team == "" && conn.sso == nil {
		if base == nil {
			return nil
		}
		return &http.Client{Transport: base}
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &http.Client{Transport: &credentialTransport{base: base, team: conn.team, sso: conn.sso}}
}

// providerClient is the HTTP client for unauthenticated discovery reads
// and the identity provider.
func (a *app) providerClient(c *commonFlags) *http.Client {
	if c != nil && c.debug {
		return debugHTTPClient(a.stderr)
	}
	return http.DefaultClient
}

// oauthContext is ctx for an oauth2 call: bounded, and on providerClient.
func (a *app) oauthContext(ctx context.Context, c *commonFlags, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithValue(ctx, oauth2.HTTPClient, a.providerClient(c)), d)
}

// browser is the browser opener: the test's, or the system's.
func (a *app) browser() func(string) error {
	if a.openBrowser != nil {
		return a.openBrowser
	}
	return openBrowser
}

// openBrowser opens u in the person's browser. u was built on an endpoint
// secureURL accepted, so it is always http(s), never a file or a handler.
func openBrowser(u string) error {
	name, args := browserCommand(runtime.GOOS, u)
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func browserCommand(goos, u string) (string, []string) {
	switch goos {
	case "darwin":
		return "open", []string{u}
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", u}
	}
	return "xdg-open", []string{u}
}
