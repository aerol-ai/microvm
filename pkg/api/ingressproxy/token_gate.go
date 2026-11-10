package ingressproxy

// The token gate for ports exposed with visibility "token"
// (plans/agent-sandbox-feature-parity.md §5.9, A2; the token is A1's,
// threat model in pkg/sandboxtoken). Every public request for such a port
// reaches serveSandboxPort (the service never gives it the direct route),
// and the gate runs there before anything else: no body is buffered, no
// wake slot is taken and no sandbox is started for a request without a
// good token.
//
//	?token=<t> ── verify + scope + not revoked ── bad ─► 401 / 403, no cookie
//	           └─ good ─► Set-Cookie __Host-aerolvm-token (Secure, HttpOnly,
//	                      SameSite=Lax, Path=/, no Domain) + 302 to the same
//	                      URL without the token
//	cookie     ── verify + scope + not revoked ── bad ─► 401 / 403
//	           └─ good ─► cookie removed from the request ─► proxy
//	neither    ─► 401
//
// The cookie holds the token itself, so it is checked exactly like the
// token on every request: a revoke refuses a cookie set before it. The
// not-before comes from the same PortAccess read as the gate (no store
// read of its own).
//
// The cookie is host-only (__Host- forbids a Domain), and each port has its
// own host (<id>-<port>.<domain>), so a page on one sandbox's host can never
// read or plant the cookie of another sandbox or port. The 302 takes the
// token out of the address bar, browser history and later Referer headers;
// the token never reaches the app (the redirect is answered here, and the
// cookie is stripped before the proxy hop). Nothing here logs the token.

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
)

// TokenCookieName carries a port token after the ?token= exchange.
const TokenCookieName = "__Host-aerolvm-token"

// TokenQueryParam is the query parameter a token arrives in.
const TokenQueryParam = "token"

// noTokenMessage tells a visitor what the gate wants, without naming
// anything about the sandbox.
const noTokenMessage = "this URL needs a sandbox token: open it with ?token=<token>"

// gatePort checks a request for a token-gated port. notBefore is the
// sandbox's tokens_not_before (PortAccess). It returns true when the request
// may be proxied (and has removed the cookie from it), and false when it
// wrote the answer itself (a refusal or the redirect).
func (h *handlers) gatePort(w http.ResponseWriter, r *http.Request, id string, port int, upstreamPath string, notBefore int64) bool {
	scope := sandboxtoken.Request{SandboxID: id, Port: port, Path: upstreamPath, Method: r.Method}
	if raw, ok := tokenFromQuery(r.URL.RawQuery); ok {
		claims, err := h.checkPortToken(raw, scope, notBefore)
		if err != nil {
			writeGateRefusal(w, err)
			return false
		}
		maxAge := int(time.Until(claims.Expiry()).Seconds())
		if maxAge < 1 {
			maxAge = 1
		}
		http.SetCookie(w, &http.Cookie{
			Name:     TokenCookieName,
			Value:    raw,
			Path:     "/",
			MaxAge:   maxAge,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Location", locationWithoutToken(upstreamPath, r.URL.RawQuery))
		w.WriteHeader(http.StatusFound)
		return false
	}
	cookies := tokenCookies(r.Header.Values("Cookie"))
	if len(cookies) == 0 {
		apihttp.WriteError(w, http.StatusUnauthorized, noTokenMessage)
		return false
	}
	// A browser can hold more than one cookie of this name only if a page
	// on this same host set one; any that covers the request lets it in.
	var lastErr error
	for _, raw := range cookies {
		if _, err := h.checkPortToken(raw, scope, notBefore); err != nil {
			lastErr = err
			continue
		}
		stripTokenCookie(r.Header)
		return true
	}
	writeGateRefusal(w, lastErr)
	return false
}

// checkPortToken verifies raw (no store read), checks it covers scope and
// was not issued before notBefore.
func (h *handlers) checkPortToken(raw string, scope sandboxtoken.Request, notBefore int64) (sandboxtoken.Claims, error) {
	if h.deps.Tokens == nil {
		return sandboxtoken.Claims{}, sandboxtoken.ErrInvalidSignature
	}
	claims, err := h.deps.Tokens.VerifySandboxToken(raw)
	if err != nil {
		return sandboxtoken.Claims{}, err
	}
	if err := claims.Allows(scope); err != nil {
		return sandboxtoken.Claims{}, err
	}
	// After the scope check: a revoked token for another sandbox or port
	// still says which part it does not cover, as it did before.
	if err := claims.CheckNotBefore(notBefore); err != nil {
		return sandboxtoken.Claims{}, err
	}
	return claims, nil
}

// writeGateRefusal answers a bad token: 403 naming the part for a good
// token used out of scope, 401 naming the reason otherwise. Neither says
// anything taken from the token.
func writeGateRefusal(w http.ResponseWriter, err error) {
	var se *sandboxtoken.ScopeError
	if errors.As(err, &se) {
		apihttp.WriteError(w, http.StatusForbidden, "this sandbox token does not cover this request: "+se.Part)
		return
	}
	reason := "malformed"
	switch {
	case errors.Is(err, sandboxtoken.ErrExpired):
		reason = "expired"
	case errors.Is(err, sandboxtoken.ErrNotYetValid):
		reason = "not_yet_valid"
	case errors.Is(err, sandboxtoken.ErrTooLongLived):
		reason = "too_long_lived"
	case errors.Is(err, sandboxtoken.ErrInvalidSignature):
		reason = "invalid_signature"
	case errors.Is(err, sandboxtoken.ErrRevoked):
		reason = "revoked"
	}
	apihttp.WriteError(w, http.StatusUnauthorized, "sandbox token refused: "+reason)
}

// tokenFromQuery finds the token parameter in a raw query. A parameter that
// is present but empty still counts (and is refused as malformed), so
// "?token=" is never quietly passed to the app.
func tokenFromQuery(rawQuery string) (string, bool) {
	for _, part := range strings.Split(rawQuery, "&") {
		key, value, _ := strings.Cut(part, "=")
		if k, err := url.QueryUnescape(key); err != nil || k != TokenQueryParam {
			continue
		}
		v, err := url.QueryUnescape(value)
		if err != nil {
			return "", true
		}
		return v, true
	}
	return "", false
}

// locationWithoutToken is the redirect target: the same path and query,
// every token parameter removed, other parameters kept in order and byte
// for byte. A relative URL, so the browser stays on the host it asked.
func locationWithoutToken(path, rawQuery string) string {
	kept := make([]string, 0, 4)
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		key, _, _ := strings.Cut(part, "=")
		if k, err := url.QueryUnescape(key); err == nil && k == TokenQueryParam {
			continue
		}
		kept = append(kept, part)
	}
	// The path is the visitor's own, decoded: escape it again so a "?" or
	// "#" in it cannot change what the redirect means.
	loc := (&url.URL{Path: path}).EscapedPath()
	if !strings.HasPrefix(loc, "/") {
		loc = "/" + loc
	}
	// "//host" would be a protocol-relative URL to another site, and so
	// would "/\host" in a browser. EscapedPath already writes a backslash
	// as %5C; the check stays so the rule holds whatever builds loc.
	if strings.HasPrefix(loc, "//") || strings.HasPrefix(loc, "/\\") {
		loc = "/" + strings.TrimLeft(loc, "/\\")
	}
	if len(kept) > 0 {
		loc += "?" + strings.Join(kept, "&")
	}
	return loc
}

// tokenCookies returns every value of the token cookie in the Cookie
// headers, read by hand so other cookies are not parsed or re-encoded.
func tokenCookies(headers []string) []string {
	var out []string
	for _, h := range headers {
		for _, part := range strings.Split(h, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && name == TokenCookieName && value != "" {
				out = append(out, strings.Trim(value, `"`))
			}
		}
	}
	return out
}

// stripTokenCookie removes the token cookie from the request's Cookie
// headers and leaves every other cookie exactly as the browser sent it.
func stripTokenCookie(header http.Header) {
	values := header.Values("Cookie")
	if len(values) == 0 {
		return
	}
	header.Del("Cookie")
	for _, h := range values {
		kept := make([]string, 0, 4)
		for _, part := range strings.Split(h, ";") {
			trimmed := strings.TrimSpace(part)
			name, _, _ := strings.Cut(trimmed, "=")
			if trimmed == "" || name == TokenCookieName {
				continue
			}
			kept = append(kept, trimmed)
		}
		if len(kept) > 0 {
			header.Add("Cookie", strings.Join(kept, "; "))
		}
	}
}
