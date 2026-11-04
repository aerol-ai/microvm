package apihttp

import (
	"net/http"
	"strings"
)

// wsBearerMarker is the first Sec-WebSocket-Protocol entry a browser sends
// before its token: browsers cannot set Authorization on a WebSocket
// handshake, so `sandbox.bearer, <token>` smuggles it in the subprotocol list.
const wsBearerMarker = "sandbox.bearer"

// BearerToken returns the caller's credential from the Authorization header
// or, failing that, the WebSocket subprotocol. It is the ONE extraction used
// both by the API's authenticate and by remote MCP's tool runner, so the
// token that authenticated a request is always the token the MCP tools act
// with (plans/identity-and-access.md eng review D5). Two drifted copies used
// to live in pkg/api/middleware.go and pkg/api/remotemcp/handler.go.
//
//   - Authorization: the scheme matches case-insensitively (RFC 7235 §2.1),
//     so "Bearer", "bearer" and "BEARER" are all accepted; surrounding
//     whitespace is trimmed from the header and from the token.
//   - An Authorization header with any other scheme, or with an empty
//     bearer, falls through to the subprotocol.
//   - Sec-WebSocket-Protocol: the first entry that is neither empty nor the
//     sandbox.bearer marker, across every header value.
//
// X-API-KEY is NOT read here: only the E2B surface accepts it, and it falls
// back to that header itself when this returns "".
func BearerToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	if token, ok := bearerFromAuthorization(r.Header.Get("Authorization")); ok {
		return token
	}
	for _, raw := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, part := range strings.Split(raw, ",") {
			candidate := strings.TrimSpace(part)
			if candidate == "" || candidate == wsBearerMarker {
				continue
			}
			return candidate
		}
	}
	return ""
}

func bearerFromAuthorization(header string) (string, bool) {
	const scheme = "bearer"
	header = strings.TrimSpace(header)
	// The scheme must be followed by whitespace: "Bearerabc" is not a bearer
	// credential, and "Bearer" alone carries none.
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	if c := header[len(scheme)]; c != ' ' && c != '\t' {
		return "", false
	}
	token := strings.TrimSpace(header[len(scheme):])
	return token, token != ""
}
