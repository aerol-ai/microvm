package apihttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestBearerToken is the shared extraction contract (eng review D5). It
// supersedes pkg/api's TestExtractBearerToken and remotemcp's TestBearerToken,
// which each pinned one of the two drifted copies.
func TestBearerToken(t *testing.T) {
	cases := []struct {
		name        string
		auth        string
		subprotocol []string
		apiKey      string
		want        string
	}{
		{name: "no credential", want: ""},
		{name: "canonical scheme", auth: "Bearer tok", want: "tok"},
		{name: "lowercase scheme (RFC 7235)", auth: "bearer tok", want: "tok"},
		{name: "uppercase scheme", auth: "BEARER tok", want: "tok"},
		{name: "mixed-case scheme", auth: "bEaReR tok", want: "tok"},
		{name: "tab after scheme", auth: "Bearer\ttok", want: "tok"},
		{name: "extra spaces are trimmed", auth: "  Bearer   tok  ", want: "tok"},
		{name: "inner spaces are kept", auth: "Bearer tok with space", want: "tok with space"},
		{name: "scheme glued to token is not bearer", auth: "Bearertok", want: ""},
		{name: "scheme alone carries nothing", auth: "Bearer", want: ""},
		{name: "scheme and blanks carry nothing", auth: "Bearer    ", want: ""},
		{name: "other scheme is ignored", auth: "Basic dXNlcjpwYXNz", want: ""},
		{name: "subprotocol smuggle", subprotocol: []string{"sandbox.bearer, ws-tok"}, want: "ws-tok"},
		{name: "subprotocol without spaces", subprotocol: []string{"sandbox.bearer,ws-tok"}, want: "ws-tok"},
		{name: "subprotocol across header values", subprotocol: []string{"sandbox.bearer", "ws-tok"}, want: "ws-tok"},
		{name: "subprotocol skips empty entries", subprotocol: []string{" , sandbox.bearer , , ws-tok"}, want: "ws-tok"},
		{name: "marker alone carries nothing", subprotocol: []string{"sandbox.bearer"}, want: ""},
		{name: "Authorization wins over subprotocol", auth: "Bearer hdr", subprotocol: []string{"sandbox.bearer, ws"}, want: "hdr"},
		{name: "empty bearer falls through to subprotocol", auth: "Bearer ", subprotocol: []string{"sandbox.bearer, ws"}, want: "ws"},
		{name: "other scheme falls through to subprotocol", auth: "Basic x", subprotocol: []string{"sandbox.bearer, ws"}, want: "ws"},
		// The E2B SDKs send X-API-KEY. BearerToken never reads it, so the
		// E2B surface sees "" and falls back to the key itself.
		{name: "E2B X-API-KEY falls through", apiKey: "e2b-key", want: ""},
		{name: "E2B X-API-KEY next to a bearer", auth: "Bearer tok", apiKey: "e2b-key", want: "tok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			for _, v := range tc.subprotocol {
				r.Header.Add("Sec-WebSocket-Protocol", v)
			}
			if tc.apiKey != "" {
				r.Header.Set("X-API-KEY", tc.apiKey)
			}
			if got := BearerToken(r); got != tc.want {
				t.Fatalf("BearerToken = %q, want %q", got, tc.want)
			}
		})
	}
	if got := BearerToken(nil); got != "" {
		t.Fatalf("BearerToken(nil) = %q, want empty", got)
	}
}

// FuzzBearerToken: whatever arrives in the two headers, extraction never
// panics, never returns surrounding whitespace, and never returns the marker
// or a value that was not in the request. FuzzParseAPIToken and FuzzJWTHeader
// (D21) belong with their parsers, which arrive in T3 and T6.
func FuzzBearerToken(f *testing.F) {
	f.Add("Bearer tok", "")
	f.Add("bearer\t tok ", "sandbox.bearer, ws")
	f.Add("", "sandbox.bearer,,x")
	f.Add("Basic abc", "")
	f.Fuzz(func(t *testing.T, auth, subprotocol string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header["Authorization"] = []string{auth}
		r.Header["Sec-Websocket-Protocol"] = []string{subprotocol}
		got := BearerToken(r)
		if got == "" {
			return
		}
		if got != strings.TrimSpace(got) {
			t.Fatalf("token %q keeps surrounding whitespace", got)
		}
		if got == wsBearerMarker {
			t.Fatalf("returned the subprotocol marker")
		}
		if !strings.Contains(auth, got) && !strings.Contains(subprotocol, got) {
			t.Fatalf("token %q appears in neither header", got)
		}
		if utf8.ValidString(auth) && utf8.ValidString(subprotocol) && !utf8.ValidString(got) {
			t.Fatalf("valid input produced invalid UTF-8 %q", got)
		}
	})
}
