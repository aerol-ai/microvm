package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestIdentityCalls(t *testing.T) {
	ctx := context.Background()
	expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	created := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	token := models.APIToken{ID: "tok_abc123def456", Name: "ci", Role: "runner", Team: "payments", CreatedBy: "operator", CreatedAt: created, ExpiresAt: expires}

	tests := []struct {
		name       string
		wantMethod string
		wantPath   string
		wantBody   string
		status     int
		reply      string
		call       func(*Client) (any, error)
		want       any
	}{
		{
			name:       "whoami decodes principal, role, team and expiry",
			wantMethod: http.MethodGet,
			wantPath:   "/v1/whoami",
			status:     http.StatusOK,
			reply:      `{"principal":{"kind":"token","id":"tok_abc123def456","name":"ci"},"role":"runner","team":"payments","expires_at":"2027-01-02T03:04:05Z"}`,
			call:       func(c *Client) (any, error) { return c.WhoAmI(ctx) },
			want:       models.WhoAmI{Principal: models.WhoAmIPrincipal{Kind: "token", ID: "tok_abc123def456", Name: "ci"}, Role: "runner", Team: "payments", ExpiresAt: &expires},
		},
		{
			name:       "whoami for the operator has no team and no expiry",
			wantMethod: http.MethodGet,
			wantPath:   "/v1/whoami",
			status:     http.StatusOK,
			reply:      `{"principal":{"kind":"operator","id":"operator"},"role":"admin"}`,
			call:       func(c *Client) (any, error) { return c.WhoAmI(ctx) },
			want:       models.WhoAmI{Principal: models.WhoAmIPrincipal{Kind: "operator", ID: "operator"}, Role: "admin"},
		},
		{
			name:       "create sends the wire field names and returns the secret",
			wantMethod: http.MethodPost,
			wantPath:   "/v1/tokens",
			wantBody:   `{"name":"ci","role":"runner","team":"payments","expires_in":"90d"}`,
			status:     http.StatusCreated,
			reply:      `{"id":"tok_abc123def456","name":"ci","role":"runner","team":"payments","created_by":"operator","created_at":"2026-10-17T09:00:00Z","expires_at":"2027-01-02T03:04:05Z","expired":false,"token":"avm_secret"}`,
			call: func(c *Client) (any, error) {
				return c.CreateAPIToken(ctx, models.CreateAPITokenRequest{Name: "ci", Role: "runner", Team: "payments", ExpiresIn: "90d"})
			},
			want: models.CreatedAPIToken{APIToken: token, Token: "avm_secret"},
		},
		{
			name:       "list decodes every token",
			wantMethod: http.MethodGet,
			wantPath:   "/v1/tokens",
			status:     http.StatusOK,
			reply:      `{"tokens":[{"id":"tok_abc123def456","name":"ci","role":"runner","team":"payments","created_by":"operator","created_at":"2026-10-17T09:00:00Z","expires_at":"2027-01-02T03:04:05Z","expired":false}]}`,
			call:       func(c *Client) (any, error) { return c.ListAPITokens(ctx) },
			want:       models.APITokenList{Tokens: []models.APIToken{token}},
		},
		{
			name:       "list turns a null list into an empty one",
			wantMethod: http.MethodGet,
			wantPath:   "/v1/tokens",
			status:     http.StatusOK,
			reply:      `{"tokens":null}`,
			call:       func(c *Client) (any, error) { return c.ListAPITokens(ctx) },
			want:       models.APITokenList{Tokens: []models.APIToken{}},
		},
		{
			name:       "revoke deletes by id",
			wantMethod: http.MethodDelete,
			wantPath:   "/v1/tokens/tok_abc123def456",
			status:     http.StatusNoContent,
			call:       func(c *Client) (any, error) { return nil, c.RevokeAPIToken(ctx, " tok_abc123def456 ") },
		},
		{
			name:       "revoke escapes the id so it stays one path segment",
			wantMethod: http.MethodDelete,
			wantPath:   "/v1/tokens/..%2Fsandboxes",
			status:     http.StatusNoContent,
			call:       func(c *Client) (any, error) { return nil, c.RevokeAPIToken(ctx, "../sandboxes") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tt.wantMethod || r.URL.EscapedPath() != tt.wantPath {
					t.Errorf("request = %s %s, want %s %s", r.Method, r.URL.EscapedPath(), tt.wantMethod, tt.wantPath)
				}
				if tt.wantBody != "" {
					var got, want map[string]any
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Errorf("decode body: %v", err)
					}
					_ = json.Unmarshal([]byte(tt.wantBody), &want)
					if !reflect.DeepEqual(got, want) {
						t.Errorf("body = %v, want %v", got, want)
					}
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.reply))
			}))
			defer server.Close()
			client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
			got, err := tt.call(client)
			if err != nil {
				t.Fatalf("call error = %v", err)
			}
			if tt.want != nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRevokeAPITokenRequiresID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a blank id must not reach the server: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	for _, id := range []string{"", "   "} {
		if err := client.RevokeAPIToken(context.Background(), id); err == nil {
			t.Fatalf("RevokeAPIToken(%q) succeeded", id)
		}
	}
}

// TestIdentityErrorsCarryTheRefusal: the 401/403/409 bodies of the identity
// routes surface as APIError fields, not just text.
func TestIdentityErrorsCarryTheRefusal(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   APIError
	}{
		{
			name:   "name taken",
			status: http.StatusConflict,
			body:   `{"error":"token name already used in this team: \"ci\""}`,
			want:   APIError{StatusCode: 409, Message: "token name already used in this team: \"ci\""},
		},
		{
			name:   "expired token reason",
			status: http.StatusUnauthorized,
			body:   `{"error":"unauthorized","reason":"expired"}`,
			want:   APIError{StatusCode: 401, Message: "unauthorized", Reason: "expired"},
		},
		{
			name:   "missing permission names the role",
			status: http.StatusForbidden,
			body:   `{"error":"role viewer on team payments cannot token.write; ask an admin for role admin on all teams","required_permission":"token.write","role":"viewer"}`,
			want:   APIError{StatusCode: 403, Message: "role viewer on team payments cannot token.write; ask an admin for role admin on all teams", RequiredPermission: "token.write", Role: "viewer"},
		},
		{
			name:   "no binding lists the caller's own claims",
			status: http.StatusForbidden,
			body:   `{"error":"no binding matches","reason":"no_binding","issuer":"okta","name":"Ada","groups":["eng","oncall"]}`,
			want:   APIError{StatusCode: 403, Message: "no binding matches", Reason: "no_binding", Issuer: "okta", Name: "Ada", Groups: []string{"eng", "oncall"}},
		},
		{
			name:   "operator body is unchanged",
			status: http.StatusForbidden,
			body:   `{"error":"operator authorization required"}`,
			want:   APIError{StatusCode: 403, Message: "operator authorization required"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
			_, err := client.CreateAPIToken(context.Background(), models.CreateAPITokenRequest{Name: "ci"})
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error %T %v is not *APIError", err, err)
			}
			if !reflect.DeepEqual(*apiErr, tt.want) {
				t.Fatalf("APIError = %+v, want %+v", *apiErr, tt.want)
			}
			if errors.Is(err, ErrConflict) != (tt.status == http.StatusConflict) {
				t.Fatalf("errors.Is(ErrConflict) mismatch for %d", tt.status)
			}
			list, err := client.ListAPITokens(context.Background())
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tt.status || list.Tokens != nil {
				t.Fatalf("ListAPITokens = (%+v, %v), want the same refusal and no list", list, err)
			}
		})
	}
}

// TestTeamHeaderOnEveryRequest: a client built with a team sends it on
// plain requests, uploads and both WebSocket handshakes; one built without
// sends no header at all (not an empty one).
func TestTeamHeaderOnEveryRequest(t *testing.T) {
	tests := []struct {
		name     string
		team     string
		wantTeam string
		wantSent bool
	}{
		{name: "team set", team: "payments", wantTeam: "payments", wantSent: true},
		{name: "team trimmed", team: "  payments ", wantTeam: "payments", wantSent: true},
		{name: "no team", team: "", wantSent: false},
		{name: "blank team", team: "   ", wantSent: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			seen := map[string][]string{}
			var upgrader websocket.Upgrader
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen[r.URL.Path] = r.Header.Values(HeaderTeam)
				mu.Unlock()
				if websocket.IsWebSocketUpgrade(r) {
					conn, err := upgrader.Upgrade(w, r, nil)
					if err != nil {
						return
					}
					defer conn.Close()
					_ = conn.WriteJSON(map[string]any{"type": "exit", "code": 0})
					return
				}
				switch r.URL.Path {
				case "/v1/whoami":
					_, _ = w.Write([]byte(`{"principal":{"kind":"token","id":"tok_1"},"role":"runner","team":"payments"}`))
				default:
					w.WriteHeader(http.StatusNoContent)
				}
			}))
			defer server.Close()
			ctx := context.Background()
			client := NewClient(server.URL, ClientOptions{PATToken: "pat", Team: tt.team, HTTPClient: server.Client()})
			if _, err := client.WhoAmI(ctx); err != nil {
				t.Fatalf("WhoAmI: %v", err)
			}
			if err := client.RevokeAPIToken(ctx, "tok_1"); err != nil {
				t.Fatalf("RevokeAPIToken: %v", err)
			}
			if err := client.UploadFile(ctx, "sb-1", "/tmp/a", []byte("x")); err != nil {
				t.Fatalf("UploadFile: %v", err)
			}
			exec, err := client.ExecStream(ctx, "sb-1", sdktypes.ExecStreamOptions{Command: "true"})
			if err != nil {
				t.Fatalf("ExecStream: %v", err)
			}
			if _, err := exec.Wait(); err != nil {
				t.Fatalf("exec Wait: %v", err)
			}
			attach, err := client.AttachSession(ctx, "sb-1", "ses-1", SessionAttachOptions{})
			if err != nil {
				t.Fatalf("AttachSession: %v", err)
			}
			if _, _, err := attach.Wait(); err != nil {
				t.Fatalf("attach Wait: %v", err)
			}

			mu.Lock()
			defer mu.Unlock()
			paths := []string{"/v1/whoami", "/v1/tokens/tok_1", "/v1/sandboxes/sb-1/toolbox/files/upload", "/v1/sandboxes/sb-1/toolbox/process/exec/stream", "/v1/sandboxes/sb-1/sessions/ses-1/attach"}
			for _, path := range paths {
				got, ok := seen[path]
				if !ok {
					t.Fatalf("%s was never requested (saw %v)", path, seen)
				}
				if !tt.wantSent {
					if len(got) != 0 {
						t.Fatalf("%s carried %s %q with no team configured", path, HeaderTeam, got)
					}
					continue
				}
				if len(got) != 1 || got[0] != tt.wantTeam {
					t.Fatalf("%s carried %s %q, want exactly %q", path, HeaderTeam, got, tt.wantTeam)
				}
			}
		})
	}
}
