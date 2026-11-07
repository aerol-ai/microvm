package apiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestIdentityRoleCalls(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	role := models.IdentityRole{Tag: "deploy", MinRole: "runner", Team: "payments", CreatedAt: at, UpdatedAt: at}
	roleJSON := `{"tag":"deploy","min_role":"runner","team":"payments","created_at":"2026-11-06T09:00:00Z","updated_at":"2026-11-06T09:00:00Z"}`
	tests := []struct {
		name, wantMethod, wantURI, wantBody string
		status                              int
		reply                               string
		call                                func(*Client) (any, error)
		want                                any
	}{
		{
			name: "put sends min_role and the team as a query", wantMethod: http.MethodPut,
			wantURI: "/v1/identity/roles/deploy?team=payments", wantBody: `{"min_role":"runner"}`,
			status: http.StatusOK, reply: roleJSON,
			call: func(c *Client) (any, error) {
				return c.PutIdentityRole(ctx, "deploy", sdktypes.IdentityRoleOptions{MinRole: "runner", Team: "payments"})
			},
			want: role,
		},
		{
			name: "put for the operator namespace sends no team", wantMethod: http.MethodPut,
			wantURI: "/v1/identity/roles/ops", wantBody: `{"min_role":"admin"}`, status: http.StatusOK, reply: roleJSON,
			call: func(c *Client) (any, error) {
				return c.PutIdentityRole(ctx, "ops", sdktypes.IdentityRoleOptions{MinRole: "admin"})
			},
		},
		{
			name: "list pages by team, cursor and limit", wantMethod: http.MethodGet,
			wantURI: "/v1/identity/roles?cursor=a&limit=10&team=payments", status: http.StatusOK,
			reply: `{"roles":[` + roleJSON + `],"next_cursor":"deploy"}`,
			call: func(c *Client) (any, error) {
				return c.ListIdentityRoles(ctx, sdktypes.ListIdentityRolesOptions{Team: "payments", Cursor: "a", Limit: 10})
			},
			want: models.IdentityRoleList{Roles: []models.IdentityRole{role}, NextCursor: "deploy"},
		},
		{
			name: "list turns a null list into an empty one", wantMethod: http.MethodGet,
			wantURI: "/v1/identity/roles", status: http.StatusOK, reply: `{"roles":null}`,
			call: func(c *Client) (any, error) { return c.ListIdentityRoles(ctx, sdktypes.ListIdentityRolesOptions{}) },
			want: models.IdentityRoleList{Roles: []models.IdentityRole{}},
		},
		{
			name: "delete escapes the tag and keeps the team", wantMethod: http.MethodDelete,
			wantURI: "/v1/identity/roles/a%2Fb?team=payments", status: http.StatusNoContent,
			call: func(c *Client) (any, error) { return nil, c.DeleteIdentityRole(ctx, "a/b", "payments") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tt.wantMethod || r.URL.RequestURI() != tt.wantURI {
					t.Errorf("request = %s %s, want %s %s", r.Method, r.URL.RequestURI(), tt.wantMethod, tt.wantURI)
				}
				if tt.wantBody != "" {
					var got, want map[string]any
					_ = json.NewDecoder(r.Body).Decode(&got)
					_ = json.Unmarshal([]byte(tt.wantBody), &want)
					if !reflect.DeepEqual(got, want) {
						t.Errorf("body = %v, want %v", got, want)
					}
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.reply))
			}))
			defer server.Close()
			got, err := tt.call(NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()}))
			if err != nil {
				t.Fatalf("call error = %v", err)
			}
			if tt.want != nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// Every role call is idempotent on the server, so a 502 is retried.
func TestIdentityRoleCallsRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	if err := client.DeleteIdentityRole(context.Background(), "deploy", ""); err != nil || calls.Load() != 2 {
		t.Fatalf("delete = %v after %d calls", err, calls.Load())
	}
	server.Close()
	if _, err := client.ListIdentityRoles(context.Background(), sdktypes.ListIdentityRolesOptions{}); err == nil {
		t.Fatal("a list against a closed server succeeded")
	}
}

// The create option and the sandbox's identity ride the shared models.
func TestCreateCarriesIdentity(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"id":"sb-1","image":"alpine","status":"started","identity":{"role_tag":"deploy","audience":"sts.amazonaws.com","subject":"team:payments:role:deploy","token_file":"/run/aerolvm/identity/token"}}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	sb, _, err := client.Create(context.Background(), sdktypes.CreateSandboxOptions{Image: "alpine",
		Identity: &sdktypes.IdentityOptions{RoleTag: "deploy", AWSRoleARN: "arn:aws:iam::123456789012:role/deploy"}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"role_tag": "deploy", "aws_role_arn": "arn:aws:iam::123456789012:role/deploy"}
	if !reflect.DeepEqual(body["identity"], want) {
		t.Fatalf("sent identity = %v", body["identity"])
	}
	if sb.Identity == nil || sb.Identity.Subject != "team:payments:role:deploy" {
		t.Fatalf("sandbox identity = %+v", sb.Identity)
	}
}
