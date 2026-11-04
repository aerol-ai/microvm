package microvm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// TestCredentialAndTeamResolution pins the env fallbacks: SB_API_TOKEN is an
// alias that SB_PAT_TOKEN beats, an explicit option beats both, and the
// team header comes from MicroVMConfig.Team, then SB_TEAM, and is absent
// when neither is set.
func TestCredentialAndTeamResolution(t *testing.T) {
	tests := []struct {
		name      string
		config    sdktypes.MicroVMConfig
		env       map[string]string
		wantAuth  string
		wantTeam  string
		wantError bool
	}{
		{name: "SB_PAT_TOKEN only", env: map[string]string{"SB_PAT_TOKEN": "pat"}, wantAuth: "Bearer pat"},
		{name: "SB_API_TOKEN alias only", env: map[string]string{"SB_API_TOKEN": "avm_alias"}, wantAuth: "Bearer avm_alias"},
		{name: "SB_PAT_TOKEN beats SB_API_TOKEN", env: map[string]string{"SB_PAT_TOKEN": "pat", "SB_API_TOKEN": "avm_alias"}, wantAuth: "Bearer pat"},
		{name: "blank SB_PAT_TOKEN falls through to the alias", env: map[string]string{"SB_PAT_TOKEN": "  ", "SB_API_TOKEN": "avm_alias"}, wantAuth: "Bearer avm_alias"},
		{name: "option beats both", config: sdktypes.MicroVMConfig{PATToken: "opt"}, env: map[string]string{"SB_PAT_TOKEN": "pat", "SB_API_TOKEN": "avm_alias"}, wantAuth: "Bearer opt"},
		{name: "SB_TEAM sends the header", env: map[string]string{"SB_API_TOKEN": "avm_alias", "SB_TEAM": " payments "}, wantAuth: "Bearer avm_alias", wantTeam: "payments"},
		{name: "team option beats SB_TEAM", config: sdktypes.MicroVMConfig{Team: "ml"}, env: map[string]string{"SB_PAT_TOKEN": "pat", "SB_TEAM": "payments"}, wantAuth: "Bearer pat", wantTeam: "ml"},
		{name: "blank SB_TEAM sends nothing", env: map[string]string{"SB_PAT_TOKEN": "pat", "SB_TEAM": "  "}, wantAuth: "Bearer pat"},
		{name: "no token anywhere", env: map[string]string{}, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range []string{"SB_PAT_TOKEN", "SB_API_TOKEN", "SB_TEAM"} {
				t.Setenv(name, tt.env[name])
			}
			var gotAuth string
			var gotTeam []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				gotTeam = r.Header.Values(HeaderTeam)
				_ = json.NewEncoder(w).Encode(models.WhoAmI{Principal: models.WhoAmIPrincipal{Kind: "operator", ID: "operator"}, Role: "admin"})
			}))
			defer server.Close()
			config := tt.config
			config.APIUrl = server.URL
			client, err := NewClientWithConfig(&config)
			if tt.wantError {
				if err == nil || !strings.Contains(err.Error(), "SB_API_TOKEN") {
					t.Fatalf("NewClientWithConfig error = %v, want one naming SB_API_TOKEN", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewClientWithConfig: %v", err)
			}
			if _, err := client.WhoAmI(context.Background()); err != nil {
				t.Fatalf("WhoAmI: %v", err)
			}
			if gotAuth != tt.wantAuth {
				t.Fatalf("Authorization = %q, want %q", gotAuth, tt.wantAuth)
			}
			if tt.wantTeam == "" && len(gotTeam) != 0 {
				t.Fatalf("%s = %q, want no header", HeaderTeam, gotTeam)
			}
			if tt.wantTeam != "" && (len(gotTeam) != 1 || gotTeam[0] != tt.wantTeam) {
				t.Fatalf("%s = %q, want %q", HeaderTeam, gotTeam, tt.wantTeam)
			}
		})
	}
}

func TestWhoAmIAndTokens(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path+" team="+r.Header.Get(HeaderTeam))
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/whoami":
			_, _ = w.Write([]byte(`{"principal":{"kind":"token","id":"tok_abc123def456","name":"ci"},"role":"admin","team":"*","expires_at":"2027-01-02T03:04:05Z"}`))
		case "POST /v1/tokens":
			var req models.CreateAPITokenRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode create: %v", err)
			}
			if req.Name == "taken" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"token name already used in this team: \"taken\""}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(models.CreatedAPIToken{APIToken: models.APIToken{ID: "tok_new", Name: req.Name, Role: req.Role, Team: req.Team}, Token: "avm_secret"})
		case "GET /v1/tokens":
			_ = json.NewEncoder(w).Encode(models.APITokenList{Tokens: []models.APIToken{{ID: "tok_new", Name: "ci", Expired: true}}})
		case "DELETE /v1/tokens/tok_new":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	ctx := context.Background()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "avm_admin", APIUrl: server.URL, Team: "ops"})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}

	who, err := client.WhoAmI(ctx)
	if err != nil || who.Principal.ID != "tok_abc123def456" || who.Role != "admin" || who.Team != "*" || who.ExpiresAt == nil {
		t.Fatalf("WhoAmI = (%+v, %v)", who, err)
	}
	created, err := client.Tokens().Create(ctx, sdktypes.CreateAPITokenOptions{Name: "ci", Role: "runner", Team: "payments", ExpiresIn: "90d"})
	if err != nil || created.ID != "tok_new" || created.Token != "avm_secret" || created.Team != "payments" {
		t.Fatalf("Create = (%+v, %v)", created, err)
	}
	if _, err := client.Tokens().Create(ctx, sdktypes.CreateAPITokenOptions{Name: "taken"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("Create(taken) error = %v, want ErrConflict", err)
	}
	list, err := client.Tokens().List(ctx)
	if err != nil || len(list.Tokens) != 1 || !list.Tokens[0].Expired {
		t.Fatalf("List = (%+v, %v)", list, err)
	}
	// Revoke twice: the server answers 204 for a token already gone.
	for i := 0; i < 2; i++ {
		if err := client.Tokens().Revoke(ctx, "tok_new"); err != nil {
			t.Fatalf("Revoke #%d: %v", i+1, err)
		}
	}
	if err := client.Tokens().Revoke(ctx, ""); err == nil {
		t.Fatal("Revoke(\"\") must fail before sending")
	}
	if len(requests) != 6 {
		t.Fatalf("requests = %q, want 6", requests)
	}
	for _, req := range requests {
		if !strings.HasSuffix(req, " team=ops") {
			t.Fatalf("request %q did not carry the configured team", req)
		}
	}
}
