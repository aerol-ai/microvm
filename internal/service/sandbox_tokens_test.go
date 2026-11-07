package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func testTokenService(t *testing.T, maxTTL time.Duration) (*Service, *store.Store, *bytes.Buffer) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "svc-tokens.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	var logs bytes.Buffer
	return &Service{
		cfg:    config.Config{SandboxTokenMaxTTL: maxTTL},
		store:  st,
		cipher: cipher,
		logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}, st, &logs
}

func seedTokenSandbox(t *testing.T, st *store.Store, id, owner string, status models.SandboxStatus) {
	t.Helper()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: id, Image: "alpine:3.19", Status: status, OwnerRef: owner,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
}

func teamCtx(team string) context.Context {
	return controlplane.ContextWithAccess(context.Background(),
		controlplane.TokenAccess("tok_x", "x", controlplane.RoleRunner, team, time.Time{}))
}

// A token issued on one node verifies with no store read, names its
// sandbox and owner, carries the asked scope, and the log line names the
// token id but never the token.
func TestIssueSandboxTokenRoundTrip(t *testing.T) {
	svc, st, logs := testTokenService(t, time.Hour)
	seedTokenSandbox(t, st, "sb-tok", "team:payments", models.SandboxStatusStarted)

	got, err := svc.IssueSandboxToken(teamCtx("payments"), "sb-tok", models.CreateSandboxTokenRequest{
		ExpiresIn: "15m", PathPrefix: "/files", Methods: []string{"get", "HEAD"},
	})
	if err != nil {
		t.Fatalf("IssueSandboxToken: %v", err)
	}
	if !strings.HasPrefix(got.Token, sandboxtoken.Prefix) || !strings.HasPrefix(got.TokenID, sandboxtoken.TokenIDPrefix) ||
		got.SandboxID != "sb-tok" || got.PathPrefix != "/files" || strings.Join(got.Methods, ",") != "GET,HEAD" {
		t.Fatalf("token = %+v", got)
	}
	if d := time.Until(got.ExpiresAt); d < 14*time.Minute || d > 16*time.Minute {
		t.Fatalf("expires_at %v is not ~15m away", got.ExpiresAt)
	}

	// Each call mints a new token: issuing is not idempotent by nature.
	again, err := svc.IssueSandboxToken(teamCtx("payments"), "sb-tok", models.CreateSandboxTokenRequest{ExpiresIn: "15m"})
	if err != nil || again.Token == got.Token || again.TokenID == got.TokenID {
		t.Fatalf("a second issue: %v, same token %v", err, again.Token == got.Token)
	}

	// The store is gone: verification still works, because it reads none.
	_ = st.Close()
	claims, err := svc.VerifySandboxToken(got.Token)
	if err != nil {
		t.Fatalf("VerifySandboxToken: %v", err)
	}
	if claims.SandboxID != "sb-tok" || claims.Owner != "team:payments" || claims.TokenID != got.TokenID {
		t.Fatalf("claims = %+v", claims)
	}
	if !strings.Contains(logs.String(), got.TokenID) || strings.Contains(logs.String(), got.Token) {
		t.Fatalf("log must name the token id and never the token: %s", logs.String())
	}

}

// Two services that share the server key (two cluster nodes) verify each
// other's tokens; one with another key does not.
func TestSandboxTokenVerifiesOnAnotherNode(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "shared-key")
	nodeA, err := secrets.NewCipher("", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := secrets.NewCipher("", keyPath)
	if err != nil {
		t.Fatal(err)
	}
	svcA, st, _ := testTokenService(t, time.Hour)
	svcA.cipher = nodeA
	seedTokenSandbox(t, st, "sb-x", "", models.SandboxStatusStarted)
	tok, err := svcA.IssueSandboxToken(context.Background(), "sb-x", models.CreateSandboxTokenRequest{ExpiresIn: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	svcB := &Service{cipher: nodeB, cfg: config.Config{SandboxTokenMaxTTL: time.Hour}}
	if _, err := svcB.VerifySandboxToken(tok.Token); err != nil {
		t.Fatalf("node B: %v", err)
	}
	other, _, _ := testTokenService(t, time.Hour)
	if _, err := other.VerifySandboxToken(tok.Token); !errors.Is(err, sandboxtoken.ErrInvalidSignature) {
		t.Fatalf("another server key: %v", err)
	}
}

func TestIssueSandboxTokenRefusals(t *testing.T) {
	svc, st, _ := testTokenService(t, time.Hour)
	seedTokenSandbox(t, st, "sb-a", "team:payments", models.SandboxStatusStarted)
	seedTokenSandbox(t, st, "sb-gone", "team:payments", models.SandboxStatusDestroyed)
	cases := []struct {
		name string
		ctx  context.Context
		id   string
		req  models.CreateSandboxTokenRequest
		want error
	}{
		{"no lifetime", context.Background(), "sb-a", models.CreateSandboxTokenRequest{}, ErrSandboxTokenInvalid},
		{"unparsable lifetime", context.Background(), "sb-a", models.CreateSandboxTokenRequest{ExpiresIn: "soon"}, ErrSandboxTokenInvalid},
		{"sub-second lifetime", context.Background(), "sb-a", models.CreateSandboxTokenRequest{ExpiresIn: "500ms"}, ErrSandboxTokenInvalid},
		{"above the cap", context.Background(), "sb-a", models.CreateSandboxTokenRequest{ExpiresIn: "2h"}, ErrSandboxTokenInvalid},
		{"bad port", context.Background(), "sb-a", models.CreateSandboxTokenRequest{ExpiresIn: "1m", Port: 70000}, ErrSandboxTokenInvalid},
		{"bad path", context.Background(), "sb-a", models.CreateSandboxTokenRequest{ExpiresIn: "1m", PathPrefix: "/a/../b"}, ErrSandboxTokenInvalid},
		{"bad method", context.Background(), "sb-a", models.CreateSandboxTokenRequest{ExpiresIn: "1m", Methods: []string{"TRACE"}}, ErrSandboxTokenInvalid},
		{"unknown sandbox", context.Background(), "sb-none", models.CreateSandboxTokenRequest{ExpiresIn: "1m"}, store.ErrNotFound},
		{"another team's sandbox", teamCtx("growth"), "sb-a", models.CreateSandboxTokenRequest{ExpiresIn: "1m"}, store.ErrNotFound},
		{"deleted sandbox", context.Background(), "sb-gone", models.CreateSandboxTokenRequest{ExpiresIn: "1m"}, store.ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.IssueSandboxToken(tc.ctx, tc.id, tc.req); !errors.Is(err, tc.want) {
				t.Fatalf("IssueSandboxToken = %v, want %v", err, tc.want)
			}
		})
	}
}

// No server key, or a revoked one: nothing is issued and nothing verifies.
func TestSandboxTokensWithoutAKey(t *testing.T) {
	svc, st, _ := testTokenService(t, 0)
	seedTokenSandbox(t, st, "sb-a", "", models.SandboxStatusStarted)
	tok, err := svc.IssueSandboxToken(context.Background(), "sb-a", models.CreateSandboxTokenRequest{ExpiresIn: "24h"})
	if err != nil {
		t.Fatalf("default cap is 24h: %v", err)
	}

	svc.cipher.Revoke()
	if _, err := svc.IssueSandboxToken(context.Background(), "sb-a", models.CreateSandboxTokenRequest{ExpiresIn: "1m"}); !errors.Is(err, ErrSandboxTokensUnavailable) || !errors.Is(err, secrets.ErrKeyRevoked) {
		t.Fatalf("issue after revoke = %v", err)
	}
	if _, err := svc.VerifySandboxToken(tok.Token); !errors.Is(err, sandboxtoken.ErrInvalidSignature) {
		t.Fatalf("verify after revoke = %v", err)
	}

	svc.cipher = nil
	if _, err := svc.IssueSandboxToken(context.Background(), "sb-a", models.CreateSandboxTokenRequest{ExpiresIn: "1m"}); !errors.Is(err, ErrSandboxTokensUnavailable) {
		t.Fatalf("issue without a key = %v", err)
	}
	if _, err := svc.VerifySandboxToken(tok.Token); !errors.Is(err, sandboxtoken.ErrInvalidSignature) {
		t.Fatalf("verify without a key = %v", err)
	}
	var nilSvc *Service
	if _, err := nilSvc.VerifySandboxToken(tok.Token); err == nil {
		t.Fatal("a nil service verified")
	}
}

// Verification uses the node's clock and cap: a token past expiry plus the
// skew is refused, and lowering the cap refuses longer tokens at once.
func TestVerifySandboxTokenClockAndCap(t *testing.T) {
	svc, st, _ := testTokenService(t, 2*time.Hour)
	seedTokenSandbox(t, st, "sb-a", "", models.SandboxStatusStarted)
	base := time.Unix(1_800_000_000, 0)
	sandboxTokenNow = func() time.Time { return base }
	t.Cleanup(func() { sandboxTokenNow = time.Now })
	tok, err := svc.IssueSandboxToken(context.Background(), "sb-a", models.CreateSandboxTokenRequest{ExpiresIn: "2h"})
	if err != nil {
		t.Fatal(err)
	}
	sandboxTokenNow = func() time.Time { return base.Add(2*time.Hour + sandboxtoken.ClockSkew + time.Second) }
	if _, err := svc.VerifySandboxToken(tok.Token); !errors.Is(err, sandboxtoken.ErrExpired) {
		t.Fatalf("after expiry: %v", err)
	}
	sandboxTokenNow = func() time.Time { return base.Add(time.Minute) }
	svc.cfg.SandboxTokenMaxTTL = time.Hour
	if _, err := svc.VerifySandboxToken(tok.Token); !errors.Is(err, sandboxtoken.ErrTooLongLived) {
		t.Fatalf("after lowering the cap: %v", err)
	}
}
