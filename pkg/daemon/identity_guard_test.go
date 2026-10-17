package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

type acceptingValidator struct{}

func (acceptingValidator) Validate(context.Context, string) (controlplane.Identity, error) {
	return controlplane.Identity{OwnerRef: "acct"}, nil
}

// TestIdentityBootGuard: sandboxd's identity and a provider's own token
// Validator never run together (§5.2); every other combination boots.
func TestIdentityBootGuard(t *testing.T) {
	cases := []struct {
		name     string
		identity bool
		provider controlplane.Provider
		wantErr  bool
	}{
		{name: "identity off, no provider validator", provider: controlplane.Noop()},
		{name: "identity off, managed validator (today's managed build)", provider: controlplane.Provider{Validator: acceptingValidator{}}.WithDefaults()},
		{name: "identity on, no provider validator", identity: true, provider: controlplane.Noop()},
		{name: "identity on, managed validator", identity: true, provider: controlplane.Provider{Validator: acceptingValidator{}}.WithDefaults(), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := identityBootGuard(config.Config{IdentityEnabled: tc.identity}, tc.provider)
			if tc.wantErr != errors.Is(err, errIdentityWithProviderValidator) || (!tc.wantErr && err != nil) {
				t.Fatalf("err = %v, want refusal %v", err, tc.wantErr)
			}
		})
	}
}

// TestEnterpriseCredentialChecks is UC-283's offline half
// (plans/identity-and-access.md §5.12, L7, D5): open-source enterprise mode
// refuses identity off, then refuses SB_PAT_SCOPE=any, each with its own
// error naming the fix, and boots with identity on (tokens-only is enough)
// and host scope. A managed provider that validates its own tokens already
// enforces named credentials, so its enterprise boot is unchanged (L8).
func TestEnterpriseCredentialChecks(t *testing.T) {
	managed := controlplane.Provider{Validator: acceptingValidator{}}.WithDefaults()
	cases := []struct {
		name     string
		cfg      config.Config
		provider controlplane.Provider
		want     error
	}{
		{name: "enterprise, identity off", cfg: config.Config{EnterpriseMode: true, PATScope: config.PATScopeHost},
			provider: controlplane.Noop(), want: config.ErrEnterpriseNeedsNamedCredentials},
		{name: "enterprise, identity on, scope any", cfg: config.Config{EnterpriseMode: true, IdentityEnabled: true, PATScope: config.PATScopeAny},
			provider: controlplane.Noop(), want: config.ErrEnterpriseNeedsHostPATScope},
		{name: "enterprise, identity on (tokens only), host scope", cfg: config.Config{EnterpriseMode: true, IdentityEnabled: true, PATScope: config.PATScopeHost},
			provider: controlplane.Noop()},
		{name: "enterprise under a managed validator keeps today's boot", cfg: config.Config{EnterpriseMode: true, PATScope: config.PATScopeAny},
			provider: managed},
		{name: "not enterprise: identity off and scope any boot", cfg: config.Config{PATScope: config.PATScopeAny}, provider: controlplane.Noop()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := identityBootGuard(tc.cfg, tc.provider)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if !strings.Contains(config.ErrEnterpriseNeedsHostPATScope.Error(), "SB_PUBLIC_API_SOCKET") ||
		!strings.Contains(config.ErrEnterpriseNeedsHostPATScope.Error(), "named token or SSO") {
		t.Fatal("the scope refusal must name both migration steps (D5)")
	}
}

// TestRunIdentityBootGuards drives the real boot: a refused combination
// stops Run before anything starts, with an error naming the conflict.
func TestRunIdentityBootGuards(t *testing.T) {
	managed := func(context.Context, FleetConfig) (controlplane.Provider, error) {
		return controlplane.Provider{Validator: acceptingValidator{}}, nil
	}
	_ = setBaseRunEnv(t)
	t.Setenv("SB_IDENTITY_ENABLED", "true")
	err := runWithAutoCancel(t, 500*time.Millisecond, managed)
	if err == nil || !strings.Contains(err.Error(), "two identity sources") {
		t.Fatalf("Run err = %v, want the two-identity-sources refusal", err)
	}
}

// The test-only static token file (SB_ITEST_IDENTITY_FILE) is gone (eng
// review D4): the variable is ignored, so a file that does not exist no
// longer stops the boot, with identity on or off, and nothing reads it.
func TestRunIgnoresRetiredITestIdentityFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	for _, identity := range []string{"false", "true"} {
		t.Run("identity="+identity, func(t *testing.T) {
			_ = setBaseRunEnv(t)
			t.Setenv("SB_IDENTITY_ENABLED", identity)
			t.Setenv("SB_ITEST_IDENTITY_FILE", missing)
			if err := runWithAutoCancel(t, 300*time.Millisecond, nil); err != nil {
				t.Fatalf("Run with SB_ITEST_IDENTITY_FILE set: %v", err)
			}
		})
	}
}
