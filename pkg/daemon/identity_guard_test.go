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
