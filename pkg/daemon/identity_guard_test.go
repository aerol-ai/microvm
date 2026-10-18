package daemon

import (
	"context"
	"errors"
	"os"
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

// TestRunIdentityBootGuards drives the real boot: each refused combination
// stops Run before anything starts, with an error naming the conflict.
func TestRunIdentityBootGuards(t *testing.T) {
	itestFile := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(itestFile, []byte("tok-a acct-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	managed := func(context.Context, FleetConfig) (controlplane.Provider, error) {
		return controlplane.Provider{Validator: acceptingValidator{}}, nil
	}
	cases := []struct {
		name     string
		env      map[string]string
		provider ProviderFactory
		wantErr  string
	}{
		{
			name:     "identity on next to a managed validator",
			env:      map[string]string{"SB_IDENTITY_ENABLED": "true"},
			provider: managed,
			wantErr:  "two identity sources",
		},
		{
			name:    "identity on plus SB_ITEST_IDENTITY_FILE",
			env:     map[string]string{"SB_IDENTITY_ENABLED": "true", "SB_ITEST_IDENTITY_FILE": itestFile},
			wantErr: "cannot be combined with SB_IDENTITY_ENABLED=true",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_ = setBaseRunEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			err := runWithAutoCancel(t, 500*time.Millisecond, tc.provider)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Run err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// With identity off the test-only file keeps working until T3 deletes it.
func TestRunITestIdentityFileStillBootsWithIdentityOff(t *testing.T) {
	_ = setBaseRunEnv(t)
	itestFile := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(itestFile, []byte("tok-a acct-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_ITEST_IDENTITY_FILE", itestFile)
	if err := runWithAutoCancel(t, 300*time.Millisecond, nil); err != nil {
		t.Fatalf("Run with the itest file and identity off: %v", err)
	}
	t.Setenv("SB_ITEST_IDENTITY_FILE", filepath.Join(t.TempDir(), "missing"))
	if err := runWithAutoCancel(t, 300*time.Millisecond, nil); err == nil || !strings.Contains(err.Error(), "load SB_ITEST_IDENTITY_FILE") {
		t.Fatalf("Run with a missing itest file = %v", err)
	}
}
