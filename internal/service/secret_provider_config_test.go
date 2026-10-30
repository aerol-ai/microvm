package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestConfigureSecretProviderLocal(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cipher, err := secrets.NewCipher("", filepath.Join(dir, "key"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := New(config.Config{SecretProvider: "local"}, logger, st, nil, nil, nil, cipher, nil, nil)
	if err := svc.ConfigureSecretProvider(context.Background()); err != nil {
		t.Fatalf("ConfigureSecretProvider: %v", err)
	}
	if svc.secretProvider == nil {
		t.Fatal("expected local provider")
	}
}

func TestConfigureSecretProviderVaultRejected(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cipher, err := secrets.NewCipher("", filepath.Join(dir, "key"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := New(config.Config{SecretProvider: "vault"}, logger, st, nil, nil, nil, cipher, nil, nil)
	err = svc.ConfigureSecretProvider(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("ConfigureSecretProvider vault = %v, want not implemented", err)
	}
}

// failingWrapper is a key store that refuses every call with err.
type failingWrapper struct{ err error }

func (f failingWrapper) Wrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, f.err
}

func (f failingWrapper) Unwrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, f.err
}

// The boot canary runs for every external provider through the router and
// the limiter; strict boot turns its failure into a refusal to start.
func TestConfigureSecretProviderExternalCanary(t *testing.T) {
	newSvc := func(t *testing.T, strict bool, backend secrets.DataKeyWrapper) *Service {
		t.Helper()
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "db.sqlite"))
		if err != nil {
			t.Fatalf("store: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		cipher, err := secrets.NewCipher("", filepath.Join(dir, "key"))
		if err != nil {
			t.Fatalf("cipher: %v", err)
		}
		cfg := config.Config{SecretProvider: "awskms", SecretAWSkmsKeyID: "alias/test", SecretProviderStrictBoot: strict, SecretProviderMaxInFlight: 2}
		svc := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), st, nil, nil, nil, cipher, nil, nil)
		svc.secretWrapBackend = backend
		return svc
	}
	fake, err := secrets.NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	svc := newSvc(t, true, fake)
	if err := svc.ConfigureSecretProvider(context.Background()); err != nil {
		t.Fatalf("healthy key store: %v", err)
	}
	if _, ok := svc.secretProvider.(*secrets.KMSProvider); !ok || secretProviderCanaryOK.Value() != 1 {
		t.Fatalf("provider %T canary %d", svc.secretProvider, secretProviderCanaryOK.Value())
	}

	denied := failingWrapper{err: fmt.Errorf("%w: no grant", secrets.ErrProviderDenied)}
	err = newSvc(t, true, denied).ConfigureSecretProvider(context.Background())
	if !errors.Is(err, secrets.ErrProviderDenied) || !strings.Contains(err.Error(), "SB_SECRET_PROVIDER_STRICT_BOOT=true") {
		t.Fatalf("strict boot with a denied canary = %v", err)
	}
	if err := newSvc(t, false, denied).ConfigureSecretProvider(context.Background()); err != nil || secretProviderCanaryOK.Value() != 0 {
		t.Fatalf("lenient boot = %v, canary %d", err, secretProviderCanaryOK.Value())
	}
}

func TestKeyStoreMetrics(t *testing.T) {
	for class, want := range map[error]string{
		secrets.ErrKeyRevoked:        "key_revoked",
		secrets.ErrKeyVersionRetired: "key_version_retired",
	} {
		if got := classifySecretMetricError(fmt.Errorf("open: %w", class)); got != want {
			t.Fatalf("classifySecretMetricError(%v) = %q, want %q", class, got, want)
		}
	}
	before := keyStoreLimiterWait.Value(secrets.BudgetCreate, "le_5ms")
	recordKeyStoreLimiterWait(secrets.BudgetCreate, 3*time.Millisecond)
	if got := keyStoreLimiterWait.Value(secrets.BudgetCreate, "le_5ms"); got != before+1 {
		t.Fatalf("create wait bucket = %d, want %d", got, before+1)
	}
}
