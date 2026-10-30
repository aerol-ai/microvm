package service

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/scaleobs"
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

// A vault node boots through Vault Agent's local proxy (no token in
// sandboxd): the canary runs against Transit and carries the boot
// correlation id; missing settings refuse.
func TestConfigureSecretProviderVault(t *testing.T) {
	var mu sync.Mutex
	var correlation []string
	transit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		correlation = append(correlation, r.Header.Get(secrets.CorrelationHeader))
		mu.Unlock()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/capabilities-self":
			_, _ = w.Write([]byte(`{"data":{"transit/encrypt/k":["update"],"transit/decrypt/k":["update"]}}`))
		case "/v1/transit/encrypt/k":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ciphertext": "vault:v1:" + body["plaintext"].(string)}})
		case "/v1/transit/decrypt/k":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": strings.TrimPrefix(body["ciphertext"].(string), "vault:v1:")}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(transit.Close)

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
	cfg := config.Config{SecretProvider: "vault", SecretProviderStrictBoot: true, SecretVaultAddr: transit.URL, SecretVaultKeyName: "k", SecretVaultMount: "transit"}
	svc := New(cfg, logger, st, nil, nil, nil, cipher, nil, nil)
	if err := svc.ConfigureSecretProvider(context.Background()); err != nil {
		t.Fatalf("ConfigureSecretProvider vault = %v", err)
	}
	if _, ok := svc.secretProvider.(*secrets.KMSProvider); !ok || secretProviderCanaryOK.Value() != 1 {
		t.Fatalf("provider %T canary %d", svc.secretProvider, secretProviderCanaryOK.Value())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(correlation) != 3 {
		t.Fatalf("calls = %d, want capabilities + encrypt + decrypt", len(correlation))
	}
	for _, id := range correlation {
		if id != "aerolvm-background:boot:standalone" {
			t.Fatalf("correlation ids = %v", correlation)
		}
	}

	missing := New(config.Config{SecretProvider: "vault"}, logger, st, nil, nil, nil, cipher, nil, nil)
	if err := missing.ConfigureSecretProvider(context.Background()); err == nil || !strings.Contains(err.Error(), "SB_SECRET_VAULT_ADDR is required") {
		t.Fatalf("vault without settings = %v", err)
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
	// Key-store calls: {backend,op,class} counts and a latency histogram.
	calls := func() int64 {
		byOp, _ := keyStoreCalls.Get("vault").(*expvar.Map)
		if byOp == nil {
			return 0
		}
		byClass, _ := byOp.Get("unwrap").(*expvar.Map)
		if byClass == nil {
			return 0
		}
		return scaleobs.IntValue(byClass.Get("throttled"))
	}
	n := calls()
	lat := keyStoreCallSeconds.Value("vault_unwrap", "le_5ms")
	recordKeyStoreCall("vault", "unwrap", "throttled", 3*time.Millisecond)
	recordKeyStoreCall("vault", "unwrap", "throttled", 3*time.Millisecond)
	if calls() != n+2 || keyStoreCallSeconds.Value("vault_unwrap", "le_5ms") != lat+2 {
		t.Fatalf("key-store calls = %d (was %d)", calls(), n)
	}
	if KeyStoreOptions(config.Config{}, "n", nil).Calls == nil {
		t.Fatal("KeyStoreOptions does not report calls")
	}
}

// pkg/daemon hands in the running PKCS#11 helper; a pkcs11 node seals with it
// and runs the boot canary through it.
func TestConfigureSecretProviderPKCS11(t *testing.T) {
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
	svc := New(config.Config{SecretProvider: "pkcs11", SecretProviderStrictBoot: true}, logger, st, nil, nil, nil, cipher, nil, nil)
	if err := svc.ConfigureSecretProvider(context.Background()); err == nil || !strings.Contains(err.Error(), "helper is not running") {
		t.Fatalf("pkcs11 with no helper = %v", err)
	}
	helper := p11Stub{}
	svc.SetPKCS11Helper(helper)
	if err := svc.ConfigureSecretProvider(context.Background()); err != nil {
		t.Fatalf("pkcs11 with a helper = %v", err)
	}
	if secretProviderCanaryOK.Value() != 1 {
		t.Fatal("canary did not run through the helper")
	}
	(*Service)(nil).SetPKCS11Helper(helper)
}

// p11Stub tags its output like the PKCS#11 helper, so the router sends rows
// back to it.
type p11Stub struct{}

func (p11Stub) Wrap(_ context.Context, dek []byte, _ map[string]string) ([]byte, error) {
	return append([]byte("p11:1:"), dek...), nil
}

func (p11Stub) Unwrap(_ context.Context, w []byte, _ map[string]string) ([]byte, error) {
	return []byte(strings.TrimPrefix(string(w), "p11:1:")), nil
}
