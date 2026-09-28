package service

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

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
