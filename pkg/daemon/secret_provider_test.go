package daemon

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestSecretProviderConfigureLocal(t *testing.T) {
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
	svc := service.New(config.Config{SecretProvider: secrets.ProviderLocal}, logger, st, nil, nil, nil, cipher, nil, nil)
	if err := svc.ConfigureSecretProvider(context.Background()); err != nil {
		t.Fatalf("ConfigureSecretProvider: %v", err)
	}
}
