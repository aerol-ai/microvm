package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/aerol-ai/microvm/pkg/secrets/pkcs11"
)

type fakePKCS11Helper struct {
	info   pkcs11.Info
	closed bool
}

func (f *fakePKCS11Helper) Wrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, nil
}
func (f *fakePKCS11Helper) Unwrap(context.Context, []byte, map[string]string) ([]byte, error) {
	return nil, nil
}
func (f *fakePKCS11Helper) Info() pkcs11.Info { return f.info }
func (f *fakePKCS11Helper) Close() error      { f.closed = true; return nil }

func TestStartKeyStorePKCS11(t *testing.T) {
	pkcs11Cfg := config.Config{
		SecretProvider: "pkcs11", SecretPKCS11Module: "/m.so", SecretPKCS11TokenLabel: "tok",
		SecretPKCS11PINFile: "/pin", SecretPKCS11KeyLabel: "k", SecretPKCS11DecryptLabels: []string{"j"},
		SecretPKCS11GCMIV: "auto", SecretPKCS11RunDir: "/run/x", SecretProviderMaxInFlight: 8,
	}
	cases := []struct {
		name       string
		cfg        func(config.Config) config.Config
		helper     *fakePKCS11Helper
		startErr   error
		wantErr    string
		wantClosed bool
		wantLog    string
	}{
		{name: "hardware token", helper: &fakePKCS11Helper{info: pkcs11.Info{HardwareSlot: true}}},
		{name: "software token warns", helper: &fakePKCS11Helper{info: pkcs11.Info{TokenLabel: "soft"}}, wantLog: "software token"},
		{name: "software token in enterprise mode", cfg: func(c config.Config) config.Config { c.EnterpriseMode = true; return c },
			helper: &fakePKCS11Helper{info: pkcs11.Info{TokenLabel: "soft"}}, wantErr: "not a hardware slot", wantClosed: true},
		{name: "first start fails, lenient", helper: &fakePKCS11Helper{}, startErr: secrets.ErrProviderUnavailable, wantLog: "retrying in the background"},
		{name: "first start fails, strict", cfg: func(c config.Config) config.Config { c.SecretProviderStrictBoot = true; return c },
			helper: &fakePKCS11Helper{}, startErr: secrets.ErrProviderUnavailable, wantErr: "STRICT_BOOT", wantClosed: true},
		{name: "cannot start at all", startErr: errors.New("no socket dir"), wantErr: "no socket dir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := pkcs11Cfg
			if tc.cfg != nil {
				cfg = tc.cfg(cfg)
			}
			var got pkcs11.HelperOptions
			orig := startPKCS11
			startPKCS11 = func(o pkcs11.HelperOptions) (pkcs11Helper, error) {
				got = o
				if tc.helper == nil {
					return nil, tc.startErr
				}
				return tc.helper, tc.startErr
			}
			t.Cleanup(func() { startPKCS11 = orig })
			var logs bytes.Buffer
			ks, err := startKeyStore(context.Background(), cfg, slog.New(slog.NewTextHandler(&logs, nil)))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if ks.helper == nil || ks.wrapper == nil {
					t.Fatalf("key store = %+v, want the helper and a client built on it", ks)
				}
			}
			if tc.helper != nil && tc.helper.closed != tc.wantClosed {
				t.Fatalf("closed = %v, want %v", tc.helper.closed, tc.wantClosed)
			}
			if tc.wantLog != "" && !strings.Contains(logs.String(), tc.wantLog) {
				t.Fatalf("log = %q, want %q", logs.String(), tc.wantLog)
			}
			if got.Socket != "/run/x/helper.sock" || got.Token.Sessions != 8+secrets.BackgroundSlots() || got.Token.KeyLabel != "k" || got.Token.DecryptLabels[0] != "j" {
				t.Fatalf("helper options = %+v", got)
			}
			if err == nil {
				ks.stop()
				if !tc.helper.closed {
					t.Fatal("stop did not close the helper")
				}
			}
		})
	}
}

func TestStartKeyStoreWithoutPKCS11(t *testing.T) {
	ks, err := startKeyStore(context.Background(), config.Config{SecretProvider: "local"}, slog.Default())
	if err != nil || ks.wrapper != nil || ks.helper != nil {
		t.Fatalf("local = %+v %v", ks, err)
	}
	ks.stop()
	// A provider whose client cannot be built stops the boot.
	if _, err := startKeyStore(context.Background(), config.Config{SecretProvider: "vault"}, slog.Default()); err == nil {
		t.Fatal("vault with no settings started")
	}
}

// §3 boot: wrapped custody generates on a fresh single node, then reopens
// the same key; a plaintext key left behind stops the boot (F1).
func TestOpenServerKey(t *testing.T) {
	ctx := context.Background()
	fake, err := secrets.NewFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := config.Config{
		SecretProvider: "awskms", SecretAWSkmsKeyID: "alias/k", CredentialKeyCustody: "wrapped",
		CredentialEncryptionKeyPath: filepath.Join(dir, "credential_encryption.key"),
		CredentialKeyWrappedPath:    filepath.Join(dir, "credential_encryption.key.wrapped"),
		DBPath:                      filepath.Join(dir, "state.db"),
	}
	c1, err := openServerKey(ctx, cfg, fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := c1.Encrypt([]byte("x"))
	f, err := secrets.ReadWrappedKeyFile(cfg.CredentialKeyWrappedPath)
	if err != nil || f.Provider != "awskms" || f.KeyRef != "alias/k" {
		t.Fatalf("wrapped file = %+v %v", f, err)
	}
	if err := os.WriteFile(cfg.DBPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c2, err := openServerKey(ctx, cfg, fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c2.Decrypt(sealed); err != nil || string(got) != "x" {
		t.Fatalf("reopen = %q %v", got, err)
	}
	if err := os.WriteFile(cfg.CredentialEncryptionKeyPath, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openServerKey(ctx, cfg, fake, nil); err == nil || !strings.Contains(err.Error(), "plaintext key file exists") {
		t.Fatalf("plaintext left behind = %v", err)
	}
	if bootNodeID(config.Config{NodeID: " n1 "}) != "n1" || bootNodeID(config.Config{}) != "standalone" {
		t.Fatal("bootNodeID")
	}
}

// §13 boot: custody=file opens its ring file and warns while the retired
// key 0 still sits in the key file.
func TestOpenServerKeyRingFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := config.Config{
		SecretProvider: "local", CredentialKeyCustody: "file",
		CredentialEncryptionKeyPath: filepath.Join(dir, "credential_encryption.key"),
		DBPath:                      filepath.Join(dir, "state.db"),
	}
	k0, _ := secrets.NewServerKey()
	if err := os.WriteFile(cfg.CredentialEncryptionKeyPath, []byte(base64.StdEncoding.EncodeToString(k0)), 0o600); err != nil {
		t.Fatal(err)
	}
	staged, _ := secrets.NewRingEntry(ctx, 1, nil)
	ring, _ := secrets.StageRingKey([]secrets.RingEntry{secrets.LegacyRingEntry(k0)}, staged)
	ring, _, _, _ = secrets.PromoteRingKey(ring)
	ring, _ = secrets.RetireRingKey(ring, 0)
	if err := secrets.WriteKeyRingFile(cfg.KeyRingPath(), secrets.KeyRingFile{Ring: ring}); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	c, err := openServerKey(ctx, cfg, nil, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil || c.CurrentKeyID() != 1 || len(c.KeyIDs()) != 1 {
		t.Fatalf("ring boot = %v", err)
	}
	if !strings.Contains(logs.String(), "key 0 is retired but the plaintext key is still") {
		t.Fatalf("no leftover-key warning: %s", logs.String())
	}
}
