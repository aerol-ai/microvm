package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/aerol-ai/microvm/pkg/secrets/pkcs11"
)

// pkcs11Helper is the running helper as the daemon uses it.
type pkcs11Helper interface {
	secrets.DataKeyWrapper
	Info() pkcs11.Info
	Close() error
}

// startPKCS11 starts the helper; tests replace it.
var startPKCS11 = func(o pkcs11.HelperOptions) (pkcs11Helper, error) {
	h, err := pkcs11.StartHelper(o)
	if h == nil {
		return nil, err
	}
	return h, err
}

// keyStore is the node's one key-store client, built before the server key
// is opened (plans/customer-key-custody.md §3 boot step 1), and the PKCS#11
// helper that hosts the vendor library when there is one.
type keyStore struct {
	helper  pkcs11Helper
	wrapper secrets.DataKeyWrapper
	stop    func()
}

// handTo gives the service the same client the server key was opened with.
func (ks keyStore) handTo(svc *service.Service) {
	if ks.helper != nil {
		svc.SetPKCS11Helper(ks.helper)
	}
	svc.SetKeyStoreWrapper(ks.wrapper)
}

// custodyFacts is what the custody report needs from the running token. A
// helper that never started reports no token, not a software one.
func (ks keyStore) custodyFacts() service.CustodyFacts {
	if ks.helper == nil {
		return service.CustodyFacts{}
	}
	info := ks.helper.Info()
	return service.CustodyFacts{SoftwareToken: info.TokenLabel != "" && !info.HardwareSlot}
}

// bootNodeID names this node in boot-time key-store calls; the cluster id
// is not known yet.
func bootNodeID(cfg config.Config) string {
	if id := strings.TrimSpace(cfg.NodeID); id != "" {
		return id
	}
	return "standalone"
}

// startKeyStore starts the PKCS#11 helper when the node has PKCS#11
// settings, then builds the key-store client for an external provider. The
// stop function closes the helper; it is a no-op when nothing was started.
func startKeyStore(ctx context.Context, cfg config.Config, logger *slog.Logger) (keyStore, error) {
	ks := keyStore{stop: func() {}}
	if cfg.SecretProvider == secrets.ProviderPKCS11 || cfg.PKCS11Configured() {
		h, stop, err := startPKCS11Helper(cfg, logger)
		if err != nil {
			return keyStore{}, err
		}
		ks.helper, ks.stop = h, stop
	}
	if !secrets.IsExternalProvider(cfg.SecretProvider) {
		return ks, nil
	}
	var helper secrets.DataKeyWrapper
	if ks.helper != nil {
		helper = ks.helper
	}
	w, err := secrets.NewWrapper(secrets.ContextWithBackgroundPurpose(ctx, "boot"), service.KeyStoreOptions(cfg, bootNodeID(cfg), helper))
	if err != nil {
		ks.stop()
		return keyStore{}, err
	}
	ks.wrapper = w
	return ks, nil
}

// startPKCS11Helper starts `sandboxd --pkcs11-helper`, so the vendor library
// never loads into the daemon (§2, eng D5).
func startPKCS11Helper(cfg config.Config, logger *slog.Logger) (pkcs11Helper, func(), error) {
	h, err := startPKCS11(pkcs11.HelperOptions{
		Socket: filepath.Join(cfg.SecretPKCS11RunDir, "helper.sock"),
		Token: pkcs11.TokenConfig{
			Module:        cfg.SecretPKCS11Module,
			TokenLabel:    cfg.SecretPKCS11TokenLabel,
			PINFile:       cfg.SecretPKCS11PINFile,
			KeyLabel:      cfg.SecretPKCS11KeyLabel,
			DecryptLabels: cfg.SecretPKCS11DecryptLabels,
			IVMode:        cfg.SecretPKCS11GCMIV,
			// The session pool matches the limiter: foreground cap plus the
			// background slots (eng D13).
			Sessions: cfg.SecretProviderMaxInFlight + secrets.BackgroundSlots(),
		},
	})
	if h == nil {
		return nil, nil, fmt.Errorf("start pkcs11 helper: %w", err)
	}
	stop := func() { _ = h.Close() }
	if err != nil {
		// The boot canary's rule: strict boot refuses; otherwise warn and let
		// the supervisor keep trying while calls report unavailable. With
		// wrapped custody the server-key unwrap then fails the boot anyway.
		if cfg.SecretProviderStrictBoot {
			stop()
			return nil, nil, fmt.Errorf("start pkcs11 helper (SB_SECRET_PROVIDER_STRICT_BOOT=true): %w", err)
		}
		logger.Warn("pkcs11 helper did not start; retrying in the background (set SB_SECRET_PROVIDER_STRICT_BOOT=true to fail closed)", "err", err)
	} else if info := h.Info(); !info.HardwareSlot {
		// A software token (SoftHSM2) holds the key in a file on this host,
		// so the HSM custody claim would be false (§2).
		if cfg.EnterpriseMode {
			stop()
			return nil, nil, fmt.Errorf("pkcs11 token %q is not a hardware slot (CKF_HW_SLOT); SB_ENTERPRISE_MODE=true needs an HSM", info.TokenLabel)
		}
		logger.Warn("pkcs11 token is a software token, not an HSM; the key sits in a file on this host",
			"token", info.TokenLabel, "manufacturer", info.Manufacturer, "model", info.Model)
	}
	return h, stop, nil
}

// enterpriseCustodyWarning is the first-release half of F2 (§7): an
// enterprise node with a customer key store whose server key is still a
// plaintext file. The next release refuses it (Phase 7).
func enterpriseCustodyWarning(cfg config.Config) string {
	if !cfg.EnterpriseMode || !secrets.IsExternalProvider(cfg.SecretProvider) || cfg.CredentialKeyCustody == secrets.CustodyWrapped {
		return ""
	}
	return "SB_ENTERPRISE_MODE=true with SB_SECRET_PROVIDER=" + secrets.NormalizeProviderName(cfg.SecretProvider) +
		" but the server key is a plaintext file (SB_CREDENTIAL_KEY_CUSTODY=file); the key custody claim does not hold. Run `sandboxd key wrap` and set SB_CREDENTIAL_KEY_CUSTODY=wrapped; the next release refuses this combination"
}

// openServerKey opens the server key per §3's boot decision: today's
// plaintext key (or custody=file's ring, once rotated) with custody "file",
// the wrapped file's ring through the key store with custody "wrapped"
// (generated on a fresh single node).
func openServerKey(ctx context.Context, cfg config.Config, w secrets.DataKeyWrapper, logger *slog.Logger) (*secrets.Cipher, error) {
	exists := func(path string) bool {
		if path == "" {
			return false
		}
		_, err := os.Stat(path)
		return err == nil
	}
	in := secrets.CustodyInputs{
		Custody:             cfg.CredentialKeyCustody,
		PlaintextEnvSet:     cfg.CredentialEncryptionKey != "",
		PlaintextFileExists: exists(cfg.CredentialEncryptionKeyPath),
		WrappedFileExists:   exists(cfg.CredentialKeyWrappedPath),
		ClusterMode:         cfg.EnableCluster,
		StateDBExists:       exists(cfg.DBPath),
		PlaintextPath:       cfg.CredentialEncryptionKeyPath,
		WrappedPath:         cfg.CredentialKeyWrappedPath,
		RingFileExists:      exists(cfg.KeyRingPath()),
		RingPath:            cfg.KeyRingPath(),
	}
	c, err := secrets.OpenServerKey(secrets.ContextWithBackgroundPurpose(ctx, "boot"), in, cfg.CredentialEncryptionKey, w,
		secrets.NormalizeProviderName(cfg.SecretProvider), service.KeyStoreRef(cfg))
	if msg := enterpriseCustodyWarning(cfg); err == nil && logger != nil && msg != "" {
		logger.Warn(msg)
	}
	if err == nil && logger != nil && secrets.RetiredKeyStillPresent(in, cfg.CredentialEncryptionKey) {
		logger.Warn("server-key ring: key 0 is retired but the plaintext key is still in SB_CREDENTIAL_ENCRYPTION_KEY or the key file; remove it so a copy of it opens nothing current",
			"key_file", cfg.CredentialEncryptionKeyPath)
	}
	return c, err
}
