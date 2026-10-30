package daemon

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/aerol-ai/microvm/internal/config"
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

// wirePKCS11Helper starts `sandboxd --pkcs11-helper` when the node has
// PKCS#11 settings and hands it to the service, so the vendor library never
// loads into the daemon (plans/customer-key-custody.md §2, eng D5). It
// returns the stop function, a no-op when nothing was started.
func wirePKCS11Helper(cfg config.Config, logger *slog.Logger, svc interface{ SetPKCS11Helper(secrets.DataKeyWrapper) }) (func(), error) {
	if cfg.SecretProvider != secrets.ProviderPKCS11 && !cfg.PKCS11Configured() {
		return func() {}, nil
	}
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
		return nil, fmt.Errorf("start pkcs11 helper: %w", err)
	}
	stop := func() { _ = h.Close() }
	if err != nil {
		// The boot canary's rule: strict boot refuses; otherwise warn and let
		// the supervisor keep trying while calls report unavailable.
		if cfg.SecretProviderStrictBoot {
			stop()
			return nil, fmt.Errorf("start pkcs11 helper (SB_SECRET_PROVIDER_STRICT_BOOT=true): %w", err)
		}
		logger.Warn("pkcs11 helper did not start; retrying in the background (set SB_SECRET_PROVIDER_STRICT_BOOT=true to fail closed)", "err", err)
	} else if info := h.Info(); !info.HardwareSlot {
		// A software token (SoftHSM2) holds the key in a file on this host,
		// so the HSM custody claim would be false (§2).
		if cfg.EnterpriseMode {
			stop()
			return nil, fmt.Errorf("pkcs11 token %q is not a hardware slot (CKF_HW_SLOT); SB_ENTERPRISE_MODE=true needs an HSM", info.TokenLabel)
		}
		logger.Warn("pkcs11 token is a software token, not an HSM; the key sits in a file on this host",
			"token", info.TokenLabel, "manufacturer", info.Manufacturer, "model", info.Model)
	}
	svc.SetPKCS11Helper(h)
	return stop, nil
}
