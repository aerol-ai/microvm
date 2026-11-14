package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
)

// wireCloudIdentity makes this node an OIDC issuer for sandbox cloud
// identities (plans/sandbox-cloud-identity.md) when SB_IDENTITY_ISSUER_URL
// is set: every node makes sure a signing key exists (the first one to get
// there makes it), and every node that owns sandboxes runs the owner-local
// token refresher. Unset, nothing starts.
func wireCloudIdentity(ctx context.Context, cfg config.Config, svc *service.Service, logger *slog.Logger) {
	if cfg.IdentityIssuerURL == "" {
		return
	}
	go bootstrapCloudIdentity(ctx, svc, logger, cloudIdentityBootRetry)
	if cfg.IsWorker() {
		go svc.SuperviseIdentityTokens(ctx)
	}
}

// cloudIdentityBootRetry is the first wait between boot attempts; it
// doubles. A var so tests do not sleep.
var cloudIdentityBootRetry = time.Second

// cloudIdentityBootAttempts covers a normal cluster start (a leader within
// about a minute). Past it the latch stays unset and the first JWKS fetch or
// token retries (CLAUDE.md rule 3): a boot never fails on it.
const cloudIdentityBootAttempts = 6

type identityKeyBootstrapper interface {
	EnsureIdentityKeysReady(ctx context.Context) error
}

func bootstrapCloudIdentity(ctx context.Context, svc identityKeyBootstrapper, logger *slog.Logger, delay time.Duration) bool {
	for attempt := 1; ; attempt++ {
		err := svc.EnsureIdentityKeysReady(ctx)
		if err == nil {
			logger.Info("identity: issuer signing keys ready")
			return true
		}
		if attempt >= cloudIdentityBootAttempts {
			logger.Warn("identity: issuer signing keys not ready at boot; the first JWKS fetch or token retries", "error", err)
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(delay):
		}
		delay *= 2
	}
}
