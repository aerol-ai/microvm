//go:build e2e

// Test-only exports used by the cross-package e2e ACME test
// (custom_domains_e2e_test.go lives in package service_test to break the
// import cycle with pkg/api/ingressproxy). Everything here is gated by the
// e2e build tag and never reaches production builds.
package service

import (
	"log/slog"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
)

// NewForE2ETest builds a minimal Service with just the surface the ACME e2e
// test needs: store + caddy client + cfg. Bypasses service.New (no runtime,
// admitter, cipher, mounts, events, image distribution). The custom-domain
// path is the only path exercised through this; calling lifecycle methods on
// the resulting Service will panic.
func NewForE2ETest(cfg config.Config, logger *slog.Logger, st *store.Store, caddyClient *caddy.Client) *Service {
	return &Service{
		cfg:    cfg,
		logger: logger,
		store:  st,
		caddy:  caddyClient,
	}
}

// SetCaddyClientForE2ETest re-points the Caddy client mid-test, used by the
// failover phase that stops the original Caddy container and brings up a
// fresh one against the same shared-storage S3 bucket.
func (s *Service) SetCaddyClientForE2ETest(c *caddy.Client) {
	s.caddy = c
}

// CfgForE2ETest exposes a read-only copy of cfg so the e2e test can pull
// TLSOnDemandBurst / TLSOnDemandInterval back out without duplicating the
// values it just installed.
func (s *Service) CfgForE2ETest() config.Config {
	return s.cfg
}
