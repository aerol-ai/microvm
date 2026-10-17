package daemon

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/api"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// identityRecorder is the service's identity_config writer
// (Service.RecordIdentityConfig); an interface so the wiring test can watch
// what it is handed.
type identityRecorder interface {
	RecordIdentityConfig(identity.Summary) bool
}

// wireIdentityFile loads the identity file (SB_IDENTITY_FILE,
// plans/identity-and-access.md §5.5) and returns the API options that put
// the OIDC verifier in the authenticator chain and its issuers in the
// sign-in discovery document. Identity off, or on without a file (tokens-
// only mode), wires nothing: no watcher, no fetches, no OIDC.
//
// Nothing here blocks boot. A missing or invalid file at boot leaves OIDC
// at 503 until the poll or a SIGHUP loads a good one; an unreachable
// provider leaves its tokens at 503 until a key fetch succeeds. The PAT and
// avm_ tokens work throughout, since neither reads the file or the network.
func wireIdentityFile(ctx context.Context, cfg config.Config, rec identityRecorder, logger *slog.Logger) []api.ServerOption {
	if !cfg.IdentityEnabled || cfg.IdentityFile == "" {
		return nil
	}
	w := identity.NewWatcher(cfg.IdentityFile, logger)
	if err := w.BootError(); err != nil {
		logger.Error("identity file invalid; sign-in through an identity provider gets 503 until it is fixed (the operator token and API tokens still work)",
			"path", cfg.IdentityFile, "error", err)
	}
	v := identity.NewVerifier(w.Current, identity.VerifierOptions{Logger: logger})
	go w.Run(ctx, identity.FilePollInterval)
	go reloadIdentityOnSIGHUP(ctx, w, logger)
	// Keys at start, through the lazy-bootstrap latch: off the boot path,
	// and a request that arrives first joins the same fetch.
	go v.Bootstrap(ctx)
	go v.Run(ctx, 0)
	go identity.RecordChanges(ctx, w, rec.RecordIdentityConfig, identity.FilePollInterval)
	return []api.ServerOption{
		api.WithCredentialAuthenticator(controlplane.PrincipalOIDC, v),
		api.WithAuthDiscovery(func() []identitywire.DiscoveryIssuer {
			if c := w.Current(); c != nil {
				return c.DiscoveryIssuers()
			}
			return nil
		}),
	}
}

// reloadIdentityOnSIGHUP reloads the identity file on SIGHUP, so an
// emergency deny_subjects entry applies at once instead of within a poll.
// signal.Notify fans SIGHUP out to every channel registered for it, so this
// and the egress operator file's reload both run.
func reloadIdentityOnSIGHUP(ctx context.Context, w *identity.Watcher, logger *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			if err := w.Reload(); err != nil {
				logger.Warn("identity file reload failed; keeping the last good file", "error", err)
			}
		}
	}
}
