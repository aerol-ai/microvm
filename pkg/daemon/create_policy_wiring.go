package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/createpolicy"
	"github.com/aerol-ai/microvm/internal/service"
)

// createPolicyPoll is how often a changed create policy file is noticed
// without a SIGHUP, the same as the egress operator file.
const createPolicyPoll = 10 * time.Second

// wireCreatePolicy loads the operator's create policy (SB_CREATE_POLICY_FILE)
// and keeps it current. Unset is a no-op. A file that is set but missing or
// invalid at boot refuses creates and resizes with 503 until it is fixed (the
// poll or a SIGHUP picks up the fix); an invalid reload keeps the last good
// file. Reloads change what later creates may do, never a running sandbox.
func wireCreatePolicy(ctx context.Context, cfg config.Config, svc *service.Service, logger *slog.Logger) {
	if cfg.CreatePolicyFile == "" {
		return
	}
	w := createpolicy.NewWatcher(cfg.CreatePolicyFile, logger)
	if err := w.BootError(); err != nil {
		logger.Error("create policy file invalid; every create and resize is refused with 503 until it is fixed", "path", cfg.CreatePolicyFile, "error", err)
	}
	svc.SetCreatePolicy(w)
	go w.Run(ctx, createPolicyPoll)
	go reloadOnSIGHUP(ctx, w, "create policy file", logger)
}
