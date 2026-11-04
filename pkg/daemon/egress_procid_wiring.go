package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/procid"
	"github.com/aerol-ai/microvm/internal/service"
)

// lookupGatewayUser resolves the gateway's system user (a seam for tests).
var lookupGatewayUser = user.Lookup

// startEgressProcid serves the gateway's executable lookups for per-binary
// rules (P3-3). The gateway runs as an unprivileged user and can't read a
// sandbox's /proc itself; sandboxd can (review finding 16). The socket is
// group-owned by the gateway's user and answers only that uid (SO_PEERCRED),
// and each answer is held to the named sandbox's own process and rule paths
// (Service.EgressProcidAuthorize). Without the user or the socket, the
// rules' flows are refused (binary_unknown), never admitted.
func startEgressProcid(ctx context.Context, cfg config.Config, svc *service.Service, logger *slog.Logger) error {
	if cfg.EgressProcidSocket == "" {
		return nil
	}
	u, err := lookupGatewayUser(cfg.EgressGatewayUser)
	if err != nil {
		return fmt.Errorf("egress gateway user %q: %w", cfg.EgressGatewayUser, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("egress gateway user %q: uid %q: %w", cfg.EgressGatewayUser, u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("egress gateway user %q: gid %q: %w", cfg.EgressGatewayUser, u.Gid, err)
	}
	path := cfg.EgressProcidSocket
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	_ = os.Remove(path) // a socket left by a previous run
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chown(path, os.Geteuid(), gid); err != nil {
		_ = ln.Close()
		return fmt.Errorf("egress procid socket: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return fmt.Errorf("egress procid socket: %w", err)
	}
	srv := &procid.Server{
		Peer: egress.UnixPeerCheck([]uint32{uint32(uid)}, ""),
		Authorize: func(id string) (int, []string, error) {
			return svc.EgressProcidAuthorize(ctx, id)
		},
	}
	go func() {
		if err := srv.Serve(ln); err != nil {
			logger.Warn("egress: executable lookups stopped; per-binary flows are refused", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	return nil
}
