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
	"strings"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/procid"
	"github.com/aerol-ai/microvm/internal/service"
)

// lookupGatewayUser resolves the gateway's system user (a seam for tests).
var lookupGatewayUser = user.Lookup

// gatewayIDs resolves SB_EGRESS_GATEWAY_USER to the gateway's uid and gid.
// A name is looked up in this machine's user database, where install.sh
// creates it for the systemd unit. A gateway in its own container (a
// Kubernetes pod, C6) runs as a user this container's /etc/passwd does not
// name, so the setting may be the numbers instead: "uid" (the gid is the
// same) or "uid:gid".
func gatewayIDs(name string) (uint32, int, error) {
	uidText, gidText, pair := strings.Cut(name, ":")
	if _, err := strconv.ParseUint(uidText, 10, 32); err == nil || pair {
		uid, err := strconv.ParseUint(uidText, 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("uid %q is not a number", uidText)
		}
		if !pair {
			gidText = uidText
		}
		// Signed 32-bit, so the gid fits int on the 32-bit builds too.
		gid, err := strconv.ParseInt(gidText, 10, 32)
		if err != nil || gid < 0 {
			return 0, 0, fmt.Errorf("gid %q is not a number from 0 to 2147483647", gidText)
		}
		return uint32(uid), int(gid), nil
	}
	u, err := lookupGatewayUser(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("gid %q: %w", u.Gid, err)
	}
	return uint32(uid), gid, nil
}

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
	uid, gid, err := gatewayIDs(cfg.EgressGatewayUser)
	if err != nil {
		return fmt.Errorf("egress gateway user %q: %w", cfg.EgressGatewayUser, err)
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
		Peer: egress.UnixPeerCheck([]uint32{uid}, ""),
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
