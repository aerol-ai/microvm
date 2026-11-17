package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// The public API socket (plans/identity-and-access.md §5.11, CEO review D4).
// Under SB_PAT_SCOPE=host the operator token is accepted from a loopback peer
// on the API listener, and Caddy connects from loopback too, so Caddy moves
// to this socket: every request on it is public, whatever the caller holds.
//
//	/run/sandboxd-public            root:caddy 0750  (/run/sandboxd is 0700)
//	/run/sandboxd-public/api.sock   root:caddy 0660
//
// Boot fails loudly when the socket cannot be made with exactly these
// owners and modes (§11): a socket Caddy cannot reach is a 502 for the whole
// public API, and one any local user can reach is a way around Caddy.

// lookupPublicAPISocketGroup resolves the group (a seam for tests).
var lookupPublicAPISocketGroup = user.LookupGroup

const (
	publicAPISocketDirMode fs.FileMode = 0o750
	publicAPISocketMode    fs.FileMode = 0o660
)

// listenPublicAPISocket makes the socket directory and the socket with
// their owners and modes, replacing a socket a previous run left behind.
// groupName is Caddy's group (SB_PUBLIC_API_SOCKET_GROUP): a name, or a gid.
func listenPublicAPISocket(path, groupName string) (net.Listener, error) {
	gid, err := publicAPISocketGID(groupName)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, publicAPISocketDirMode); err != nil {
		return nil, fmt.Errorf("public API socket: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("public API socket: %w", err)
	}
	if !info.IsDir() {
		// A symlink here could point the chown and chmod below anywhere.
		return nil, fmt.Errorf("public API socket: %s is not a directory", dir)
	}
	// MkdirAll leaves an existing directory as it was, and the umask trims
	// a new one: set both explicitly, every boot.
	if err := os.Chown(dir, os.Geteuid(), gid); err != nil {
		return nil, fmt.Errorf("public API socket: chown %s: %w", dir, err)
	}
	if err := os.Chmod(dir, publicAPISocketDirMode); err != nil {
		return nil, fmt.Errorf("public API socket: chmod %s: %w", dir, err)
	}
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("public API socket: %w", err)
	}
	if err := os.Chown(path, os.Geteuid(), gid); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("public API socket: chown %s: %w", path, err)
	}
	if err := os.Chmod(path, publicAPISocketMode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("public API socket: chmod %s: %w", path, err)
	}
	return ln, nil
}

// publicAPISocketGID is groupName's gid. A number is taken as it is: a
// Kubernetes pod's edge runs as a bare uid and gid that the image's
// /etc/group never names, so a lookup there could only fail.
func publicAPISocketGID(groupName string) (int, error) {
	if gid, err := strconv.Atoi(groupName); err == nil {
		if gid < 0 {
			return 0, fmt.Errorf("public API socket: group %q (Caddy's): a gid is not negative", groupName)
		}
		return gid, nil
	}
	group, err := lookupPublicAPISocketGroup(groupName)
	if err != nil {
		return 0, fmt.Errorf("public API socket: group %q (Caddy's): %w", groupName, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return 0, fmt.Errorf("public API socket: group %q: gid %q: %w", groupName, group.Gid, err)
	}
	return gid, nil
}

// removeStaleSocket removes a socket a previous run left at path. Anything
// else there is refused, never deleted: the path came from configuration.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("public API socket: %w", err)
	}
	if info.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("public API socket: %s exists and is not a socket", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("public API socket: remove stale %s: %w", path, err)
	}
	return nil
}

// logPATBootSettings logs the settings an operator needs during a PAT
// rotation or a PROXY-protocol mismatch (§5.11, §11): the effective operator
// volume scope (rotation step 0 pins it), and whether the caddy-l4 fallback
// sends PROXY v2, which needs the 8443 site's listener wrapper.
func logPATBootSettings(logger *slog.Logger, cfg config.Config) {
	if cfg.PATScopeHostOnly() {
		logger.Info("operator token confined to this host and cluster peers (SB_PAT_SCOPE=host); Caddy must proxy to the public socket",
			"public_socket", cfg.PublicAPISocket, "group", cfg.PublicAPISocketGroup)
	}
	if cfg.PATTokenPrevious != "" {
		logger.Info("previous operator token accepted during a rotation (SB_PAT_TOKEN_PREVIOUS); remove it once every node runs the new one")
	}
	if cfg.PATIsNodeLocal() {
		logger.Info("this node holds the operator token's hash, not the token (SB_PAT_TOKEN_SHA256): it checks the operator token by hash, calls peers with its node cert alone, and its own SB_PAT_TOKEN works only for local tools on its loopback",
			"hashes", len(cfg.PATTokenSHA256))
	}
	if cfg.L4FallbackProxyProtocol {
		logger.Info("caddy-l4 fallback sends PROXY protocol v2 to the HTTPS site (SB_L4_FALLBACK_PROXY_PROTOCOL=true); the site needs the proxy_protocol listener wrapper install.sh writes, or every public HTTPS handshake fails",
			"fallback", cfg.L4TLSFallback)
	}
	if cfg.PlatformVolumes.Enabled {
		scope, err := volumes.OperatorScope(cfg.OperatorVolumeScope, cfg.PATToken)
		if err != nil {
			logger.Warn("operator volume scope unresolved", "error", err)
			return
		}
		logger.Info("operator volume scope", "scope", scope, "pinned", cfg.OperatorVolumeScope != "",
			"hint", "pin it with SB_OPERATOR_VOLUME_SCOPE before rotating SB_PAT_TOKEN, or operator volumes move")
	}
}

// newPublicAPIServer serves handler on the public socket with the API
// listener's timeouts and protocols.
func newPublicAPIServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		Protocols:         apiListenerProtocols(),
	}
}
