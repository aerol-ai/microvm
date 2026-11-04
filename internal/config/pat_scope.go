package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aerol-ai/microvm/pkg/volumes"
)

// Where the operator token (PAT) is accepted, and the settings that come
// with it (plans/identity-and-access.md §5.11, §10). Every default is
// today's behavior (L8): the PAT works from anywhere, no second listener,
// no PROXY protocol on Caddy's internal hop.
const (
	// PATScopeAny accepts the PAT from any peer, as every release before
	// this one did. The default.
	PATScopeAny = "any"
	// PATScopeHost accepts the PAT only from a loopback TCP peer on the API
	// listener and from mTLS cluster peers, so people outside the host must
	// use SSO or a named token (CEO review D4). Enterprise mode requires it
	// (D5; checked at daemon boot, where the control-plane provider is known).
	PATScopeHost = "host"

	// DefaultPublicAPISocket is Caddy's upstream under PATScopeHost. Its
	// directory is root:caddy 0750: /run/sandboxd is 0700, so Caddy could
	// not reach a socket inside it.
	DefaultPublicAPISocket = "/run/sandboxd-public/api.sock"
)

// loadPATScopeConfig reads and checks the PAT-scope settings: the scope, the
// public socket Caddy uses under host scope, the previous PAT accepted
// during a rotation, the pinned operator volume scope, and the PROXY
// protocol flag of the caddy-l4 fallback route.
func (cfg *Config) loadPATScopeConfig() error {
	cfg.PATScope = strings.ToLower(strings.TrimSpace(getEnv("SB_PAT_SCOPE", PATScopeAny)))
	switch cfg.PATScope {
	case PATScopeAny, PATScopeHost:
	default:
		return fmt.Errorf("SB_PAT_SCOPE must be %q or %q, got %q", PATScopeAny, PATScopeHost, cfg.PATScope)
	}
	cfg.PublicAPISocket = strings.TrimSpace(getEnv("SB_PUBLIC_API_SOCKET", DefaultPublicAPISocket))
	if cfg.PATScope == PATScopeHost && !filepath.IsAbs(cfg.PublicAPISocket) {
		return fmt.Errorf("SB_PUBLIC_API_SOCKET must be an absolute path when SB_PAT_SCOPE=host, got %q", cfg.PublicAPISocket)
	}

	cfg.PATTokenPrevious = strings.TrimSpace(os.Getenv("SB_PAT_TOKEN_PREVIOUS"))

	cfg.OperatorVolumeScope = strings.TrimSpace(os.Getenv("SB_OPERATOR_VOLUME_SCOPE"))
	if cfg.OperatorVolumeScope != "" {
		if err := volumes.ValidateOperatorScope(cfg.OperatorVolumeScope); err != nil {
			return fmt.Errorf("SB_OPERATOR_VOLUME_SCOPE: %w", err)
		}
	} else if cfg.PATTokenPrevious != "" && cfg.PlatformVolumes.Enabled {
		// A rotation without a pinned scope moves every operator volume to
		// an empty path under the new PAT's hash: refuse it and name the
		// value that keeps them where they are (rotation step 0).
		old, _ := volumes.OperatorScope("", cfg.PATTokenPrevious)
		return fmt.Errorf("SB_PAT_TOKEN_PREVIOUS is set while SB_OPERATOR_VOLUME_SCOPE is not: a new PAT would move every operator volume; pin the old scope first with SB_OPERATOR_VOLUME_SCOPE=%s", old)
	}

	l4Proxy, _, err := envBoolStrict("SB_L4_FALLBACK_PROXY_PROTOCOL")
	if err != nil {
		// A typo here must not silently pick a side: on with no listener
		// wrapper breaks every HTTPS handshake, off hides client addresses.
		return err
	}
	cfg.L4FallbackProxyProtocol = l4Proxy

	if cfg.EnterpriseMode && cfg.PATTokenPrevious != "" && len([]byte(cfg.PATTokenPrevious)) < minEnterpriseCredentialBytes {
		return fmt.Errorf("SB_PAT_TOKEN_PREVIOUS must contain at least %d bytes when SB_ENTERPRISE_MODE=true", minEnterpriseCredentialBytes)
	}
	return nil
}

// PATScopeHostOnly reports whether the PAT is confined to the host and
// cluster peers (SB_PAT_SCOPE=host).
func (c Config) PATScopeHostOnly() bool { return c.PATScope == PATScopeHost }

// ErrEnterpriseNeedsNamedCredentials and ErrEnterpriseNeedsHostPATScope are
// enterprise mode's credential checks (§5.12, L7, D5). The daemon runs them
// at boot (see pkg/daemon's identity guard): a managed provider that
// validates its own tokens already enforces named credentials, so they apply
// only to the open-source identity path.
var (
	ErrEnterpriseNeedsNamedCredentials = errors.New("SB_ENTERPRISE_MODE=true requires SB_IDENTITY_ENABLED=true: enterprise mode enforces named credentials (SSO or scoped API tokens; an identity file is optional, so tokens-only mode works air-gapped)")
	ErrEnterpriseNeedsHostPATScope     = errors.New("SB_ENTERPRISE_MODE=true requires SB_PAT_SCOPE=host: point Caddy's reverse_proxy at SB_PUBLIC_API_SOCKET (re-run install.sh with --pat-scope host), and move remote tools that use the operator token (Prometheus scrape, dashboard, remote MCP, SDK scripts) to a named token or SSO")
)
