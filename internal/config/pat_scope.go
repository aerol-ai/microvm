package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
	// DefaultPublicAPISocketGroup is the group the socket and its directory
	// get: the stock caddy package's, which install.sh's Caddy runs as.
	DefaultPublicAPISocketGroup = "caddy"
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
	// A group by name, or by number where Caddy's user has no name in this
	// image (a Kubernetes pod, where the edge runs as a bare uid and gid).
	cfg.PublicAPISocketGroup = getEnv("SB_PUBLIC_API_SOCKET_GROUP", DefaultPublicAPISocketGroup)
	// A listener of its own for the admin token from inside the pod (the
	// chart sets it in enterprise mode): a mesh sidecar delivers outside
	// callers to the API port from loopback, so there loopback is not the
	// pod. Only a loopback address literal: anything else would take the
	// admin token from the network.
	cfg.PATLocalListen = strings.TrimSpace(os.Getenv("SB_PAT_LOCAL_LISTEN"))
	if cfg.PATLocalListen != "" {
		if cfg.PATScope != PATScopeHost {
			return fmt.Errorf("SB_PAT_LOCAL_LISTEN needs SB_PAT_SCOPE=host: under scope any the admin token works from anywhere")
		}
		port, ok := loopbackListen(cfg.PATLocalListen)
		if !ok {
			return fmt.Errorf("SB_PAT_LOCAL_LISTEN must be 127.0.0.1:<port> or [::1]:<port>, got %q", cfg.PATLocalListen)
		}
		if port == strconv.Itoa(cfg.APIPort) {
			return fmt.Errorf("SB_PAT_LOCAL_LISTEN %q uses the API port; give it a port of its own", cfg.PATLocalListen)
		}
		if other := cfg.listenerOnPort(port); other != "" {
			return fmt.Errorf("SB_PAT_LOCAL_LISTEN %q uses the port of %s; give it a port of its own", cfg.PATLocalListen, other)
		}
		if n, _ := strconv.Atoi(port); n >= cfg.L4PortRangeStart && n <= cfg.L4PortRangeEnd {
			return fmt.Errorf("SB_PAT_LOCAL_LISTEN %q is inside SB_L4_PORT_RANGE_START/END (%d-%d), where Caddy listens for sandboxes' TCP ports; give it a port of its own",
				cfg.PATLocalListen, cfg.L4PortRangeStart, cfg.L4PortRangeEnd)
		}
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
	if err := cfg.loadPATVerifier(); err != nil {
		return err
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

// listenerOnPort names the setting of another listener on this port, or "".
// A pod's containers share one network namespace, and sandboxd binds most of
// these on loopback too: the chart first gave the admin token listener
// 127.0.0.1:21213, the gateway's ingress proxy address, and every gateway
// then failed to start on "address already in use". The host is not
// compared: 0.0.0.0 and 127.0.0.1 on one port clash as well.
func (cfg *Config) listenerOnPort(port string) string {
	listeners := []struct{ env, addr string }{
		{"SB_INTERNAL_INGRESS_ADDR", cfg.InternalIngressAddr},
		{"SB_INTERNAL_L4_WAKE_ADDR", cfg.InternalL4WakeAddr},
		{"SB_L4_TLS_FALLBACK", cfg.L4TLSFallback},
		{"SB_ROUTE_DNS_ADDR", cfg.RouteDNSAddr},
		{"SB_SSH_LISTEN_ADDR", cfg.SSHListenAddr},
		{"SB_RAFT_BIND_ADDR", cfg.RaftBindAddr},
		{"SB_GOSSIP_BIND_ADDR", cfg.GossipBindAddr},
		{"SB_CLUSTER_INTERNAL_LISTEN", cfg.ClusterInternalListenAddr},
		{"SB_AGENT_SANDBOX_API_ADDR", cfg.AgentSandboxAPIAddr},
		{"SB_HOSTPORT_REDIRECT_PORT", ":" + strconv.Itoa(cfg.HostPortRedirectPort)},
		{"SB_EGRESS_PROXY_PORT", ":" + strconv.Itoa(cfg.EgressProxyPort)},
		{"SB_EGRESS_DNS_PORT", ":" + strconv.Itoa(cfg.EgressDNSPort)},
	}
	// Caddy, in the same pod (the edge container) or on the same VM.
	if u, err := url.Parse(cfg.CaddyAdminURL); err == nil {
		listeners = append(listeners, struct{ env, addr string }{"SB_CADDY_ADMIN_URL", u.Host})
	}
	for _, l := range listeners {
		if _, p, err := net.SplitHostPort(strings.TrimSpace(l.addr)); err == nil && p == port {
			return l.env
		}
	}
	return ""
}

// LocalAdminURL is where a tool on this node sends the admin token (the
// PAT): the admin token's own listener (SB_PAT_LOCAL_LISTEN) when the node
// has one, since the API port then refuses the admin token even from
// loopback; else the API port on loopback. Every local caller of the admin
// token goes through it or LocalAdminURLFromEnv.
func (c Config) LocalAdminURL() string {
	listen := ""
	if c.PATLocalOnly() {
		listen = c.PATLocalListen
	}
	return localAdminURL(c.APIHost, strconv.Itoa(c.APIPort), listen)
}

// LocalAdminURLFromEnv is LocalAdminURL for a tool that reads the node's
// env files instead of loading its config (sandboxd's upgrade guard, the
// installer's init, join and adopt): get returns one variable's value, ""
// when it is not set.
func LocalAdminURLFromEnv(get func(string) string) string {
	listen := ""
	if strings.EqualFold(strings.TrimSpace(get("SB_PAT_SCOPE")), PATScopeHost) {
		listen = strings.TrimSpace(get("SB_PAT_LOCAL_LISTEN"))
	}
	// The port as sandboxd reads it (getEnvInt: a number, else 21212), and
	// only 1-65535: anything else written into the URL, such as
	// "21212@collector.example", would make 127.0.0.1:21212 the userinfo
	// and send the admin token to the host after the @.
	port := "21212"
	if n, err := strconv.Atoi(strings.TrimSpace(get("SB_API_PORT"))); err == nil && n >= 1 && n <= 65535 {
		port = strconv.Itoa(n)
	}
	return localAdminURL(get("SB_API_HOST"), port, listen)
}

// localAdminURL: the admin listener when there is one, else the API port.
// It never leaves this host's loopback, whatever the env files say: the
// listener only as Load takes it (loopbackListen; an env file is read
// without Load's checks), and the API host only as a loopback literal. A
// wildcard bind ("", 0.0.0.0, ::) is reached on 127.0.0.1, and so is
// anything else: a DNS name (resolved again at call time, wherever it then
// points) or another address would send the admin token off the machine in
// clear. A node bound to one other address then gets a refused connection,
// never a leaked token.
func localAdminURL(host, port, listen string) string {
	if _, ok := loopbackListen(listen); ok {
		return "http://" + strings.TrimSpace(listen)
	}
	h := strings.Trim(strings.TrimSpace(host), "[]")
	if ip, err := netip.ParseAddr(h); err != nil || (ip != netip.MustParseAddr("127.0.0.1") && ip != netip.IPv6Loopback()) {
		h = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(h, port)
}

// loopbackListen is SB_PAT_LOCAL_LISTEN's rule, for Load and for every
// tool that reads it from an env file: 127.0.0.1:<port> or [::1]:<port>, a
// port other than 0. It returns the port.
func loopbackListen(addr string) (string, bool) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || (ip != netip.MustParseAddr("127.0.0.1") && ip != netip.IPv6Loopback()) {
		return "", false
	}
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return "", false
	}
	return port, true
}

// PATLocalOnly reports whether the admin token works only on its own
// loopback listener (SB_PAT_LOCAL_LISTEN), not on the API port at all.
func (c Config) PATLocalOnly() bool { return c.PATScopeHostOnly() && c.PATLocalListen != "" }

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
