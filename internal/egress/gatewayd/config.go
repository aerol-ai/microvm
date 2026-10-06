// Package gatewayd is the `sandboxd egress-gateway` process (plans/
// egress-domain-filtering.md §5.3, D9): it owns the nft table, the filtering
// DNS resolver and the SNI/Host proxy, and takes orders from sandboxd over a
// UDS. It runs as its own systemd unit, so sandboxd restarts never interrupt
// gateway-mode egress.
package gatewayd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/dnsfilter"
	"github.com/aerol-ai/microvm/internal/egress/proxy"
)

// Config is the gateway process configuration (rows in setup/config-defaults.md).
type Config struct {
	SocketPath         string
	StateDir           string
	DNSPort            uint16
	ProxyPort          uint16
	DNSUpstreams       []string
	DNSQPS             float64
	LearnedMax         int
	LearnMax           int
	ProxyMaxConns      int
	ProxyMaxPerSandbox int
	AuditBuffer        int
	// PeerUIDs and PeerCgroup gate the UDS (CEO D22).
	PeerUIDs   []uint32
	PeerCgroup string
	// HeartbeatInterval paces table-loss checks and heartbeat events (D17).
	HeartbeatInterval time.Duration
	// FlowReadInterval paces reads of the dynamic flow sets (F3, C9).
	FlowReadInterval time.Duration
	// SnapshotDebounce batches snapshot writes after changes.
	SnapshotDebounce time.Duration
	// OperatorFile is the private-cloud operator policy (§5.10).
	OperatorFile string
}

// Defaults.
const (
	DefaultSocketPath = "/run/aerolvm/egress-gateway.sock"
	DefaultStateDir   = "/var/lib/aerolvm-egress"
	DefaultDNSPort    = 53054
	DefaultProxyPort  = 15080
)

// FromEnv reads the SB_EGRESS_* environment.
func FromEnv() (Config, error) {
	cfg := Config{
		SocketPath:         envOr("SB_EGRESS_GATEWAY_SOCKET", DefaultSocketPath),
		StateDir:           envOr("SB_EGRESS_STATE_DIR", DefaultStateDir),
		DNSPort:            DefaultDNSPort,
		ProxyPort:          DefaultProxyPort,
		DNSQPS:             dnsfilter.DefaultQPS,
		LearnedMax:         egress.DefaultLearnedMax,
		LearnMax:           1024,
		ProxyMaxConns:      proxy.DefaultMaxConns,
		ProxyMaxPerSandbox: proxy.DefaultMaxConnsPerSandbox,
		AuditBuffer:        egress.DefaultAuditBuffer,
		PeerUIDs:           []uint32{0},
		PeerCgroup:         envOr("SB_EGRESS_PEER_CGROUP", "sandboxd.service"),
		HeartbeatInterval:  5 * time.Second,
		FlowReadInterval:   2 * time.Second,
		SnapshotDebounce:   500 * time.Millisecond,
		OperatorFile:       strings.TrimSpace(os.Getenv("SB_EGRESS_OPERATOR_FILE")),
	}
	var err error
	if cfg.DNSPort, err = envPort("SB_EGRESS_DNS_PORT", cfg.DNSPort); err != nil {
		return cfg, err
	}
	if cfg.ProxyPort, err = envPort("SB_EGRESS_PROXY_PORT", cfg.ProxyPort); err != nil {
		return cfg, err
	}
	if v := strings.TrimSpace(os.Getenv("SB_EGRESS_DNS_UPSTREAMS")); v != "" {
		for _, u := range strings.Split(v, ",") {
			if u = strings.TrimSpace(u); u != "" {
				if !strings.Contains(u, ":") || strings.Count(u, ":") > 1 && !strings.HasPrefix(u, "[") {
					u += ":53"
				}
				cfg.DNSUpstreams = append(cfg.DNSUpstreams, u)
			}
		}
	}
	for name, dst := range map[string]*int{
		"SB_EGRESS_LEARNED_MAX":                 &cfg.LearnedMax,
		"SB_EGRESS_LEARN_MAX":                   &cfg.LearnMax,
		"SB_EGRESS_PROXY_MAX_CONNS":             &cfg.ProxyMaxConns,
		"SB_EGRESS_PROXY_MAX_CONNS_PER_SANDBOX": &cfg.ProxyMaxPerSandbox,
		"SB_EGRESS_AUDIT_BUFFER":                &cfg.AuditBuffer,
	} {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return cfg, fmt.Errorf("%s: want a positive integer, got %q", name, v)
			}
			*dst = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("SB_EGRESS_DNS_QPS")); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f <= 0 {
			return cfg, fmt.Errorf("SB_EGRESS_DNS_QPS: want a positive number, got %q", v)
		}
		cfg.DNSQPS = f
	}
	if cfg.DNSPort == cfg.ProxyPort {
		return cfg, fmt.Errorf("SB_EGRESS_DNS_PORT and SB_EGRESS_PROXY_PORT must differ")
	}
	return cfg, nil
}

func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func envPort(name string, def uint16) (uint16, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%s: want a port, got %q", name, v)
	}
	return uint16(n), nil
}
