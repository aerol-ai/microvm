package config

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

// SandboxNodePort is one extra node port the operator opens to every
// sandbox on the node (SB_SANDBOX_NODE_PORTS_ALLOW).
type SandboxNodePort struct {
	Proto string // "tcp" or "udp"
	Port  uint16
}

func (p SandboxNodePort) String() string { return strconv.Itoa(int(p.Port)) + "/" + p.Proto }

// ParseSandboxNodePorts reads SB_SANDBOX_NODE_PORTS_ALLOW: a comma list of
// ports, each optionally suffixed /tcp or /udp (tcp when bare), such as
// "8080,5353/udp". Empty is the default: nothing extra. Ranges and "all"
// are not accepted, on purpose: every entry is one port someone decided to
// open.
func ParseSandboxNodePorts(raw string) ([]SandboxNodePort, error) {
	var out []SandboxNodePort
	for _, f := range strings.Split(raw, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		port, proto, _ := strings.Cut(f, "/")
		if proto == "" {
			proto = "tcp"
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || (proto != "tcp" && proto != "udp") {
			return nil, fmt.Errorf("invalid SB_SANDBOX_NODE_PORTS_ALLOW entry %q: want a port 1-65535, optionally /tcp or /udp", f)
		}
		p := SandboxNodePort{Proto: proto, Port: uint16(n)}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// hostServicePorts are services every node runs that no sandbox has any
// business reaching: the operator's SSH and rpcbind (on by default on the
// stock Ubuntu image).
var hostServicePorts = []uint16{22, 111}

// NodeControlPorts are this node's control listeners (API, SSH gateway,
// Raft, gossip, the cluster mTLS listener and, with ingress proxy routing,
// the host-port redirect listener) and its host services. The egress
// gateway's control-port guard drops them on every member's addresses, and
// SB_SANDBOX_NODE_PORTS_ALLOW may never open one.
func (c Config) NodeControlPorts() []uint16 {
	out := slices.Clone(hostServicePorts)
	if c.APIPort > 0 && c.APIPort < 65536 {
		out = append(out, uint16(c.APIPort))
	}
	// The redirect listener takes raw-TCP host-port traffic the firewall
	// steered to it; a sandbox has no business dialing it directly (found
	// reachable on cluster-3-mixed-routing, UC-319).
	if c.IngressProxyRouting && c.HostPortRedirectPort > 0 && c.HostPortRedirectPort < 65536 {
		out = append(out, uint16(c.HostPortRedirectPort))
	}
	for _, addr := range []string{c.SSHListenAddr, c.RaftBindAddr, c.GossipBindAddr, c.ClusterInternalListenAddr} {
		if _, p, err := net.SplitHostPort(strings.TrimSpace(addr)); err == nil {
			if n, err := strconv.ParseUint(p, 10, 16); err == nil && n > 0 {
				out = append(out, uint16(n))
			}
		}
	}
	return out
}

// validateSandboxNodePorts refuses an escape hatch that would undo a guard:
// any entry in enterprise mode, and a control port anywhere (the egress
// gateway's control-port guard would drop it for every sandbox on the
// bridges anyway, so the two guards would disagree).
func validateSandboxNodePorts(cfg Config) error {
	if len(cfg.SandboxNodePortsAllow) == 0 {
		return nil
	}
	if cfg.EnterpriseMode {
		return fmt.Errorf("SB_SANDBOX_NODE_PORTS_ALLOW must be empty when SB_ENTERPRISE_MODE=true: a port open to every sandbox on every node is the exposure enterprise mode rules out; run that service off the node (got %v)", cfg.SandboxNodePortsAllow)
	}
	control := cfg.NodeControlPorts()
	for _, p := range cfg.SandboxNodePortsAllow {
		if slices.Contains(control, p.Port) {
			return fmt.Errorf("SB_SANDBOX_NODE_PORTS_ALLOW entry %s is one of this node's control or host-service ports (%v); sandboxes may never reach those", p, control)
		}
	}
	if cfg.EgressDNSPort > 0 || cfg.EgressProxyPort > 0 {
		for _, p := range cfg.SandboxNodePortsAllow {
			if int(p.Port) == cfg.EgressDNSPort || int(p.Port) == cfg.EgressProxyPort {
				return fmt.Errorf("SB_SANDBOX_NODE_PORTS_ALLOW entry %s is the egress gateway's own port; it is opened to the sandboxes that use the gateway already", p)
			}
		}
	}
	return nil
}

// validEgressGatewayPorts checks the gateway ports sandboxd opens to its
// sandboxes. They must match the gateway's own SB_EGRESS_DNS_PORT and
// SB_EGRESS_PROXY_PORT (egress-gateway.env); sandboxd also follows the
// ports the gateway reports it listens on.
func validEgressGatewayPorts(cfg Config) error {
	for name, v := range map[string]int{"SB_EGRESS_DNS_PORT": cfg.EgressDNSPort, "SB_EGRESS_PROXY_PORT": cfg.EgressProxyPort} {
		if v < 1 || v > 65535 {
			return fmt.Errorf("invalid %s %d: require 1-65535", name, v)
		}
	}
	if cfg.EgressDNSPort == cfg.EgressProxyPort {
		return fmt.Errorf("SB_EGRESS_DNS_PORT and SB_EGRESS_PROXY_PORT must differ (both %d)", cfg.EgressDNSPort)
	}
	return nil
}
