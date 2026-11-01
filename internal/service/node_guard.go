package service

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/runtime/resolvconf"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The node guard: sandboxes are default-denied from the node they run on.
// Container, gVisor and Firecracker sandboxes get it from the host firewall
// (netrules ChainAerolvmNode, one chain per sandbox subnet); WASM and
// isolate sandboxes dial from host processes and get it from the dial guard
// (egresspolicy.CheckNode). The control-port guard it replaces listed the
// ports to drop, so every other service on the node (an EDR agent, a log
// shipper, a node exporter) was open to every default sandbox (UC-319).
//
// What a sandbox may still reach on its own node, and where each comes from:
//   - the egress gateway's DNS (udp+tcp) and proxy (tcp) ports, when the
//     gateway runs here: its nat prerouting redirects a gateway-mode
//     sandbox's DNS and web traffic to them on the bridge address
//     (internal/egress nft_linux.go addChains);
//   - DNS (53, udp+tcp) on a node address only when the resolvers handed to
//     sandboxes name that address: resolvconf.Generate copies the host's
//     upstream resolvers into containerd and Firecracker sandboxes, and
//     dockerd copies the same ones (or systemd-resolved's upstreams) into
//     its containers;
//   - the public web ports 80 and 443 on a node that serves ingress
//     (Caddy): the public front door, which every internet client reaches
//     anyway, so a sandbox can fetch its own public URL when that resolves
//     to this node;
//   - SB_SANDBOX_NODE_PORTS_ALLOW, the operator's escape hatch (refused in
//     enterprise mode).
//
// Nothing else is needed: the toolbox is reached by the host (replies pass
// the guard's established-return rule), Firecracker's handshake runs over
// vsock, guests and containers get static addresses (no DHCP), and dockerd's
// embedded DNS (user-defined networks) answers inside the container's own
// network namespace.

// nodeGuardReassertInterval paces the check that the guard is still in
// place, matching the user-chain re-assert (pkg/daemon chainReassertInterval).
const nodeGuardReassertInterval = 30 * time.Second

// ErrNodeGuardNotReady refuses a container or Firecracker create while the
// node guard is not installed for that runtime: the sandbox could reach
// every service on the node (503, node_guard_not_ready; the supervisor
// retries every few seconds).
var ErrNodeGuardNotReady = errors.New("this node cannot keep sandboxes off its own services right now; creates on this runtime are refused until it can")

// nodeGuardReady is 1 per runtime whose guard is installed, 0 otherwise.
var nodeGuardReady = expvar.NewMap("aerolvm_node_guard_ready")

// nodeGuardResolvConfs are the resolver files whose nameservers sandboxes
// are handed (a var for tests).
var nodeGuardResolvConfs = []string{resolvconf.HostPath, resolvconf.SystemdUpstreamPath}

type nodeGuardState struct {
	// mu serializes syncs (boot, supervisor ticks).
	mu sync.Mutex
	// applied is the allowlist each runtime got, keyed by runtime name.
	applied   map[string]string
	checkedAt time.Time
	// gatewayPorts are the ports the egress gateway reported it listens on.
	gatewayPorts atomic.Pointer[[2]uint16]
	// status is each runtime's last result (nil: installed), read by the
	// create gate without the lock.
	status atomic.Pointer[map[string]error]
}

// SandboxNodeAllowlist is what sandboxes on bridges and TAP subnets may still
// reach on their own node (see the list above), sorted and deduplicated.
func (s *Service) SandboxNodeAllowlist() []netrules.NodePort {
	var out []netrules.NodePort
	if s.egressEnabled() {
		dns, proxy := s.gatewayNodePorts()
		out = append(out,
			netrules.NodePort{Proto: "udp", Port: dns},
			netrules.NodePort{Proto: "tcp", Port: dns},
			netrules.NodePort{Proto: "tcp", Port: proxy})
	}
	for _, ns := range localNameservers() {
		out = append(out,
			netrules.NodePort{Proto: "udp", Port: 53, Dst: ns},
			netrules.NodePort{Proto: "tcp", Port: 53, Dst: ns})
	}
	if servesIngress(s.cfg) {
		out = append(out, netrules.NodePort{Proto: "tcp", Port: 80}, netrules.NodePort{Proto: "tcp", Port: 443})
	}
	for _, p := range s.cfg.SandboxNodePortsAllow {
		out = append(out, netrules.NodePort{Proto: p.Proto, Port: p.Port})
	}
	slices.SortFunc(out, func(a, b netrules.NodePort) int { return strings.Compare(a.String(), b.String()) })
	return slices.Compact(out)
}

// HostMediatedNodePorts are the node ports WASM and isolate sandboxes may
// still reach on the node's non-loopback addresses: ingress and the escape
// hatch. The gateway ports and DNS are for bridged sandboxes; a host
// process resolves names itself.
func HostMediatedNodePorts(cfg config.Config) []uint16 {
	var out []uint16
	if servesIngress(cfg) {
		out = append(out, 80, 443)
	}
	for _, p := range cfg.SandboxNodePortsAllow {
		out = append(out, p.Port)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// servesIngress reports whether Caddy on this node is the public front
// door, so 80 and 443 here are what the internet reaches anyway.
func servesIngress(cfg config.Config) bool { return cfg.IsIngress() && cfg.EnableCaddy }

// gatewayNodePorts are the ports the gateway reported listening on, or the
// configured ones until it has.
func (s *Service) gatewayNodePorts() (dns, proxy uint16) {
	if p := s.nodeGuard.gatewayPorts.Load(); p != nil {
		return p[0], p[1]
	}
	return uint16(s.cfg.EgressDNSPort), uint16(s.cfg.EgressProxyPort)
}

// learnGatewayPorts reads the gateway's listeners ("udp:IP:port",
// "tcp:IP:port", "proxy:IP:port"), so the guard opens what it really
// listens on even when egress-gateway.env set other ports than
// sandboxd.env.
func (s *Service) learnGatewayPorts(ctx context.Context) {
	if !s.egressEnabled() || !s.egressReady.Load() {
		return
	}
	st, err := s.egressGateway().Ready(ctx)
	if err != nil {
		return
	}
	var dns, proxy uint16
	for _, l := range st.Listeners {
		kind, addr, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			continue
		}
		switch kind {
		case "udp", "tcp":
			dns = ap.Port()
		case "proxy":
			proxy = ap.Port()
		}
	}
	if dns == 0 || proxy == 0 {
		return
	}
	if cd, cp := uint16(s.cfg.EgressDNSPort), uint16(s.cfg.EgressProxyPort); (dns != cd || proxy != cp) && s.nodeGuard.gatewayPorts.Load() == nil {
		s.logger.Warn("egress gateway listens on other ports than SB_EGRESS_DNS_PORT/SB_EGRESS_PROXY_PORT say; the node guard follows the gateway",
			"gateway_dns", dns, "gateway_proxy", proxy, "configured_dns", cd, "configured_proxy", cp)
	}
	s.nodeGuard.gatewayPorts.Store(&[2]uint16{dns, proxy})
}

// localNameservers are the resolvers handed to sandboxes that are this
// node's own addresses.
func localNameservers() []netip.Addr {
	local := map[netip.Addr]bool{}
	for _, ip := range localIPv4s() {
		local[ip] = true
	}
	var out []netip.Addr
	for _, path := range nodeGuardResolvConfs {
		for _, ns := range resolvconf.Nameservers(path) {
			if ns.Is4() && local[ns] && !slices.Contains(out, ns) {
				out = append(out, ns)
			}
		}
	}
	return out
}

type namedRuntime struct {
	name string
	rt   runtime.Runtime
}

// nodeGuardRuntimes are the runtimes whose sandboxes sit on a host bridge
// or TAP subnet, by the name the create gate uses.
func (s *Service) nodeGuardRuntimes() []namedRuntime {
	return []namedRuntime{
		{models.ContainerEngineDocker, s.docker},
		{models.ContainerEngineContainerd, s.containerd},
		{models.RuntimeFirecracker, s.firecracker},
	}
}

// ApplyNodeGuard installs the guard on every runtime. The daemon calls it at
// boot, before the API serves, so no sandbox is created before it.
func (s *Service) ApplyNodeGuard(ctx context.Context) {
	s.syncNodeGuard(ctx, true)
}

// SuperviseNodeGuard keeps the guard in place: it installs it on a runtime
// where it failed, re-installs it when the allowlist changes (the gateway
// came up, a resolver changed), and re-asserts it every
// nodeGuardReassertInterval in case a host firewall reload or a flush took
// it away.
func (s *Service) SuperviseNodeGuard(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.syncNodeGuard(ctx, false)
		}
	}
}

func (s *Service) syncNodeGuard(ctx context.Context, force bool) {
	ng := &s.nodeGuard
	ng.mu.Lock()
	defer ng.mu.Unlock()
	due := force || time.Since(ng.checkedAt) >= nodeGuardReassertInterval
	if due {
		s.learnGatewayPorts(ctx)
	}
	allow := s.SandboxNodeAllowlist()
	key := nodePortsKey(allow)
	if ng.applied == nil {
		ng.applied = map[string]string{}
	}
	status := map[string]error{}
	if prev := ng.status.Load(); prev != nil {
		for k, v := range *prev {
			status[k] = v
		}
	}
	for _, nr := range s.nodeGuardRuntimes() {
		setter, ok := nr.rt.(runtime.NodeGuardSetter)
		if nr.rt == nil || !ok {
			continue
		}
		prev, seen := status[nr.name]
		var err error
		switch {
		case force || ng.applied[nr.name] != key || !seen || prev != nil:
			err = setter.SetNodeGuard(ctx, allow)
			if err == nil {
				ng.applied[nr.name] = key
			} else {
				delete(ng.applied, nr.name)
			}
		case due:
			var repaired bool
			repaired, err = setter.ReassertNodeGuard(ctx)
			if repaired && err == nil {
				s.logger.Warn("node guard was missing and has been put back; something rewrote the host firewall", "runtime", nr.name)
			}
		default:
			continue
		}
		s.noteNodeGuard(nr.name, prev, seen, err, allow)
		status[nr.name] = err
	}
	ng.status.Store(&status)
	if due {
		ng.checkedAt = time.Now()
	}
}

// noteNodeGuard logs a runtime's guard result when it changes, and
// publishes it.
func (s *Service) noteNodeGuard(name string, prev error, seen bool, err error, allow []netrules.NodePort) {
	v := new(expvar.Int)
	if err == nil {
		v.Set(1)
	}
	nodeGuardReady.Set(name, v)
	if seen && errText(prev) == errText(err) {
		return
	}
	switch {
	case err == nil:
		s.logger.Info("node guard installed: sandboxes reach nothing on this node but the allowlist", "runtime", name, "allow", nodePortsKey(allow))
	case errors.Is(err, runtime.ErrNodeGuardUnavailable) && !s.cfg.EnterpriseMode:
		s.logger.Warn("node guard unavailable: network rules are off, so sandboxes can reach every service on this node", "runtime", name)
	default:
		s.logger.Error("node guard not installed: sandboxes on this runtime could reach every service on this node, so its creates are refused until it is", "runtime", name, "error", err)
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func nodePortsKey(allow []netrules.NodePort) string {
	parts := make([]string, 0, len(allow))
	for _, p := range allow {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

// requireNodeGuard is the create gate: a container or Firecracker sandbox
// is not created on a runtime whose guard failed to install. A runtime with
// network rules off is allowed outside enterprise mode (the operator turned
// the host firewall off, and the boot log says what that costs). One map
// read; nothing until the daemon has run the guard once (tests, nodes that
// own no sandboxes).
func (s *Service) requireNodeGuard(chosenRuntime string) error {
	name := s.nodeGuardRuntimeName(chosenRuntime)
	st := s.nodeGuard.status.Load()
	if name == "" || st == nil {
		return nil
	}
	err, seen := (*st)[name]
	if !seen || err == nil || (errors.Is(err, runtime.ErrNodeGuardUnavailable) && !s.cfg.EnterpriseMode) {
		return nil
	}
	return fmt.Errorf("%w (runtime %s: %v)", ErrNodeGuardNotReady, name, err)
}

// nodeGuardRuntimeName maps a create's runtime to the runtime whose guard
// covers it: Firecracker guests are on the TAP subnet, runc and gVisor
// containers on the host engine's bridge; WASM and isolate sandboxes are
// guarded in-process.
func (s *Service) nodeGuardRuntimeName(chosenRuntime string) string {
	switch chosenRuntime {
	case models.RuntimeFirecracker:
		return models.RuntimeFirecracker
	case models.RuntimeWasm, models.RuntimeIsolate:
		return ""
	}
	if s.cfg.ContainerEngine == models.ContainerEngineContainerd {
		return models.ContainerEngineContainerd
	}
	return models.ContainerEngineDocker
}
