package rootd

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The helper's network calls (plans/security-gaps-m1-m4.md §3.3, "Network";
// M1 PR 4): a containerd sandbox's named network namespace, its CNI
// attachment to the sandboxes' bridge, and its address. The agent's netns
// pool keeps the bookkeeping (which slot is whose, in its store) and names
// a namespace by its pool name; the helper does the root work:
//
//   - The path is the helper's: <NetnsDir>/<name>, from a name the rules
//     pass (rootpolicy.NetnsPath). The netns folder is root's alone, so a
//     name in it is what root left there.
//   - CNI runs with the helper's own config and plugins, from folders only
//     root can write: CNI plugins run as root, so the agent must never be
//     able to place one or edit the config that names one.
//   - An address the agent sends (teardown's NAT chain and connection
//     tracking) must be a sandbox's, in the helper's range
//     (rootpolicy.CheckSandboxAddress).
//   - A namespace that already exists is touched only when the kernel says
//     it is a sandbox's: loopback (and the tunnel devices the kernel puts
//     in every new namespace) alone, or veths whose peers sit on the
//     helper's bridge (NetnsState.Foreign). The helper keeps no state of its
//     own; on a VM /run/netns is shared with anything else that uses `ip
//     netns`, and the agent must not reach those namespaces through it.
//
// Every call is safe to retry after a dropped connection, and to repeat
// (rootclient retrySafe): RealizeNetns answers a namespace it already
// realized as it is, and clears a half-made one before building it again,
// so a second run never attaches a sandbox twice.

// ReasonNotSandboxNetns: a namespace by that name exists and holds a link
// that is not one of the helper's sandbox veths.
const ReasonNotSandboxNetns = "not_sandbox_netns"

// NetworkConfig is where the helper's CNI lives: its own settings, which the
// operator sets for both the helper and sandboxd under the same names.
type NetworkConfig struct {
	// PluginDir holds the CNI plugins the helper runs as root
	// (SB_CONTAINERD_CNI_PLUGIN_DIR).
	PluginDir string
	// ConfPath is the bridge conflist (SB_CONTAINERD_CNI_CONF_PATH). The
	// helper writes it when it is absent and never rewrites one that is
	// there: sandboxes may hold its addresses.
	ConfPath string
	// Subnet is SB_CONTAINERD_BRIDGE_SUBNET: empty takes the conflist's
	// range, or the default for a conflist the helper writes. Set, it must
	// match a conflist that is already there.
	Subnet string
}

func (n NetworkConfig) configured() bool { return n != NetworkConfig{} }

func (n NetworkConfig) validate() error {
	if !n.configured() {
		return nil
	}
	for _, p := range []struct{ name, path string }{{"CNI plugin folder", n.PluginDir}, {"CNI config", n.ConfPath}} {
		if !filepath.IsAbs(p.path) || filepath.Clean(p.path) != p.path || p.path == "/" {
			return fmt.Errorf("root helper: %s %q: want a clean absolute path other than /", p.name, p.path)
		}
	}
	if n.Subnet != "" {
		p, err := netip.ParsePrefix(n.Subnet)
		if err != nil || !p.Addr().Is4() || p.Masked() != p || p.Bits() < 8 || p.Bits() > 24 {
			return fmt.Errorf("root helper: sandbox range %q: want an IPv4 network between /8 and /24", n.Subnet)
		}
	}
	return nil
}

// NetnsState is a namespace as the kernel shows it.
type NetnsState struct {
	// Exists: something is at the namespace's path.
	Exists bool
	// Foreign names the first link in it that is not loopback and not a
	// veth whose peer is on the helper's bridge, or says the file is not a
	// namespace at all; empty when every link is the helper's.
	Foreign string
	// IPv4 lists its IPv4 addresses, loopback aside, in link order.
	IPv4 []string
}

// NetworkHost is the kernel and CNI work behind the network calls: the
// helper's own on Linux (openNetwork), a fake in tests. The calls' rules,
// order and answers are network.go's; a NetworkHost acts on paths the
// rules built.
type NetworkHost interface {
	// Subnet is the sandboxes' range the CNI config hands out.
	Subnet() netip.Prefix
	// EnsureHost turns IP forwarding on and writes the CNI config when it
	// is absent. Repeating it changes nothing.
	EnsureHost() error
	// Inspect reads the namespace at path back from the kernel.
	Inspect(path string) (NetnsState, error)
	// Realize builds the namespace name at path and attaches it: what
	// netns.Host.Realize does. It answers the address CNI gave it.
	Realize(ctx context.Context, name, path string) (ip string, err error)
	// Remove undoes Realize: CNI DEL for name, the NAT chain and connection
	// tracking for ip (when set), and the namespace. A missing namespace is
	// no error.
	Remove(ctx context.Context, name, path, ip string) error
	// DisableIPv6 turns IPv6 off inside the namespace at path.
	DisableIPv6(path string) error
}

// network serves the network calls. Its host is opened on the first call,
// with the repo's lazy bootstrap (an atomic latch, a mutex for the single
// opening); a failed open is tried again by the next call. So a helper on a
// node whose CNI folders are missing or unsafe still starts and serves its
// other calls, and each network call is refused with the reason.
type network struct {
	policy rootpolicy.Policy
	open   func(Config) (NetworkHost, error)
	whole  Config
	locks  *keyedLocks

	ready atomic.Bool
	mu    sync.Mutex
	host  NetworkHost
}

func newNetwork(cfg Config, injected NetworkHost, locks *keyedLocks) *network {
	if injected == nil && !cfg.Network.configured() {
		return nil
	}
	n := &network{policy: cfg.Policy, open: openNetworkFn, whole: cfg, locks: locks, host: injected}
	if injected != nil {
		n.ready.Store(true)
	}
	return n
}

// openNetworkFn opens the helper's own network; tests replace it.
var openNetworkFn = openNetwork

// networkFeatures are the calls network serves, as Version lists them.
var networkFeatures = []string{rootdpb.FeatureEnsureHostNetwork, rootdpb.FeatureRealizeNetns,
	rootdpb.FeatureRemoveNetns, rootdpb.FeatureDisableNetnsIPv6, rootdpb.FeatureNetnsAddrs}

func (n *network) opened() (NetworkHost, error) {
	if n.ready.Load() {
		return n.host, nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.host != nil {
		return n.host, nil
	}
	h, err := n.open(n.whole)
	if err != nil {
		return nil, &fileError{code: codes.FailedPrecondition, msg: "root helper: sandbox networks are not set up on this node: " + err.Error()}
	}
	n.host = h
	n.ready.Store(true)
	return h, nil
}

// netnsKey is the per-object lock key of a namespace (eng review D11):
// calls for one namespace run one at a time, so a Remove and a Realize of
// it never interleave. Calls for different namespaces run in parallel;
// what they share keeps only its own locks (the netns folder's flock, the
// CNI IPAM plugin's lock, the iptables lock).
func netnsKey(name string) string { return "netns/" + name }

// path checks name and builds its namespace path; a bad name is refused.
func (n *network) path(name string) (string, error) {
	p, err := rootpolicy.NetnsPath(n.policy, name)
	if err != nil {
		return "", refusedRule(codes.InvalidArgument, err)
	}
	return p, nil
}

// refusedRule turns a rootpolicy violation into the call's refusal.
func refusedRule(code codes.Code, err error) error {
	return &fileError{code: code, reason: string(rootpolicy.RuleOf(err)), msg: err.Error()}
}

func notSandboxNetns(name, link string) error {
	return &fileError{code: codes.PermissionDenied, reason: ReasonNotSandboxNetns,
		msg: fmt.Sprintf("root helper: network namespace %s is not a sandbox's (%s)", name, link)}
}

// inspect reads name's namespace and refuses it when it is not a sandbox's.
func inspect(h NetworkHost, name, path string) (NetnsState, error) {
	st, err := h.Inspect(path)
	if err != nil {
		return NetnsState{}, fmt.Errorf("root helper: network namespace %s: %w", name, err)
	}
	if st.Exists && st.Foreign != "" {
		return NetnsState{}, notSandboxNetns(name, st.Foreign)
	}
	return st, nil
}

func (n *network) ensureHost() (*rootdpb.EnsureHostNetworkResponse, error) {
	h, err := n.opened()
	if err != nil {
		return nil, err
	}
	if err := h.EnsureHost(); err != nil {
		return nil, fmt.Errorf("root helper: host network: %w", err)
	}
	return &rootdpb.EnsureHostNetworkResponse{Subnet: h.Subnet().String()}, nil
}

// realize makes sure name's namespace is realized. One already realized
// (a namespace of the helper's with a sandbox address in it: a retried
// call whose answer was lost, or a build whose store write did not happen)
// is answered as it is: CNI ADD is not idempotent, and a second one would
// fail on the interface it finds, or give a second address. One left half
// made (no address: a build cut short) is removed whole first, CNI DEL
// included, so its address lease and NAT chain go too, and built again.
func (n *network) realize(ctx context.Context, req *rootdpb.RealizeNetnsRequest) (*rootdpb.RealizeNetnsResponse, error) {
	name := req.GetNetnsName()
	path, err := n.path(name)
	if err != nil {
		return nil, err
	}
	h, err := n.opened()
	if err != nil {
		return nil, err
	}
	defer n.locks.lock(netnsKey(name))()
	st, err := inspect(h, name, path)
	if err != nil {
		return nil, err
	}
	if st.Exists {
		if ip := sandboxAddress(h.Subnet(), st.IPv4); ip != "" {
			return &rootdpb.RealizeNetnsResponse{NetnsPath: path, ContainerIp: ip}, nil
		}
		if err := h.Remove(ctx, name, path, ""); err != nil {
			return nil, fmt.Errorf("root helper: clear half-made network namespace %s: %w", name, err)
		}
	}
	ip, err := h.Realize(ctx, name, path)
	if err != nil {
		return nil, fmt.Errorf("root helper: realize network namespace %s: %w", name, err)
	}
	if _, err := rootpolicy.CheckSandboxAddress(h.Subnet(), ip); err != nil {
		// CNI's own answer, from the helper's own config: not the agent's
		// doing, so a failure, not a refusal. Undo it; no spec may join a
		// namespace whose address is not a sandbox's.
		_ = h.Remove(ctx, name, path, "")
		return nil, fmt.Errorf("root helper: network namespace %s came up at %q: %w", name, ip, err)
	}
	return &rootdpb.RealizeNetnsResponse{NetnsPath: path, ContainerIp: ip}, nil
}

// sandboxAddress is the first of addrs that is a sandbox address in subnet.
func sandboxAddress(subnet netip.Prefix, addrs []string) string {
	for _, a := range addrs {
		if _, err := rootpolicy.CheckSandboxAddress(subnet, a); err == nil {
			return a
		}
	}
	return ""
}

// remove makes sure name's namespace is gone, with its attachment. An
// address is checked before anything is touched; a missing namespace still
// gets CNI DEL, which releases a lease a crash left behind.
func (n *network) remove(ctx context.Context, req *rootdpb.RemoveNetnsRequest) (*rootdpb.RemoveNetnsResponse, error) {
	name := req.GetNetnsName()
	path, err := n.path(name)
	if err != nil {
		return nil, err
	}
	h, err := n.opened()
	if err != nil {
		return nil, err
	}
	ip := req.GetContainerIp()
	if ip != "" {
		if _, err := rootpolicy.CheckSandboxAddress(h.Subnet(), ip); err != nil {
			return nil, refusedRule(codes.InvalidArgument, err)
		}
	}
	defer n.locks.lock(netnsKey(name))()
	if _, err := inspect(h, name, path); err != nil {
		return nil, err
	}
	if err := h.Remove(ctx, name, path, ip); err != nil {
		return nil, fmt.Errorf("root helper: remove network namespace %s: %w", name, err)
	}
	return &rootdpb.RemoveNetnsResponse{}, nil
}

func (n *network) disableIPv6(req *rootdpb.DisableNetnsIPv6Request) (*rootdpb.DisableNetnsIPv6Response, error) {
	name := req.GetNetnsName()
	path, err := n.path(name)
	if err != nil {
		return nil, err
	}
	h, err := n.opened()
	if err != nil {
		return nil, err
	}
	defer n.locks.lock(netnsKey(name))()
	st, err := inspect(h, name, path)
	if err != nil {
		return nil, err
	}
	if !st.Exists {
		return nil, &fileError{code: codes.NotFound, msg: "root helper: no network namespace " + name}
	}
	if err := h.DisableIPv6(path); err != nil {
		return nil, fmt.Errorf("root helper: disable IPv6 in %s: %w", name, err)
	}
	return &rootdpb.DisableNetnsIPv6Response{}, nil
}

func (n *network) addrs(req *rootdpb.NetnsAddrsRequest) (*rootdpb.NetnsAddrsResponse, error) {
	name := req.GetNetnsName()
	path, err := n.path(name)
	if err != nil {
		return nil, err
	}
	h, err := n.opened()
	if err != nil {
		return nil, err
	}
	defer n.locks.lock(netnsKey(name))()
	st, err := inspect(h, name, path)
	if err != nil {
		return nil, err
	}
	return &rootdpb.NetnsAddrsResponse{Exists: st.Exists, Ipv4: st.IPv4}, nil
}

// keyedLocks are the helper's per-object locks (eng review D11): calls
// that name one object (a container's files, a namespace) run one at a
// time, in the order they take the lock, and calls for different objects
// run in parallel. An entry lives only while a call holds or waits for it.
type keyedLocks struct {
	mu sync.Mutex
	m  map[string]*keyedLock
}

type keyedLock struct {
	mu      sync.Mutex
	waiters int
}

// lock takes key's lock and returns its release. A nil keyedLocks (a
// helper value built by hand in a test) locks nothing.
func (k *keyedLocks) lock(key string) (unlock func()) {
	if k == nil {
		return func() {}
	}
	k.mu.Lock()
	if k.m == nil {
		k.m = map[string]*keyedLock{}
	}
	l := k.m[key]
	if l == nil {
		l = &keyedLock{}
		k.m[key] = l
	}
	l.waiters++
	k.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		if l.waiters--; l.waiters == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}

// held is how many keys have a call holding or waiting; for tests.
func (k *keyedLocks) held() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}
