package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/netns"
	"github.com/aerol-ai/microvm/internal/privmode"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// Privilege mode (internal/privmode, plans/security-gaps-m1-m4.md D5, D22).
// single, the default and the mode when the setting is absent, is today's:
// nothing here runs. split runs sandboxd with no rights; the root helper
// does its root work, which is built one step at a time (M1 PRs 4 to 9).
// External storage mounts are the helper's from M1 PR 8 (newMountManager).
// So far the helper does the containerd engine's network (namespaces, CNI,
// the forwarding sysctls, the CNI config), its host firewall (every
// sandbox rule, the node guard, the deny floor, the IPv6 fence), and the
// hostname gateway's host side (the self-test's probe network, the
// executable lookups); and Firecracker's VMs, TAPs and guests' firewall
// (M1 PRs 9b and 14). Image builds need no helper call: buildkitd runs
// rootless, and sandboxd imports each build through the gate
// (buildKitBuilderFor). Root work it does not do yet is refused by name,
// at start for what sandboxd does at boot, at the call for the rest, and
// never done as root instead.

// checkPrivilegeMode refuses, at start, a split-mode node this build cannot
// run. Two needs last: split is the containerd engine only (Docker's
// socket is as good as root, and Docker has no gate), and the netns pool,
// whose namespaces the helper makes. The rest are steps the helper does
// not do yet, each named.
func checkPrivilegeMode(cfg config.Config) error {
	if cfg.PrivilegeMode != privmode.Split {
		return nil
	}
	if cfg.ContainerEngine != models.ContainerEngineContainerd {
		return errors.New("SB_PRIVILEGE_MODE=split needs SB_CONTAINER_ENGINE=containerd: the Docker engine's socket " +
			"is as good as root and has no gate in front of it, so a Docker node runs in privilege mode single")
	}
	if !cfg.ContainerdNativeNetnsPoolEnabled {
		return errors.New("SB_PRIVILEGE_MODE=split needs SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED=true: " +
			"the root helper makes every sandbox's network namespace for the pool")
	}
	var gaps []privmode.Step
	// The host firewall (SB_ENABLE_NETWORK_RULES) and enterprise mode's
	// IPv6 fence are the helper's from M1 PR 5 (split_firewall.go); the
	// hostname gateway's host side (SB_EGRESS_FQDN_ENABLED, split_egress.go)
	// and ingress proxy routing's host ports (SB_INGRESS_PROXY_ROUTING,
	// splitHostPortForwarder) from PR 5b. The containerd warm pool
	// (SB_CONTAINERD_POOL_ENABLED) is a create's root work plus the park
	// socket's name, the helper's from M1 PR 13 (containerd split_park.go).
	// V8 isolate groups are the helper's from M1 PR 9 (split_hosts.go): it
	// builds each group's jail and runs workerd; it jails every group, so
	// an unjailed one is single mode only.
	if cfg.EnableIsolate && !cfg.IsolateUseJail {
		return errors.New("SB_PRIVILEGE_MODE=split runs every V8 isolate group in the root helper's jail: " +
			"set SB_ISOLATE_USE_JAIL=true, or run this node in privilege mode single")
	}
	// WASM workers and resident hosts are the helper's from M1 PR 9 too
	// (split_hosts.go), shared with sandboxd by the worker user's group.
	if cfg.EnableWasm {
		if err := checkSplitWasm(cfg); err != nil {
			return err
		}
		if warmPoolEffectivelyEnabled(cfg) {
			gaps = append(gaps, privmode.StepWasmWarmPool)
		}
	}
	// Firecracker VMs are the helper's from M1 PR 9b (split_firecracker.go):
	// it runs the jailer, makes each VM's jail, TAP and filesystems, keeps
	// the guests' firewall (M1 PR 14) and hands a VM's memory and state
	// files across (M1 PR 14b). It always runs the jailer, and it does not
	// run the warm VM pool yet.
	if cfg.EnableFirecracker {
		if !cfg.UseJailer {
			return errors.New("SB_PRIVILEGE_MODE=split runs every Firecracker VM through the root helper's jailer: " +
				"set SB_FIRECRACKER_USE_JAILER=true, or run this node in privilege mode single")
		}
		if cfg.FirecrackerVMMPoolEnabled {
			gaps = append(gaps, privmode.StepFirecrackerWarmPool)
		}
	}
	// gVisor checkpoint moves (SB_GVISOR_CHECKPOINT_MOVES) are the
	// helper's from M1 PR 13: it runs runsc checkpoint and keeps both
	// sides' checkpoints in its own moves folder (containerd
	// split_moves.go, rootd moves.go).
	return privmode.NotYet("start sandboxd", gaps...)
}

// agentGroups are this process's supplementary groups; tests stand them in.
var agentGroups = os.Getgroups

// checkSplitWasm refuses, at start, a split node whose WASM workers the
// helper could not run as it must: dropped to the worker user, on the
// engine its own binary has, and sharing files with a sandboxd in the
// worker user's group.
func checkSplitWasm(cfg config.Config) error {
	if !cfg.WasmWorkerDropPrivs {
		return errors.New("SB_PRIVILEGE_MODE=split runs every WASM worker as the worker user (SB_WASM_WORKER_UID): " +
			"SB_WASM_WORKER_DROP_PRIVS=false is privilege mode single only")
	}
	if eng := strings.ToLower(strings.TrimSpace(cfg.WasmEngine)); eng != "" && eng != "wazero" {
		return fmt.Errorf("SB_PRIVILEGE_MODE=split runs WASM workers on the root helper's own binary, which has the wazero engine only; "+
			"SB_WASM_ENGINE=%s is privilege mode single only", cfg.WasmEngine)
	}
	if cfg.WasmWorkerUID == os.Getuid() {
		return fmt.Errorf("SB_WASM_WORKER_UID=%d is sandboxd's own uid: a worker's escape would be sandboxd", cfg.WasmWorkerUID)
	}
	groups, err := agentGroups()
	if err != nil {
		return fmt.Errorf("privilege mode split: read sandboxd's groups: %w", err)
	}
	if !slices.Contains(groups, cfg.WasmWorkerGID) {
		return fmt.Errorf("SB_PRIVILEGE_MODE=split shares each WASM sandbox's files with its worker by group: "+
			"sandboxd must be a member of the WASM worker group (SB_WASM_WORKER_GID=%d)", cfg.WasmWorkerGID)
	}
	return nil
}

// mountsOffFor is why this node refuses external storage, or "". In split
// mode the root helper mounts (M1 PR 8), in the runtime's own mount
// namespace, so F13's pod checks (mountsOffReason) have nothing to check;
// a helper that serves no mounts (no mount user) is refused at the call,
// by name (rootclient.Mounts.Ready).
func mountsOffFor(cfg config.Config) string {
	if cfg.PrivilegeMode == privmode.Split {
		return ""
	}
	return mountsOffReason(cfg)
}

// newMountManager is the service's mount manager: sandboxd's own in single
// mode, and in split mode one that sends every call to the root helper,
// which it learns of through the returned setter once the helper's client
// exists (the client hears refusals through the service, which takes the
// manager). The setter does nothing in single mode.
func newMountManager(cfg config.Config, logger *slog.Logger, off string) (*mounts.Manager, func(*rootclient.Client), error) {
	if cfg.PrivilegeMode != privmode.Split {
		m, err := mounts.New(logger, mounts.Config{
			RootDir:        cfg.MountsRootPath,
			CredDir:        cfg.MountsCredentialsRuntimeDir,
			WaitTimeout:    cfg.MountWaitTimeout,
			CgroupRoot:     cfg.HostProcessCgroupRoot(),
			RuntimePIDFile: cfg.MountsRuntimePIDFile,
			Unavailable:    off,
		})
		return m, func(*rootclient.Client) {}, err
	}
	var helper atomic.Pointer[rootclient.Client]
	m, err := mounts.NewRemote(logger, rootclient.Mounts{Client: helper.Load, Policy: cfg.MountToolPolicy()}, off)
	return m, func(c *rootclient.Client) { helper.Store(c) }, err
}

// newRootHelper is the agent's client of the helper in split mode, nil in
// single. It dials nothing until its first call (the lazy bootstrap,
// rootclient: an atomic latch and a single flight, like
// Service.EnsureLayer4Ready), and every refusal it is answered with is
// audited through the service (eng review D9).
func newRootHelper(cfg config.Config, svc *service.Service) *rootclient.Client {
	if cfg.PrivilegeMode != privmode.Split {
		return nil
	}
	c := rootHelperConfig(cfg)
	if svc != nil {
		c.OnRefusal = svc.RecordRootRefusal
	}
	return rootclient.New(c)
}

// rootHelperConfig is how sandboxd reaches the helper. The network calls
// get their own bound (PR 4 review): a namespace build queues behind a
// burst's others for seconds, and the two seconds of the connect and the
// handshake would fail most of a burst that single mode serves.
func rootHelperConfig(cfg config.Config) rootclient.Config {
	return rootclient.Config{Socket: cfg.RootdSocket, HelperUID: rootHelperUID,
		Timeout: rootclient.DefaultTimeout, NetworkTimeout: helperNetworkTimeout}
}

// helperNetworkTimeout bounds one network call to the helper whose caller
// set no deadline (the netns pool's refiller and the create path set none).
var helperNetworkTimeout = rootclient.DefaultNetworkTimeout

// rootHelperUID is the uid that must serve the helper's socket: root. Tests,
// whose own process serves it, set their uid.
var rootHelperUID uint32

// helperBootWait bounds how long sandboxd waits at start for the helper:
// the supervisor starts it beside sandboxd, and it may still be coming up.
// Past it the start fails, and the kubelet or systemd tries again.
var helperBootWait, helperBootRetry = time.Minute, time.Second

// hostNetwork is the helper's boot call (*rootclient.Client).
type hostNetwork interface {
	EnsureHostNetwork(ctx context.Context) (string, error)
}

// resolveSplitBridgeSubnet has the helper set the host up for sandbox
// networks (forwarding sysctls, its CNI config) and takes the sandboxes'
// range from it: the helper's CNI config is what hands addresses out now.
// It waits for a helper that is not up yet; a set SB_CONTAINERD_BRIDGE_SUBNET
// must name the same range.
func resolveSplitBridgeSubnet(ctx context.Context, cfg config.Config, h hostNetwork, logger *slog.Logger) (string, error) {
	deadline := time.Now().Add(helperBootWait)
	var subnet string
	for logged := false; ; logged = true {
		var err error
		if subnet, err = h.EnsureHostNetwork(ctx); err == nil {
			break
		}
		if !errors.Is(err, rootclient.ErrUnavailable) || time.Now().Add(helperBootRetry).After(deadline) {
			return "", fmt.Errorf("root helper: set the host up for sandbox networks: %w", err)
		}
		if !logged {
			logger.Warn("privilege mode split: waiting for the root helper", "socket", cfg.RootdSocket, "error", err, "for", helperBootWait)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(helperBootRetry):
		}
	}
	if want := cfg.ContainerdBridgeSubnet; want != "" && want != subnet {
		return "", fmt.Errorf("SB_CONTAINERD_BRIDGE_SUBNET is %s, but the root helper's CNI config hands out %s; "+
			"set the same range for both", want, subnet)
	}
	logger.Info("privilege mode split: the root helper does the network work", "socket", cfg.RootdSocket, "subnet", subnet)
	return subnet, nil
}

// netnsHelper is the helper's network calls the pool uses
// (*rootclient.Client).
type netnsHelper interface {
	RealizeNetns(ctx context.Context, name string) (string, string, error)
	RemoveNetns(ctx context.Context, name, ip string) error
	DisableNetnsIPv6(ctx context.Context, name string) error
	NetnsAddrs(ctx context.Context, name string) (bool, []string, error)
}

// helperNetnsHost is the netns pool's HostManager in split mode: each step
// one helper call, the namespace named by the same identity the in-process
// Host keys it by (netns.Slot.NetnsName). It also answers the pool's two
// optional steps, DisableIPv6 and IPv4Addrs, and its exists check.
//
// With the host firewall on (fw set, M1 PR 5), a cold create's build takes
// the create's rules with it (cntr.BuildRules): one PrepareSandbox for the
// namespace and the rules, so the address is never without them. And a
// release is one ReleaseSandbox: the address's rules go, then the
// namespace, in the helper, before CNI DEL frees the address.
type helperNetnsHost struct {
	h      netnsHelper
	fw     firewallHelper
	subnet netip.Prefix
	log    *slog.Logger
}

func newHelperNetnsHost(h netnsHelper, subnet string, log *slog.Logger) *helperNetnsHost {
	p, _ := netip.ParsePrefix(subnet)
	return &helperNetnsHost{h: h, subnet: p.Masked(), log: log}
}

// Realize answers a namespace the helper built, or leaves none behind
// (PR 4 review). A build the agent gave up on (its deadline, a cancel, a
// dropped answer) or that failed inside the helper may have left a part:
// a namespace, an address lease, the create's rules. The pool records
// nothing for a failed build, and a create's slot goes back to the free
// list under another name, so nothing would ever name it again; it is
// removed here, under the name it was built under. The helper takes that
// name's lock, so the removal runs only once the build has stopped. A
// build the helper never ran (refused, too old, at its limit of calls)
// has nothing to remove.
func (n *helperNetnsHost) Realize(ctx context.Context, slot netns.Slot) (string, string, error) {
	if strings.TrimSpace(slot.SandboxID) == "" {
		return "", "", errors.New("netns host: sandbox_id is required")
	}
	name := slot.NetnsName()
	path, ip, err := n.build(ctx, name)
	if err == nil || !mayHaveRun(err) {
		return path, ip, err
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), helperNetworkTimeout)
	defer cancel()
	// The address is the helper's to find, in the namespace: the build's
	// answer never came. Its rules, when the build carried some, go too.
	parts := []string{rootdpb.PartNetns}
	if n.fw != nil && cntr.BuildRulesFrom(ctx) != nil {
		parts = append(parts, rootdpb.PartFirewall)
	}
	if rerr := n.release(rctx, name, "", parts); rerr != nil {
		n.log.Warn("containerd netns build failed and its leftovers could not be removed; a create of the same sandbox ID clears them",
			"slot_id", slot.SlotID, "netns", name, "build_error", err, "error", rerr)
	}
	return "", "", err
}

// build is RealizeNetns, or PrepareSandbox with the create's rules when the
// create carries them (cntr.BuildRules): one call for both.
func (n *helperNetnsHost) build(ctx context.Context, name string) (string, string, error) {
	rules := cntr.BuildRulesFrom(ctx)
	if n.fw == nil || rules == nil {
		return n.h.RealizeNetns(ctx, name)
	}
	resp, err := n.fw.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: name,
		Parts:    []string{rootdpb.PartNetns, rootdpb.PartFirewall},
		Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: rules.BlockAll, AllowCidrs: rules.Allow, DenyCidrs: rules.Deny}})
	if err != nil {
		return "", "", err
	}
	rules.MarkApplied()
	return resp.GetNetnsPath(), resp.GetContainerIp(), nil
}

// release removes a slot: ReleaseSandbox with the firewall on, which
// clears the address's rules first; RemoveNetns otherwise.
func (n *helperNetnsHost) release(ctx context.Context, name, ip string, parts []string) error {
	if n.fw == nil {
		return n.h.RemoveNetns(ctx, name, ip)
	}
	return n.fw.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: name, ContainerIp: ip, Parts: parts})
}

// Remove sends the address the pool recorded only when it is a sandbox
// address in the range: the helper refuses any other, and a refusal is a
// security event, which a stale row (a backup from another machine) is
// not. Without it the helper still removes the namespace, its attachment
// and its lease; only that address's connection tracking (and rules, which
// an address outside the range never had) are left.
//
// An address the helper's CNI has since leased to another slot is that
// slot's now, with that slot's rules: the helper refuses to clear them, and
// the slot is removed without its address (a stale row again).
func (n *helperNetnsHost) Remove(ctx context.Context, slot netns.Slot) error {
	name := slot.NetnsName()
	if name == "" {
		return nil
	}
	ip := strings.TrimSpace(slot.ContainerIP)
	if ip != "" {
		if _, err := rootpolicy.CheckSandboxAddress(n.subnet, ip); err != nil {
			n.log.Warn("containerd netns teardown: the recorded address is not one of this node's sandbox addresses; not sending it to the root helper",
				"slot_id", slot.SlotID, "netns", name, "container_ip", ip, "subnet", n.subnet)
			ip = ""
		}
	}
	parts := []string{rootdpb.PartNetns, rootdpb.PartFirewall}
	err := n.release(ctx, name, ip, parts)
	if err != nil && n.fw != nil && ip != "" && isLeaseRefusal(err) {
		// The helper finds the slot's own address in its namespace.
		n.log.Warn("containerd netns teardown: the recorded address is another slot's now; releasing the slot by its own",
			"slot_id", slot.SlotID, "netns", name, "container_ip", ip)
		return n.release(ctx, name, "", parts)
	}
	return err
}

func (n *helperNetnsHost) DisableIPv6(ctx context.Context, slot netns.Slot) error {
	if strings.TrimSpace(slot.NetnsPath) == "" {
		return errors.New("netns host: slot has no netns path")
	}
	return n.h.DisableNetnsIPv6(ctx, slot.NetnsName())
}

func (n *helperNetnsHost) IPv4Addrs(ctx context.Context, slot netns.Slot) ([]string, error) {
	if strings.TrimSpace(slot.NetnsPath) == "" {
		return nil, errors.New("netns host: slot has no netns path")
	}
	_, addrs, err := n.h.NetnsAddrs(ctx, slot.NetnsName())
	return addrs, err
}

// exists is the pool's boot check of a recorded namespace path, asked of
// the helper: sandboxd cannot see the helper's netns folder. A helper that
// cannot answer keeps the slot: the address check that follows rebuilds a
// warm slot it cannot vouch for.
func (n *helperNetnsHost) exists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	ok, _, err := n.h.NetnsAddrs(context.Background(), filepath.Base(path))
	return ok || err != nil
}

// mayHaveRun: a failed helper call that the helper may have run, in part.
func mayHaveRun(err error) bool {
	var refused *rootclient.RefusedError
	return !errors.As(err, &refused) && !errors.Is(err, rootclient.ErrUnsupported) && !errors.Is(err, rootclient.ErrBusy)
}

// buildKitBuilderFor is the containerd engine's BuildKit builder. With
// SB_CONTAINERD_BUILDKIT_ROOTLESS (always so in privilege mode split,
// config refuses split without it) buildkitd is rootless and cannot reach
// containerd: each build comes back as an OCI archive the driver imports,
// through the root helper's gate in split mode, so sandboxd holds no
// root-level socket for builds (plan PR 10b, eng review D14). Otherwise it
// is today's root buildkitd, whose containerd worker writes the image.
func buildKitBuilderFor(cfg config.Config, driver *cntr.Driver, logger *slog.Logger) *cntr.BuildKitBuilder {
	build := cntr.NewBuildKitBuilder(cfg.ContainerdBuildKitAddr, "", logger).WithContextIDBase(cfg.ContainerdBuildContextIDBase)
	if cfg.ContainerdBuildKitRootless {
		build = build.WithArchiveImport(driver, cfg.ContainerdBuildMaxImageBytes)
	}
	return build
}

// volumeHelper is the helper's platform volume reclaim (*rootclient.Client).
type volumeHelper interface {
	ReclaimVolume(ctx context.Context, source string) error
}

// volumeReclaimerFor is the platform volume reclaimer: sandboxd's own in
// single mode. In split mode an NFS volume's files are the helper's to
// delete (a mount and a delete as root, of the helper's own export), and an
// S3 one's stay sandboxd's: the aws CLI needs no rights.
func volumeReclaimerFor(cfg config.Config, own service.VolumeReclaimer, helper *rootclient.Client) service.VolumeReclaimer {
	if cfg.PrivilegeMode != privmode.Split || helper == nil {
		return own
	}
	return splitReclaimer{own: own, helper: helper}
}

type splitReclaimer struct {
	own    service.VolumeReclaimer
	helper volumeHelper
}

func (r splitReclaimer) Reclaim(ctx context.Context, kind, source string) error {
	if kind == volumes.BackendNFS {
		return r.helper.ReclaimVolume(ctx, source)
	}
	return r.own.Reclaim(ctx, kind, source)
}

// imageBuilderFor is the image builder the API gets on the containerd
// engine, nil without one (a nil *cntr.ImageBuilder must not become a
// non-nil interface). Image reads, pushes and removals go through the
// driver's containerd client, which split mode points at the gate.
func imageBuilderFor(b *cntr.ImageBuilder) service.ImageBuilder {
	if b == nil {
		return nil
	}
	return b
}
