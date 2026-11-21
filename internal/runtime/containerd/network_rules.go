package containerd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"sync/atomic"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// HostFirewall is the host firewall the driver keeps sandboxes' rules in:
// *netrules.Manager in privilege mode single, in this process, as before;
// the root helper in privilege mode split (pkg/daemon's helperFirewall),
// which renders the same rules from the same calls. The driver calls the
// same methods in the same order either way.
type HostFirewall interface {
	Enabled() bool
	BridgeSubnet() netip.Prefix
	BlockAllEgress(ip string) error
	BlockAllEgressReport(ip string) (bool, error)
	LiftBlockAllEgress(ip string) error
	ClearBlockAllEgress(ip string) error
	BlockAllIngress(ip string) error
	ClearBlockAllIngress(ip string) error
	ApplyEgressPolicy(ip string, allow, deny []string) error
	ClearEgressPolicy(ip string, allow, deny []string) error
	HoldEgress(ip string) error
	ClearHoldEgress(ip string) error
	SetNodeGuard(subnet netip.Prefix, allow []netrules.NodePort) error
	ReassertNodeGuard() (bool, error)
	SetFloor(subnet netip.Prefix, cidrs []netip.Prefix) error
	ReassertFloor() (bool, error)
}

var _ HostFirewall = (*netrules.Manager)(nil)

// CreateRules is what a HostFirewall may add for privilege mode split: a
// create's rules, and a teardown's clears, as one call each with the
// namespace's own (M1 PR 5, design note "one helper call per create").
type CreateRules interface {
	// ApplyCreateRules puts a create's rules on the address of the slot
	// named netns in one call: block-all, then the CIDR lists.
	ApplyCreateRules(ctx context.Context, netns, ip string, blockAll bool, allow, deny []string) error
	// FoldsIntoBuild says the namespace build of a cold create takes the
	// create's rules too (netns.WithCreateRules), so its address is never
	// without them, and no second call is made.
	FoldsIntoBuild() bool
	// ClearsOnRelease says the slot's release clears every rule its
	// address has, before the address is freed: the driver makes no clears
	// of its own before it.
	ClearsOnRelease() bool
}

// BuildRules are a cold create's rules, on the context of its namespace
// build when the firewall folds them into it (CreateRules.FoldsIntoBuild).
// The netns pool passes the context through untouched; the helper's
// namespace host (pkg/daemon) reads them, sends them with the build, and
// marks them applied. A build that did not (a warm claim, which builds
// nothing; a helper without the firewall part) leaves them unmarked, and
// the create applies them itself, after NewContainer, as in single mode.
type BuildRules struct {
	BlockAll    bool
	Allow, Deny []string
	applied     atomic.Bool
}

// MarkApplied records that the build put the rules on its address.
func (r *BuildRules) MarkApplied() { r.applied.Store(true) }

// Applied reports whether it did.
func (r *BuildRules) Applied() bool { return r != nil && r.applied.Load() }

type buildRulesKey struct{}

// BuildRulesFrom is the create's rules on a build's context, or nil.
func BuildRulesFrom(ctx context.Context) *BuildRules {
	r, _ := ctx.Value(buildRulesKey{}).(*BuildRules)
	return r
}

// ContextWithBuildRules puts r on a build's context.
func ContextWithBuildRules(ctx context.Context, r *BuildRules) context.Context {
	return context.WithValue(ctx, buildRulesKey{}, r)
}

// buildRulesFor puts a create's rules on the context of its namespace
// build, when the firewall takes them there; else ctx and nil.
func (d *Driver) buildRulesFor(ctx context.Context, req models.CreateSandboxRequest) (context.Context, *BuildRules) {
	cr := d.createRules()
	if cr == nil || !cr.FoldsIntoBuild() || !hasCreateNetRules(req) || !d.networkRules.Enabled() {
		return ctx, nil
	}
	r := &BuildRules{BlockAll: req.NetworkBlockAll, Allow: req.NetworkAllowOut, Deny: req.NetworkDenyOut}
	return ContextWithBuildRules(ctx, r), r
}

// SetHostFirewall replaces the host firewall: privilege mode split hands
// the driver the helper's. Call it before the first create.
func (d *Driver) SetHostFirewall(fw HostFirewall) { d.networkRules = fw }

// createRules is the firewall's CreateRules, or nil (single mode).
func (d *Driver) createRules() CreateRules {
	cr, _ := d.networkRules.(CreateRules)
	return cr
}

// clearsOnRelease: the slot's release clears the address's rules itself.
func (d *Driver) clearsOnRelease() bool {
	cr := d.createRules()
	return cr != nil && cr.ClearsOnRelease()
}

func (d *Driver) PushAllowedPorts(ctx context.Context, containerIP, toolboxToken string, ports []int) error {
	_ = ctx
	_ = toolboxToken
	_ = ports
	// Toolbox allowlist push is toolboxd-local today; docker path is best-effort HTTP.
	return nil
}

func (d *Driver) ClearNetworkRules(containerIP string) error {
	if d.networkRules == nil {
		return nil
	}
	_ = d.networkRules.ClearBlockAllEgress(containerIP)
	return d.networkRules.ClearBlockAllIngress(containerIP)
}

// hasCreateNetRules reports whether a create asks for host firewall rules.
func hasCreateNetRules(req models.CreateSandboxRequest) bool {
	return req.NetworkBlockAll || len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0
}

// applyCreateNetRules installs a create's rules on ip: block-all (which a
// hostname-filtered create arrives as, the gateway attach lifting it), or
// the CIDR lists. A create without either installs nothing. In split mode
// it is one call to the helper, for the slot at netnsPath.
func (d *Driver) applyCreateNetRules(ctx context.Context, netnsPath, ip string, req models.CreateSandboxRequest) error {
	if cr := d.createRules(); cr != nil {
		if !hasCreateNetRules(req) || !d.networkRules.Enabled() {
			return nil
		}
		if err := cr.ApplyCreateRules(ctx, path.Base(netnsPath), ip, req.NetworkBlockAll, req.NetworkAllowOut, req.NetworkDenyOut); err != nil {
			return fmt.Errorf("apply network rules: %w", err)
		}
		return nil
	}
	if req.NetworkBlockAll {
		if err := d.ApplyNetworkBlockAll(ip); err != nil {
			return fmt.Errorf("apply network block: %w", err)
		}
	}
	if len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0 {
		if err := d.ApplyEgressPolicy(ip, req.NetworkAllowOut, req.NetworkDenyOut); err != nil {
			return fmt.Errorf("apply egress policy: %w", err)
		}
	}
	return nil
}

// clearCreateNetRules removes what applyCreateNetRules may have installed
// on ip, a partial install included. Best effort, as Destroy's clears are.
func (d *Driver) clearCreateNetRules(ip string, req models.CreateSandboxRequest) {
	if !hasCreateNetRules(req) || d.clearsOnRelease() {
		return
	}
	_ = d.ClearNetworkRules(ip)
	if len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0 {
		_ = d.ClearEgressPolicy(ip, req.NetworkAllowOut, req.NetworkDenyOut)
	}
}

func (d *Driver) ApplyNetworkBlockAll(containerIP string) error {
	_, err := d.ApplyNetworkBlockAllReport(containerIP)
	return err
}

// ApplyNetworkBlockAllReport implements runtime.NetworkBlockReporter. See the
// docker client's copy for why reconcile needs the inserted flag.
func (d *Driver) ApplyNetworkBlockAllReport(containerIP string) (bool, error) {
	if d.networkRules == nil {
		return false, nil
	}
	return d.networkRules.BlockAllEgressReport(containerIP)
}

func (d *Driver) ApplyNetworkBlockIngress(containerIP string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.BlockAllIngress(containerIP)
}

func (d *Driver) ClearNetworkBlockIngress(containerIP string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.ClearBlockAllIngress(containerIP)
}

func (d *Driver) ClearNetworkBlockEgress(containerIP string) error {
	if d.networkRules == nil {
		return nil
	}
	// The sandbox keeps its address: lift, don't forget (netrules
	// LiftBlockAllEgress; on the block sets, one element add).
	return d.networkRules.LiftBlockAllEgress(containerIP)
}

func (d *Driver) ApplyEgressPolicy(containerIP string, allowCIDRs, denyCIDRs []string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.ApplyEgressPolicy(containerIP, allowCIDRs, denyCIDRs)
}

func (d *Driver) ClearEgressPolicy(containerIP string, allowCIDRs, denyCIDRs []string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.ClearEgressPolicy(containerIP, allowCIDRs, denyCIDRs)
}

var (
	_ sbruntime.EgressHolder     = (*Driver)(nil)
	_ sbruntime.NetRulesReporter = (*Driver)(nil)
)

// NetRulesEnabled reports whether the AEROLVM-USER rules are live. A nil or
// disabled manager (network rules off, or not Linux) makes every rule method
// here a no-op.
func (d *Driver) NetRulesEnabled() bool { return d.networkRules != nil && d.networkRules.Enabled() }

// ApplyEgressHold installs the fail-closed hold DROP (CEO D16).
func (d *Driver) ApplyEgressHold(containerIP string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.HoldEgress(containerIP)
}

// ClearEgressHold lifts the hold after a successful gateway attach.
func (d *Driver) ClearEgressHold(containerIP string) error {
	if d.networkRules == nil {
		return nil
	}
	return d.networkRules.ClearHoldEgress(containerIP)
}

var _ sbruntime.NodeGuardSetter = (*Driver)(nil)

// SetNodeGuard default-denies the CNI bridge subnet from the node itself,
// except allow (netrules ChainAerolvmNode).
func (d *Driver) SetNodeGuard(_ context.Context, allow []netrules.NodePort) error {
	if d.networkRules == nil || !d.networkRules.Enabled() {
		return sbruntime.ErrNodeGuardUnavailable
	}
	return d.networkRules.SetNodeGuard(d.networkRules.BridgeSubnet(), allow)
}

// ReassertNodeGuard puts the guard back if something removed it.
func (d *Driver) ReassertNodeGuard(context.Context) (bool, error) {
	if d.networkRules == nil {
		return false, nil
	}
	return d.networkRules.ReassertNodeGuard()
}

var _ sbruntime.EgressFloorSetter = (*Driver)(nil)

// SetEgressFloor installs the operator's node-wide deny floor for the CNI
// bridge subnet (§5.10 PC-2).
func (d *Driver) SetEgressFloor(_ context.Context, cidrs []netip.Prefix) error {
	if d.networkRules == nil || !d.networkRules.Enabled() {
		return sbruntime.ErrEgressFloorUnavailable
	}
	subnet := d.networkRules.BridgeSubnet()
	if !subnet.IsValid() {
		// SetFloor would install nothing and report success.
		return errors.New("containerd: egress floor needs the CNI bridge subnet")
	}
	return d.networkRules.SetFloor(subnet, cidrs)
}

// ReassertEgressFloor puts the floor back if something removed it.
func (d *Driver) ReassertEgressFloor(context.Context) (bool, error) {
	if d.networkRules == nil {
		return false, nil
	}
	return d.networkRules.ReassertFloor()
}
