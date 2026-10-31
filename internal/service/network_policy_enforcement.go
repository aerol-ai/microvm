package service

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ErrNetworkPolicyUnenforced is a create, update or start that needs the host
// firewall on a node where it is off (501 network_policy_unenforced). On the
// docker, containerd and Firecracker runtimes block-all, the CIDR lists and
// the byte-cap blocks are host firewall rules, and hostname rules, profiles
// and learn mode rely on them too: the sandbox boots behind a block-all until
// the egress gateway attaches it, and a failed attach or apply holds it with
// a firewall DROP. With the firewall off (SB_ENABLE_NETWORK_RULES=false, or
// not a Linux host) every one of those is a silent no-op, so the policy would
// be stored, shown on GET, and not enforced. WASM and isolate filter egress in
// their own host-side mediator and are never refused.
var ErrNetworkPolicyUnenforced = errors.New("network policy refused: the host firewall is off on this node")

// unenforcedPolicyError names the refused fields and how to fix the node. It
// matches ErrNetworkPolicyUnenforced and, like every option a node can't
// honour, models.ErrRuntimeNotImplemented, so facades that only know the
// latter still answer 501.
type unenforcedPolicyError struct {
	runtime string
	fields  []string
}

func (e *unenforcedPolicyError) Error() string {
	return fmt.Sprintf("%s refused: runtime %q enforces it with the host firewall, which is off on this node "+
		"(SB_ENABLE_NETWORK_RULES=false, or not a Linux host). Turn on SB_ENABLE_NETWORK_RULES on a Linux host; "+
		"for local development only, SB_ALLOW_UNENFORCED_NETWORK_POLICY=true accepts it unenforced",
		strings.Join(e.fields, ", "), e.runtime)
}

func (e *unenforcedPolicyError) Unwrap() []error {
	return []error{ErrNetworkPolicyUnenforced, models.ErrRuntimeNotImplemented}
}

// netRulesEnabled reports whether rt's network policy is live. A driver that
// doesn't report is trusted: the three that use the host firewall (docker,
// containerd, Firecracker) assert NetRulesReporter at compile time, and
// WASM and isolate never reach here.
func netRulesEnabled(rt runtime.Runtime) bool {
	r, ok := rt.(runtime.NetRulesReporter)
	return !ok || r.NetRulesEnabled()
}

// firewallPolicyFields lists the fields of a create (or an update, written as
// one) that a host-firewall runtime enforces with firewall rules, by their
// wire names. Empty means the request asks for nothing the firewall does.
func firewallPolicyFields(req *models.CreateSandboxRequest) []string {
	var out []string
	if req.NetworkBlockAll {
		out = append(out, "network_block_all")
	}
	if len(req.NetworkAllowOut) > 0 {
		out = append(out, "network_allow_out")
	}
	if len(req.NetworkDenyOut) > 0 {
		out = append(out, "network_deny_out")
	}
	if len(req.EgressProfiles) > 0 {
		out = append(out, "egress_profiles")
	}
	if req.NetworkEgressMode != "" {
		out = append(out, "network_egress_mode")
	}
	if len(req.NetworkEgressRules) > 0 {
		out = append(out, "network_egress_rules")
	}
	if req.NetworkBytesInLimit > 0 {
		out = append(out, "network_bytes_in_limit")
	}
	if req.NetworkBytesOutLimit > 0 {
		out = append(out, "network_bytes_out_limit")
	}
	return out
}

// sandboxFirewallFields is firewallPolicyFields for a stored sandbox.
func sandboxFirewallFields(sb *models.Sandbox) []string {
	return firewallPolicyFields(&models.CreateSandboxRequest{
		NetworkBlockAll: sb.NetworkBlockAll, NetworkAllowOut: sb.NetworkAllowOut, NetworkDenyOut: sb.NetworkDenyOut,
		EgressProfiles: sb.EgressProfiles, NetworkEgressMode: sb.NetworkEgressMode, NetworkEgressRules: sb.NetworkEgressRules,
		NetworkBytesInLimit: sb.NetworkBytesInLimit, NetworkBytesOutLimit: sb.NetworkBytesOutLimit,
	})
}

// requireNetRules refuses fields that rt would leave unenforced. With the
// operator's SB_ALLOW_UNENFORCED_NETWORK_POLICY opt-in it accepts them and
// reports unenforced=true so the caller can warn once it knows the sandbox
// id. Two field reads and an interface assertion: no I/O.
func (s *Service) requireNetRules(rt runtime.Runtime, runtimeName string, fields []string) (unenforced bool, err error) {
	if len(fields) == 0 || models.RuntimeMediatesEgress(runtimeName) || netRulesEnabled(rt) {
		return false, nil
	}
	if s.cfg.AllowUnenforcedNetworkPolicy {
		return true, nil
	}
	return false, &unenforcedPolicyError{runtime: runtimeName, fields: fields}
}

// warnUnenforced is the per-sandbox warning for a policy accepted under the
// opt-in.
func (s *Service) warnUnenforced(sandboxID, runtimeName, op string, fields []string) {
	s.logger.Warn("network policy accepted but NOT enforced: the host firewall is off and SB_ALLOW_UNENFORCED_NETWORK_POLICY=true; this sandbox's traffic is not filtered",
		"sandbox_id", sandboxID, "runtime", runtimeName, "op", op, "fields", strings.Join(fields, ","))
}

// checkSandboxNetRules is requireNetRules for an existing sandbox (start,
// live policy and limit updates): it resolves the sandbox's runtime and warns
// under the opt-in. A runtime that can't be resolved is left to the caller,
// which fails on it anyway.
func (s *Service) checkSandboxNetRules(sb *models.Sandbox, op string, fields []string) error {
	if len(fields) == 0 || models.RuntimeMediatesEgress(sb.Runtime) {
		return nil
	}
	rt, err := s.runtimeForSandbox(sb)
	if err != nil {
		return nil
	}
	unenforced, err := s.requireNetRules(rt, sb.Runtime, fields)
	if unenforced {
		s.warnUnenforced(sb.ID, sb.Runtime, op, fields)
	}
	return err
}

// sandboxNetRulesOff reports whether a sandbox has an egress policy its
// runtime is not enforcing (GET's egress_status "unenforced").
func (s *Service) sandboxNetRulesOff(sb *models.Sandbox) bool {
	if models.RuntimeMediatesEgress(sb.Runtime) {
		return false
	}
	rt, err := s.runtimeForSandbox(sb)
	return err == nil && !netRulesEnabled(rt)
}
