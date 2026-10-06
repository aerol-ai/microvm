package service

import (
	"errors"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ErrEgressGatewayUnavailable means the gateway could not attach the sandbox
// (unreachable, version skew, a failed nft write). The create rolls back and
// the API answers 503: a 2xx would claim a policy that is not live.
var ErrEgressGatewayUnavailable = errors.New("egress gateway unavailable")

// ErrEgressGatewayRequired means a policy needs the egress gateway (hostname
// entries or learn mode) and this node can't attach the sandbox to one.
var ErrEgressGatewayRequired = fmt.Errorf("hostname egress filtering needs the egress gateway on this node: %w", models.ErrRuntimeNotImplemented)

// compileCreateEgress validates a container create's egress fields with the
// shared grammar every runtime uses (plans/egress-domain-filtering.md §5.1,
// D4, D15): hostnames, *. wildcards and host:port allowed in allow lists, CIDRs
// only in deny lists, mixed lists with allow-wins precedence. A deny of the
// whole address space with no allow list is block-all, so it is folded into
// NetworkBlockAll and the lists are dropped (one blanket DROP, nothing to
// clean up twice). Every error matches egresspolicy.ErrInvalid and names the
// offending entry (400).
func compileCreateEgress(req *models.CreateSandboxRequest) (*egresspolicy.Policy, error) {
	return compileEgress(req, egresspolicy.MaxInlineHostnames)
}

// compileCreateEgressEffective compiles a create whose allow list may
// already hold its profiles' entries: with profiles, the list is the
// effective one, so it is held to the union cap (the inline part was held to
// the inline cap before the expansion).
func compileCreateEgressEffective(req *models.CreateSandboxRequest) (*egresspolicy.Policy, error) {
	if len(req.EgressProfiles) > 0 {
		return compileEgress(req, egresspolicy.MaxUnionHostnames)
	}
	return compileCreateEgress(req)
}

func compileEgress(req *models.CreateSandboxRequest, maxHostnames int) (*egresspolicy.Policy, error) {
	pol, err := egresspolicy.Compile(egresspolicy.Spec{
		AllowOut:     req.NetworkAllowOut,
		DenyOut:      req.NetworkDenyOut,
		BlockAll:     req.NetworkBlockAll,
		Mode:         egresspolicy.Mode(req.NetworkEgressMode),
		MaxHostnames: maxHostnames,
	})
	if err != nil {
		return nil, err
	}
	// The stored mode is "learn" or empty; "enforce" is the default spelled
	// out.
	if pol.Mode() == egresspolicy.ModeLearn {
		req.NetworkEgressMode = models.NetworkEgressModeLearn
		if len(req.EgressProfiles) > 0 {
			return nil, fmt.Errorf("%w: network_egress_mode %q can't be combined with egress_profiles", egresspolicy.ErrInvalid, egresspolicy.ModeLearn)
		}
	} else {
		req.NetworkEgressMode = ""
	}
	if req.NetworkBlockAll && len(req.EgressProfiles) > 0 {
		return nil, fmt.Errorf("%w: egress_profiles can't be combined with network_block_all", egresspolicy.ErrInvalid)
	}
	// With profiles the allow entries come from them, so a deny-all inline
	// list is the portable allowlist spelling, not block-all.
	if pol.BlockAll() && !req.NetworkBlockAll && len(req.EgressProfiles) == 0 {
		req.NetworkBlockAll = true
		req.NetworkAllowOut, req.NetworkDenyOut = nil, nil
	}
	return pol, nil
}
