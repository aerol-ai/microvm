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
	pol, err := egresspolicy.Compile(egresspolicy.Spec{
		AllowOut: req.NetworkAllowOut,
		DenyOut:  req.NetworkDenyOut,
		BlockAll: req.NetworkBlockAll,
	})
	if err != nil {
		return nil, err
	}
	if pol.BlockAll() && !req.NetworkBlockAll {
		req.NetworkBlockAll = true
		req.NetworkAllowOut, req.NetworkDenyOut = nil, nil
	}
	return pol, nil
}
