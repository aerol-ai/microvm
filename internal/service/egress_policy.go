package service

import (
	"fmt"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

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
