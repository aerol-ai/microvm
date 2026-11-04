package service

import (
	"context"
	"errors"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// CheckNetworkPolicy answers "would a sandbox created with these egress
// fields reach this destination?" (plans/egress-domain-filtering.md P2-9,
// CEO D5) with the same matcher every enforcement point uses. It sees the
// policy a create would get: with no egress fields, the operator's default
// policy applies. A ceiling breach is reported in OutsideCeiling rather than
// refused, so a caller can see why a create would fail. Pure and read-only:
// no sandbox, no I/O.
func (s *Service) CheckNetworkPolicy(ctx context.Context, req models.NetworkPolicyCheckRequest) (*models.NetworkPolicyCheckResponse, error) {
	create := models.CreateSandboxRequest{
		NetworkBlockAll: req.NetworkBlockAll,
		NetworkAllowOut: req.NetworkAllowOut,
		NetworkDenyOut:  req.NetworkDenyOut,
	}
	op := s.egressOperator()
	s.NormalizeCreateEgressDefault(&create)
	// The default's org profiles are references; check their entries.
	if len(create.EgressProfiles) > 0 {
		r, err := s.resolveEgressProfiles(ctx, "", create.NetworkAllowOut, create.EgressProfiles)
		if err != nil {
			return nil, err
		}
		create.NetworkAllowOut = r.Effective
	}
	pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: create.NetworkAllowOut, DenyOut: create.NetworkDenyOut, BlockAll: create.NetworkBlockAll})
	if err != nil {
		return nil, err
	}
	res, err := egresspolicy.Check(pol, req.Destination)
	if err != nil {
		return nil, err
	}
	out := &models.NetworkPolicyCheckResponse{Allowed: res.Allowed, MatchedRule: res.MatchedRule, DefaultVerdict: string(res.DefaultVerdict)}
	if c := op.Ceiling(); c != nil {
		var ce *egresspolicy.CeilingError
		if err := c.Fits(pol); errors.As(err, &ce) {
			out.OutsideCeiling = ce.Entry
			if out.OutsideCeiling == "" {
				out.OutsideCeiling = ce.Reason
			}
		}
	}
	return out, nil
}
