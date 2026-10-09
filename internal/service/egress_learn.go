package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Learn mode (plans/egress-domain-filtering.md P2-7, CEO D2): a learn-mode
// sandbox has open egress and its runtime records what it reaches. One
// recorder implementation (egresspolicy.Recorder) serves every runtime, so
// identical traffic gives identical suggestions. Recordings are not
// replicated: a failover recreate starts a fresh one.

// GetNetworkLearned returns what a sandbox reached while in learn mode, and
// the allow list that would have allowed it. A recording stays readable
// after the sandbox switches to enforce, until it is destroyed.
func (s *Service) GetNetworkLearned(ctx context.Context, id string) (*models.NetworkLearned, error) {
	sb, err := s.scopedGet(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.isFirecrackerSandbox(sb) {
		return nil, unsupportedFirecrackerOption("egress learn mode")
	}
	switch {
	case s.isWasmSandbox(sb):
		return s.mediatedLearned(sb, s.wasm)
	case s.isIsolateSandbox(sb):
		return s.mediatedLearned(sb, s.isolate)
	}
	if !s.egressEnabled() {
		return nil, ErrEgressGatewayRequired
	}
	raw, err := s.egressGateway().Learned(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEgressGatewayUnavailable, err)
	}
	var l egresspolicy.Learned
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("decode learn recording: %w", err)
	}
	return learnedModel(sb.NetworkEgressMode, l), nil
}

// egressLearnReader is the WASM and isolate drivers' recording read: their
// mediators record learn-mode traffic themselves (one Recorder type, S7).
type egressLearnReader interface {
	EgressLearned(sandboxID string) (egresspolicy.Learned, error)
}

func (s *Service) mediatedLearned(sb *models.Sandbox, driver any) (*models.NetworkLearned, error) {
	reader, ok := driver.(egressLearnReader)
	if !ok {
		return nil, fmt.Errorf("%w: egress learn mode is not available for runtime %s", models.ErrRuntimeNotImplemented, sb.Runtime)
	}
	l, err := reader.EgressLearned(sb.ID)
	if err != nil {
		return nil, err
	}
	return learnedModel(sb.NetworkEgressMode, l), nil
}

func learnedModel(mode string, l egresspolicy.Learned) *models.NetworkLearned {
	out := &models.NetworkLearned{
		Mode:              egressModeName(mode),
		Truncated:         l.Truncated,
		Entries:           make([]models.NetworkLearnedEntry, 0, len(l.Entries)),
		CIDRs:             append([]string{}, l.CIDRs...),
		SuggestedAllowOut: append([]string{}, l.SuggestedAllowOut...),
	}
	for _, e := range l.Entries {
		out.Entries = append(out.Entries, models.NetworkLearnedEntry{
			Host: e.Host, Ports: append([]uint16{}, e.Ports...), FirstSeen: e.FirstSeen, LastSeen: e.LastSeen, Hits: e.Hits,
		})
	}
	if l.SuggestedProfile != nil {
		out.SuggestedProfile = &models.EgressProfileRequest{
			AllowOut:    append([]string{}, l.SuggestedProfile.AllowOut...),
			Description: l.SuggestedProfile.Description,
		}
	}
	return out
}

// forgetLearned drops a destroyed container sandbox's recording from the
// gateway. A recording outlives learn → enforce, so destroy is what ends it;
// best effort, since a gateway that is down has nothing live to drop and
// keeps at most a small file.
func (s *Service) forgetLearned(ctx context.Context, sb *models.Sandbox) {
	if !s.egressEnabled() || !models.RuntimeUsesEgressGateway(sb.Runtime) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, egressAttachTimeout)
	defer cancel()
	if err := s.egressGateway().ForgetLearned(ctx, sb.ID); err != nil {
		s.logger.Warn("egress: learn recording not dropped", "sandbox_id", sb.ID, "error", err)
	}
}
