package service

import (
	"context"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker/netstats"
	"github.com/aerol-ai/microvm/pkg/models"
)

type wasmNetworkByteCounter interface {
	DrainNetworkByteCounters() map[string]struct{ BytesIn, BytesOut int64 }
}

type wasmNetworkPolicySink interface {
	SetNetworkBlocks(sandboxID string, blockIngress, blockEgress bool)
}

func (s *Service) drainWasmNetworkCounters(ctx context.Context) {
	counter, ok := s.wasm.(wasmNetworkByteCounter)
	if !ok || counter == nil {
		return
	}
	deltas := counter.DrainNetworkByteCounters()
	if len(deltas) == 0 {
		return
	}
	now := time.Now().UTC()
	samples := make([]netstats.Sample, 0, len(deltas))
	for sandboxID, d := range deltas {
		if d.BytesIn == 0 && d.BytesOut == 0 {
			continue
		}
		samples = append(samples, netstats.Sample{
			SandboxID: sandboxID,
			BytesIn:   d.BytesIn,
			BytesOut:  d.BytesOut,
			SampledAt: now,
			ActiveTCP: false,
		})
	}
	if len(samples) == 0 {
		return
	}
	netstatsServiceSink{svc: s}.handleNetworkSamples(ctx, samples)
}

func (s *Service) syncWasmNetworkPolicy(ctx context.Context, sandbox *models.Sandbox, overIn, overOut bool) {
	if sandbox == nil || !s.isWasmSandbox(sandbox) {
		return
	}
	unlock := s.egressHoldLocks.lock(sandbox.ID)
	defer unlock()
	s.syncWasmBlocksLocked(ctx, sandbox, overIn, overOut)
}

// syncWasmBlocksLocked runs under the sandbox's hold lock, so it composes
// from a hold record no writer is changing.
func (s *Service) syncWasmBlocksLocked(ctx context.Context, sandbox *models.Sandbox, overIn, overOut bool) {
	sink, ok := s.wasm.(wasmNetworkPolicySink)
	if !ok || sink == nil {
		return
	}
	// Egress is shut for block-all, the quota, and any recorded hold: a
	// quota sample below the limit must not reopen a sandbox held for an
	// unresolved profile or an unapplied policy (review 2 finding 4), nor a
	// hold that couldn't be read (review 3 finding 7).
	held, _ := s.egressHeld(ctx, sandbox)
	blockIn := overIn || sandbox.NetworkBlockAll
	blockOut := overOut || sandbox.NetworkBlockAll || held
	sink.SetNetworkBlocks(sandbox.ID, blockIn, blockOut)
}
