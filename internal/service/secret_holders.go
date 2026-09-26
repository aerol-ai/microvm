package service

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/internal/store"
)

// SecretHolders is the operator-visible view of which nodes hold a sandbox's
// sealed cluster secret.
//
// It exists because every /v1/cluster/internal/* route is mTLS-gated and there
// is no list verb on the peer secret path, so an operator — or the integration
// suite, which authenticates with a PAT and has no client certificate — had no
// way to observe the recipient set at all. Fan-out, failover and reseal are
// all defined in terms of that set, so it could not be asserted from outside
// the cluster's own peer protocol.
//
// It deliberately carries NO ciphertext and no plaintext: only who holds a
// copy, at which generation, and what is still owed. Adding the payload here
// would turn an observability read into a second exfiltration path for the
// thing the whole subsystem exists to protect.
type SecretHolders struct {
	SandboxID     string `json:"sandbox_id"`
	IncarnationID string `json:"incarnation_id"`
	// Ref is the sealed row's address. Useful when correlating with audit
	// records, which reference secrets by ref rather than by sandbox.
	Ref string `json:"ref"`
	// Holders is the recipient set: the nodes that should hold a sealed copy.
	// Sorted so a caller can compare two reads without normalising.
	Holders []string `json:"holders"`
	// SealGeneration fences a reseal. Two reads with the same holders but
	// different generations mean a reseal happened in between, which is the
	// difference between "nothing changed" and "everything was rewritten".
	SealGeneration int64 `json:"seal_generation"`
	Version        int   `json:"version"`
	// PendingPut is the fan-out obligation: peers that have not yet
	// acknowledged a sealed copy. PendingDelete is the teardown obligation:
	// peers whose copy has not yet been removed. Without these a caller cannot
	// tell a converged fan-out from one still in flight, nor a completed
	// delete from one whose tombstones are still outstanding.
	PendingPut    []string `json:"pending_put,omitempty"`
	PendingDelete []string `json:"pending_delete,omitempty"`
}

// SecretHoldersForSandbox reports the recipient set for a sandbox's current
// incarnation.
//
// store.ErrNotFound (which the API maps to 404) distinguishes the two "no
// holders" cases that matter: an UNKNOWN sandbox 404s, while a known sandbox
// with no sealed secret returns an empty holder set. Collapsing them would
// make a test for "secrets were removed on delete" pass against a typo'd id.
func (s *Service) SecretHoldersForSandbox(ctx context.Context, sandboxID string) (*SecretHolders, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		// Defence in depth; the handler rejects this with 400 before calling.
		return nil, store.ErrNotFound
	}
	sandbox, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		return nil, err
	}

	rec, err := s.store.GetClusterSecretForSandboxIncarnation(ctx, sandbox.ID, sandbox.AuditIncarnationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The sandbox exists but holds no sealed secret. Reported as an
			// empty holder set rather than 404 so a caller can distinguish it
			// from an unknown sandbox, which the store.Get above already 404s.
			return &SecretHolders{
				SandboxID:     sandbox.ID,
				IncarnationID: sandbox.AuditIncarnationID,
				Holders:       []string{},
			}, nil
		}
		return nil, err
	}

	out := &SecretHolders{
		SandboxID:      sandbox.ID,
		IncarnationID:  sandbox.AuditIncarnationID,
		Ref:            rec.Ref,
		Holders:        sortedCopy(rec.Recipients),
		SealGeneration: rec.SealGeneration,
		Version:        rec.Version,
	}
	// The outbox lives in its own tables, not on the sealed row: GetClusterSecret
	// reads cluster_secrets alone and leaves the outbox fields zero. Reading
	// them separately is what makes "converged" distinguishable from "still
	// fanning out" — without it a caller asserting "all three nodes hold a
	// copy" is asserting against a moving target.
	if put, err := s.store.GetSecretPutOutboxForIncarnation(ctx, sandbox.ID, sandbox.AuditIncarnationID); err == nil && put != nil {
		out.PendingPut = sortedCopy(put.Recipients)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if del, err := s.store.GetSecretDeleteOutboxForIncarnation(ctx, sandbox.ID, sandbox.AuditIncarnationID); err == nil && del != nil {
		out.PendingDelete = sortedCopy(del.Recipients)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	return out, nil
}

// sortedCopy never returns nil for a non-nil input: an empty JSON array and a
// null are different things to a caller asserting "no holders left".
func sortedCopy(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
