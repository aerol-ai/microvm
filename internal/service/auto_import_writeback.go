package service

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// MarkImported is the spec write-back invoked by the AutoImportReconciler
// after a successful import. It flips the replicated spec's distribution
// mode to `aocr_imported` and points ImageRegistryRef at the new cluster-
// side ref so any future failover/recreate pulls from the cluster
// namespace (cluster PAT) instead of the original upstream.
//
// Best-effort by contract: a missing spec, a non-leader UpsertSpec
// rejection, or a Raft commit error all log+return without surfacing the
// failure. The bytes are already in AOCR; the original ref still resolves
// through the mirror; the next mutation will refresh the FSM. This is the
// AutoImportSpecMutator implementation referenced by the reconciler.
func (s *Service) MarkImported(ctx context.Context, sandboxID string, registryRef string) {
	if s == nil {
		return
	}
	registryRef = strings.TrimSpace(registryRef)
	if registryRef == "" {
		return
	}
	s.replicateSpecPatch(ctx, sandboxID, func(spec *models.CreateSandboxRequest) {
		spec.ImageDistributionMode = models.ImageDistributionAOCRImported
		spec.ImageRegistryRef = registryRef
	})
}
