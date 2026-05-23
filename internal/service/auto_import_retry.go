package service

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/aerol-ai/microvm/pkg/models"
)

// AutoImportPendingStore is the narrow store surface the reconciler needs.
// Pulled out as an interface so the reconciler can be tested without
// instantiating a full SQLite store — and so future store backends can
// satisfy it without growing the reconciler's dependency surface.
type AutoImportPendingStore interface {
	ListAutoImportPendingIDs(ctx context.Context) ([]string, error)
	Get(ctx context.Context, id string) (*models.Sandbox, error)
	SetAutoImportPending(ctx context.Context, id string, pending bool) error
}

// AutoImportSpecResolver lets the reconciler look up the replicated
// CreateSandboxRequest that owns a given sandbox. The reconciler needs
// this because the spec carries the original upstream ref + the failover
// policy (the gate for whether import should happen at all), but the
// sandbox row only carries the runtime view. In standalone mode this is
// backed by an in-memory map; in cluster mode by the Raft FSM.
//
// Returns nil, false when no replicated spec exists — the reconciler
// treats that as "drop the flag, nothing to retry" rather than as an
// error, since a sandbox without a spec cannot meaningfully be recreated
// elsewhere anyway.
type AutoImportSpecResolver interface {
	GetSandboxSpec(sandboxID string) (*models.CreateSandboxRequest, bool)
}

// AutoImportSpecMutator is the optional write-back hook. After a successful
// import, the reconciler calls MarkImported so the replicated spec carries
// the new cluster registry ref and `aocr_imported` distribution mode. Future
// failovers then pull from the cluster namespace with the cluster PAT, fully
// decoupled from the original upstream credential.
//
// Implementations must be safe to call on a non-leader node: the leader-
// forwarding lives below this surface (cluster.UpsertSpec proposes through
// the Raft FSM regardless of caller node). Errors are absorbed inside the
// implementation — the reconciler always treats import success as a clean
// retryOutcome even if the mutator can't reach the leader, because the
// imported bytes are already in AOCR.
//
// A nil mutator disables write-through cleanly; the reconciler logs the new
// ref and moves on. This is the standalone-mode default.
type AutoImportSpecMutator interface {
	MarkImported(ctx context.Context, sandboxID string, registryRef string)
}

// AutoImportReconciler walks the rows the post-pull path flagged
// `auto_import_pending = true` and re-tries them. One ticker per node;
// fan-out inside a single tick is capped to keep a recovery storm from
// saturating the local Docker daemon or AOCR.
//
// The reconciler does not own a goroutine — `RunOnce` is the unit of
// work, and a thin wrapper in main.go schedules it on a ticker. That
// keeps the type fully testable (table-driven, no time.Tick) and lets
// the operator trigger an immediate retry from a debug endpoint if
// they want.
type AutoImportReconciler struct {
	importer    *AutoImporter
	store       AutoImportPendingStore
	specs       AutoImportSpecResolver
	mutator     AutoImportSpecMutator
	logger      *slog.Logger
	maxInFlight int
}

// SetSpecMutator installs the optional write-back hook. Calling again
// replaces the previous one; pass nil to disable. Separated from the
// constructor so existing call sites (and tests) keep working unchanged —
// the mutator is a strict upgrade, not a required dependency.
func (r *AutoImportReconciler) SetSpecMutator(m AutoImportSpecMutator) {
	if r == nil {
		return
	}
	r.mutator = m
}

// NewAutoImportReconciler builds the reconciler. Returns nil if the
// importer is nil (auto-import disabled) so callers can `if r == nil
// { return }` cheaply. maxInFlight clamps fan-out per tick; pass 0 for
// the safe default (4).
func NewAutoImportReconciler(importer *AutoImporter, store AutoImportPendingStore, specs AutoImportSpecResolver, logger *slog.Logger, maxInFlight int) *AutoImportReconciler {
	if importer == nil || store == nil || specs == nil {
		return nil
	}
	if maxInFlight <= 0 {
		maxInFlight = 4
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &AutoImportReconciler{
		importer:    importer,
		store:       store,
		specs:       specs,
		logger:      logger,
		maxInFlight: maxInFlight,
	}
}

// AutoImportReconcileStats is what RunOnce reports back. Used by tests
// and by the metrics-collection wrapper in main.go.
type AutoImportReconcileStats struct {
	Scanned   int
	Succeeded int
	Failed    int
	Skipped   int
}

// RunOnce processes one sweep of the auto-import pending queue. Blocks
// until all per-sandbox attempts have returned (success, failure, or
// context cancel). The bounded semaphore caps in-flight HTTP calls;
// the AOCR side is happy with the load but the local Docker network
// stack is not infinitely parallel.
func (r *AutoImportReconciler) RunOnce(ctx context.Context) (AutoImportReconcileStats, error) {
	if r == nil {
		return AutoImportReconcileStats{}, nil
	}
	ids, err := r.store.ListAutoImportPendingIDs(ctx)
	if err != nil {
		return AutoImportReconcileStats{}, err
	}
	stats := AutoImportReconcileStats{Scanned: len(ids)}
	if len(ids) == 0 {
		return stats, nil
	}

	sem := make(chan struct{}, r.maxInFlight)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()

			outcome := r.retryOne(ctx, id)
			mu.Lock()
			switch outcome {
			case retrySucceeded:
				stats.Succeeded++
			case retryFailed:
				stats.Failed++
			case retrySkipped:
				stats.Skipped++
			}
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return stats, nil
}

type retryOutcome int

const (
	retrySucceeded retryOutcome = iota
	retryFailed
	retrySkipped
)

// retryOne re-imports a single sandbox. Errors are logged and turned into
// `retryFailed` (the row stays pending for the next tick); they are not
// propagated up because one bad sandbox should not abort the whole sweep.
// The retry is best-effort by design — the cluster failover path will
// fall back to F17 wrap-creds if the import never succeeds.
func (r *AutoImportReconciler) retryOne(ctx context.Context, sandboxID string) retryOutcome {
	sandbox, err := r.store.Get(ctx, sandboxID)
	if err != nil {
		// Sandbox was deleted between the scan and the retry — drop the
		// flag is not possible (the row is gone), so treat as skip.
		r.logger.Debug("auto-import retry: sandbox vanished",
			"sandbox_id", sandboxID, "error", err)
		return retrySkipped
	}
	if !sandbox.AutoImportPending {
		// Concurrent reconcile (or operator-cleared) won the race. Nothing
		// to do — the index scan saw it but it's no longer pending.
		return retrySkipped
	}

	spec, ok := r.specs.GetSandboxSpec(sandboxID)
	if !ok || spec == nil {
		// No replicated spec → no useful import. Clear the flag so we
		// don't keep scanning this row forever; recreate is already
		// impossible without a spec.
		if err := r.store.SetAutoImportPending(ctx, sandboxID, false); err != nil {
			r.logger.Warn("auto-import retry: drop pending flag failed",
				"sandbox_id", sandboxID, "error", err)
		}
		return retrySkipped
	}

	req, ok := autoImportRequestFromSpec(spec)
	if !ok {
		// Spec no longer eligible (e.g. failover policy was patched to
		// "none" after the import was scheduled). Drop the flag.
		if err := r.store.SetAutoImportPending(ctx, sandboxID, false); err != nil {
			r.logger.Warn("auto-import retry: drop pending flag failed",
				"sandbox_id", sandboxID, "error", err)
		}
		return retrySkipped
	}

	result, err := r.importer.Import(ctx, req)
	if err != nil {
		r.logger.Warn("auto-import retry: import call failed",
			"sandbox_id", sandboxID, "upstream", req.UpstreamHost+"/"+req.UpstreamRepo, "error", err)
		return retryFailed
	}

	// Import succeeded — clear the flag, then (best-effort) propose the
	// spec mutation through the cluster. The spec write-through goes via
	// the leader regardless of which node we're on; failures are absorbed
	// by the mutator since the bytes are already in AOCR and future
	// pulls of the original ref still resolve cleanly through the mirror.
	if err := r.store.SetAutoImportPending(ctx, sandboxID, false); err != nil {
		r.logger.Warn("auto-import retry: succeeded but flag clear failed",
			"sandbox_id", sandboxID, "ref", result.RegistryRef, "error", err)
		return retryFailed
	}
	if r.mutator != nil {
		r.mutator.MarkImported(ctx, sandboxID, result.RegistryRef)
	}
	r.logger.Info("auto-import retry: succeeded",
		"sandbox_id", sandboxID, "registry_ref", result.RegistryRef,
		"already_present", result.AlreadyPresent)
	return retrySucceeded
}

// autoImportRequestFromSpec extracts the upstream coordinates from a
// replicated create-spec. Returns ok=false when the spec is no longer
// eligible (no failover, no upstream digest, mode is already
// `aocr_imported`, etc.) so the reconciler can clear the flag without
// firing a doomed retry.
func autoImportRequestFromSpec(spec *models.CreateSandboxRequest) (AutoImportRequest, bool) {
	if spec == nil {
		return AutoImportRequest{}, false
	}
	if spec.Failover == nil || !spec.Failover.ShouldRecreate() {
		return AutoImportRequest{}, false
	}
	if spec.ImageDistributionMode == models.ImageDistributionAOCRImported {
		// Already imported — nothing to do.
		return AutoImportRequest{}, false
	}
	// We need the digest to do a deterministic mount-from-repo. Without
	// it the import is non-idempotent and a tag race could overwrite the
	// wrong manifest.
	if spec.ImageDigest == "" {
		return AutoImportRequest{}, false
	}
	host, repo, tag := parseUpstreamFromRegistryRef(spec.ImageRegistryRef, spec.Image)
	if host == "" || repo == "" {
		return AutoImportRequest{}, false
	}
	return AutoImportRequest{
		UpstreamHost:   host,
		UpstreamRepo:   repo,
		UpstreamTag:    tag,
		UpstreamDigest: spec.ImageDigest,
	}, true
}

// parseUpstreamFromRegistryRef splits a `host/repo[:tag]` reference into
// its components. Prefers the explicit ImageRegistryRef (set during pull
// classification) and falls back to the user-supplied Image string. Tag
// is optional — the digest is what makes the import authoritative.
//
// This deliberately does NOT understand AOCR mirror-prefix rewriting
// (`mirror.aocr.aerol.ai/aocr/ghcr/...`): the AutoImport path runs against
// the *original* upstream ref, not the mirror-rewritten one. The mirror
// rewrite is a pull-time concern only.
func parseUpstreamFromRegistryRef(registryRef, image string) (host, repo, tag string) {
	pick := registryRef
	if pick == "" {
		pick = image
	}
	first, rest, ok := splitOnce(pick, "/")
	if !ok {
		return "", "", ""
	}
	// Same host detection as docker.splitHostRepo — must contain `.`/`:`
	// or be `localhost`. Bare names like `library/redis` are docker.io
	// and have no upstream host.
	if first != "localhost" && !containsAny(first, ".:") {
		return "", "", ""
	}
	host = first
	repo = rest
	if at := lastIndexByte(repo, ':'); at >= 0 {
		// Only treat as tag if the colon is after the last slash —
		// otherwise it's part of a port we already split.
		if lastIndexByte(repo, '/') < at {
			tag = repo[at+1:]
			repo = repo[:at]
		}
	}
	return host, repo, tag
}

// Trivial string helpers kept local to avoid pulling pkg/docker into the
// service package just for substring math.
func splitOnce(s, sep string) (a, b string, ok bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}

func containsAny(s, chars string) bool {
	for i := 0; i < len(s); i++ {
		for j := 0; j < len(chars); j++ {
			if s[i] == chars[j] {
				return true
			}
		}
	}
	return false
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// AutoImportDisabledError is returned by callsites that want to distinguish
// "feature off" from "feature on, but failed". main() can switch on it to
// suppress alerts.
var AutoImportDisabledError = errors.New("auto-import disabled")
