package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// replicateSpecPatch keeps the FSM-replicated spec in sync after a local
// mutation (resize, lifecycle update). It is a best-effort write-through that
// mirrors the v1 wrapper of the same name: on failure it warns and returns
// without surfacing the error to the caller, because the local sandbox is
// already authoritative and the next mutation will refresh the FSM.
//
// No-op when the cluster doesn't carry a spec for this sandbox yet
// (pre-cluster sandbox; Noop client in single-node mode also returns nil).
// Same-sandbox concurrent mutations can clobber each other in the FSM, but
// the worst case is a stale spec on a node that hasn't died — the next
// mutating call fixes it. Single-sandbox mutations serialize at the docker
// layer anyway.
func (s *Service) replicateSpecPatch(ctx context.Context, id string, patch func(*models.CreateSandboxRequest)) {
	c := s.Cluster()
	if c == nil {
		return
	}
	spec := c.SpecOf(id)
	if spec == nil {
		return
	}
	patch(spec)
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.UpsertSpec(commitCtx, id, spec, cluster.PlacementSecrets{}); err != nil && s.logger != nil {
		s.logger.Warn("cluster: spec write-through failed; FSM spec stale until next mutation",
			"sandbox_id", id, "err", err)
	}
}

// provider returns the provider installed by New or ConfigureSecretProvider.
func (s *Service) provider() secrets.Provider {
	if s == nil {
		return nil
	}
	return s.secretProvider
}

// secretsFromRequest extracts the credential-bearing portions of req into the
// Provider Secrets bag. MountCreds is keyed by MountSpec.Target.
func secretsFromRequest(req models.CreateSandboxRequest) secrets.Secrets {
	var bag secrets.Secrets
	if req.Registry != nil && req.Registry.Password != "" {
		regCopy := *req.Registry
		bag.Registry = &regCopy
	}
	for _, m := range req.Mounts {
		if len(m.Credentials) == 0 {
			continue
		}
		if bag.MountCreds == nil {
			bag.MountCreds = make(map[string]map[string]string, len(req.Mounts))
		}
		cp := make(map[string]string, len(m.Credentials))
		for k, v := range m.Credentials {
			cp[k] = v
		}
		bag.MountCreds[m.Target] = cp
	}
	if len(req.Env) > 0 {
		env := make(map[string]string, len(req.Env))
		for k, v := range req.Env {
			env[k] = v
		}
		bag.Env = env
	}
	return bag
}

// OpenClusterSecretsForNode resolves a replicated secret handle and merges the
// decrypted credentials back into a redacted spec. The handle (Ref/Version)
// is the only carrier — placements never embed sealed bytes.
//
// sandboxID is preferred for the audit event; when empty it is parsed from the
// incarnation-scoped placement ref. Every open is fenced to that placement
// lifetime before the provider can resolve retained ciphertext.
func (s *Service) OpenClusterSecretsForNode(ctx context.Context, sandboxID string, redacted models.CreateSandboxRequest, placement cluster.PlacementSecrets, nodeID string) (out models.CreateSandboxRequest, err error) {
	if placement.Ref == "" {
		return redacted, nil
	}
	sandboxID = strings.TrimSpace(sandboxID)
	parsed, parseErr := secrets.ParseRef(placement.Ref)
	if sandboxID == "" && parseErr == nil {
		sandboxID = parsed.SandboxID
	}
	actor := nodeID
	if actor == "" {
		actor = s.auditActor()
	}
	placementIncarnationID := strings.TrimSpace(placement.IncarnationID)
	auditIncarnationID := placementIncarnationID
	if auditIncarnationID == "" && parseErr == nil {
		auditIncarnationID = parsed.IncarnationID
	}
	_, auditOwnerRef := s.auditIdentityFor(sandboxID)
	done := beginSecretAuditOwned(s.secretAuditSink(), sandboxID, placement.Ref, actor, correlationIDFromContext(ctx), auditIncarnationID, auditOwnerRef)
	defer func() { done(err) }()
	if parseErr != nil || placement.Version != secrets.RefVersion || placement.SealGeneration <= 0 || placementIncarnationID == "" ||
		parsed.SandboxID != sandboxID || parsed.IncarnationID != placementIncarnationID || parsed.Version != placement.Version {
		recordClusterSecretKeyMismatch()
		return redacted, fmt.Errorf("%w: placement secret handle does not match the current sandbox lifecycle", secrets.ErrVersionMismatch)
	}
	p := s.provider()
	if p == nil {
		return redacted, errors.New("cluster secret store is not configured")
	}
	bag, openErr := p.Open(ctx, sandboxID, secrets.Handle{
		Ref: placement.Ref, Version: placement.Version, SealGeneration: placement.SealGeneration,
	}, nodeID)
	if openErr != nil && errors.Is(openErr, secrets.ErrVersionMismatch) {
		if staged, ok := s.stagedResealTakeoverHandle(ctx, sandboxID, placement, nodeID); ok {
			if s.logger != nil {
				s.logger.Warn("cluster: opening staged reseal generation for takeover; Raft still publishes the older generation",
					"sandbox_id", sandboxID, "placement_generation", placement.SealGeneration, "local_generation", staged.SealGeneration)
			}
			bag, openErr = p.Open(ctx, sandboxID, staged, nodeID)
		}
	}
	if openErr != nil {
		if errors.Is(openErr, secrets.ErrVersionMismatch) {
			recordClusterSecretKeyMismatch()
		}
		// Include the ref when the provider didn't — operators need a log-safe
		// handle on decrypt failures (E1a); never plaintext.
		if placement.Ref != "" && !strings.Contains(openErr.Error(), placement.Ref) {
			return redacted, fmt.Errorf("%w (ref %q)", openErr, placement.Ref)
		}
		return redacted, openErr
	}
	return mergeClusterSecrets(redacted, bag), nil
}

// stagedResealTakeoverHandle returns the handle for a strictly newer local
// generation of the exact lifecycle the placement names, when this node is a
// recipient of it. A reseal stages G+1 on its replacement recipients before
// the Raft CAS; a replacement that was already a backup holds one row per
// ref, so the staged PUT overwrites its committed G copy. If the owner dies
// before the CAS, Raft keeps handing out G and the only surviving copies are
// the staged ones — refusing them strands failover while the plaintext (the
// same bag, resealed to a new recipient set) sits on disk. Once this node is
// the owner, expandAndResealDeadSecretTargets finalizes the interrupted
// promotion so Raft catches up with the store.
func (s *Service) stagedResealTakeoverHandle(ctx context.Context, sandboxID string, placement cluster.PlacementSecrets, nodeID string) (secrets.Handle, bool) {
	if s == nil || !s.cfg.EnableCluster || s.store == nil || placement.SealGeneration <= 0 {
		return secrets.Handle{}, false
	}
	rec, err := s.store.GetClusterSecret(ctx, placement.Ref)
	if err != nil || rec == nil || rec.SandboxID != sandboxID || rec.Version != placement.Version ||
		rec.SealGeneration <= placement.SealGeneration || !secrets.RecipientAllowed(rec.Recipients, nodeID) {
		return secrets.Handle{}, false
	}
	parsed, parseErr := secrets.ParseRef(rec.Ref)
	if parseErr != nil || parsed.IncarnationID != strings.TrimSpace(placement.IncarnationID) {
		return secrets.Handle{}, false
	}
	return secrets.Handle{Ref: rec.Ref, Version: rec.Version, SealGeneration: rec.SealGeneration}, true
}

func (s *Service) DeleteClusterSecrets(ctx context.Context, sandboxID, incarnationID string) error {
	if s == nil {
		return nil
	}
	sandboxID = strings.TrimSpace(sandboxID)
	incarnationID = strings.TrimSpace(incarnationID)
	if sandboxID == "" || incarnationID == "" {
		return errors.New("cluster secret delete requires sandbox_id and incarnation_id")
	}
	unlock := lockSecretSandboxOps(sandboxID)
	defer unlock()
	recipients, err := s.secretRecipientsForDelete(ctx, sandboxID, incarnationID)
	if err != nil {
		return fmt.Errorf("resolve cluster secret recipients before delete: %w", err)
	}
	err = s.deleteClusterSecretsOriginator(ctx, sandboxID, incarnationID, recipients)
	if err == nil {
		s.maybeAsyncDeleteFanout(sandboxID, incarnationID)
	}
	return err
}

// DeleteClusterSecretsForAuthoritativePlacement is the rollback finalizer for
// a failed reserved/promote create that may not have persisted a sandbox row.
// It retains the placement until this exact lifecycle has been tombed and its
// remote cleanup journal is durable.
func (s *Service) DeleteClusterSecretsForAuthoritativePlacement(ctx context.Context, sandboxID string) error {
	if s == nil {
		return nil
	}
	sandboxID = strings.TrimSpace(sandboxID)
	c := s.Cluster()
	if sandboxID == "" || c == nil {
		return errors.New("authoritative cluster placement is unavailable for secret cleanup")
	}
	placements, err := c.AuthoritativePlacementsByIDs(ctx, []string{sandboxID})
	if err != nil {
		return fmt.Errorf("authoritative placement read before secret cleanup: %w", err)
	}
	placement, ok := placements[sandboxID]
	if !ok || placement.SandboxID != sandboxID {
		return errors.New("authoritative placement disappeared before secret cleanup")
	}
	incarnationID := strings.TrimSpace(placement.IncarnationID)
	if incarnationID == "" {
		return errors.New("authoritative placement incarnation_id is required for secret cleanup")
	}
	unlock := lockSecretSandboxOps(sandboxID)
	defer unlock()
	recipients := secrets.NormalizeRecipients(placement.SecretRecipients)
	err = s.deleteClusterSecretsOriginator(ctx, sandboxID, incarnationID, recipients)
	if err == nil {
		s.maybeAsyncDeleteFanout(sandboxID, incarnationID)
	}
	return err
}

// secretRecipientsForDelete resolves the exact locally retained lifecycle,
// falling back to its durable PUT outbox when the ciphertext row is already
// gone. Destruction must not turn a failed local read into an empty set: doing
// so can skip the remote cleanup journal and permanently strand ciphertext.
func (s *Service) secretRecipientsForDelete(ctx context.Context, sandboxID, incarnationID string) ([]string, error) {
	if s == nil {
		return nil, nil
	}
	if s.store == nil {
		return nil, nil
	}
	sandboxID = strings.TrimSpace(sandboxID)
	incarnationID = strings.TrimSpace(incarnationID)
	if sandboxID == "" || incarnationID == "" {
		return nil, errors.New("local sandbox secret identity is required")
	}
	rec, err := s.store.GetClusterSecretForSandboxIncarnation(ctx, sandboxID, incarnationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if put, putErr := s.store.GetSecretPutOutboxForIncarnation(ctx, sandboxID, incarnationID); putErr != nil {
				return nil, putErr
			} else if put != nil {
				return secrets.NormalizeRecipients(put.Recipients), nil
			}
			return s.secretRecipientsFromExactPlacement(ctx, sandboxID, incarnationID)
		}
		return nil, err
	}
	if rec == nil {
		return s.secretRecipientsFromExactPlacement(ctx, sandboxID, incarnationID)
	}
	parsed, parseErr := secrets.ParseRef(rec.Ref)
	if parseErr != nil || parsed.SandboxID != strings.TrimSpace(sandboxID) || parsed.IncarnationID == "" {
		return nil, errors.New("stored cluster secret has an invalid current-format identity")
	}
	return secrets.NormalizeRecipients(rec.Recipients), nil
}

// secretRecipientsFromExactPlacement is the final no-vacuum source when a
// local ciphertext/PUT row was already removed but the authoritative
// lifecycle still exists. A different incarnation is never consulted: it may
// be a replacement reusing the same sandbox ID. Placement lookup failure is
// fail-closed, while a genuinely absent placement is compatible with retrying
// after an earlier successful placement removal.
func (s *Service) secretRecipientsFromExactPlacement(ctx context.Context, sandboxID, incarnationID string) ([]string, error) {
	if s == nil || !s.cfg.EnableCluster {
		return nil, nil
	}
	placements, err := s.authoritativeSecretPlacements(ctx, []string{sandboxID})
	if err != nil {
		return nil, err
	}
	placement, ok := placements[sandboxID]
	if !ok || strings.TrimSpace(placement.IncarnationID) != incarnationID {
		return nil, nil
	}
	return secrets.NormalizeRecipients(placement.SecretRecipients), nil
}

// deleteClusterSecretsOriginator tombs, deletes local rows, and enqueues the
// peer-delete outbox in one SQLite transaction when fan-out is enabled and
// there is at least one non-self recipient. Standalone destroys must not leave
// forever-pending outbox rows or permanent tombs.
func (s *Service) deleteClusterSecretsOriginator(ctx context.Context, sandboxID, incarnationID string, recipients []string) error {
	if s == nil {
		return nil
	}
	clearSecretFanoutHoldersForIncarnation(sandboxID, incarnationID)
	var peers []string
	if len(recipients) > 0 {
		// Avoid SelfNodeID() when there is nothing to filter — rollback/test
		// stubs may panic on identity lookup during seal-failure retract.
		peers = nonSelfRecipients(recipients, s.selfNodeID())
	}
	if s.store != nil && len(peers) > 0 {
		_, err := s.store.DeleteClusterSecretsOriginatorWithOutbox(ctx, sandboxID, incarnationID, peers)
		return err
	}
	if p := s.provider(); p != nil {
		return p.Delete(secrets.ContextWithIncarnationID(ctx, incarnationID), sandboxID)
	}
	if s.store != nil {
		return s.store.DeleteClusterSecretRowsForIncarnation(ctx, sandboxID, incarnationID)
	}
	return nil
}

// DeleteClusterSecretsLocal applies an authenticated peer DELETE with
// generation gating and a local tombstone so delayed PUTs cannot resurrect
// deleted credentials. In cluster mode the mTLS peer must be either the
// authoritative owner or a recipient recorded on this exact local ciphertext
// lifecycle. Standalone callers retain the local-only behavior.
func (s *Service) DeleteClusterSecretsLocal(ctx context.Context, sandboxID, incarnationID string, generation int64, peerNodeID string) error {
	if s == nil {
		return nil
	}
	unlock := lockSecretSandboxOps(sandboxID)
	defer unlock()
	incarnationID = strings.TrimSpace(incarnationID)
	if incarnationID == "" {
		return errors.New("peer secret delete incarnation_id is required")
	}
	alreadyApplied, err := s.authorizePeerSecretDelete(ctx, sandboxID, incarnationID, generation, peerNodeID)
	if err != nil {
		return err
	}
	if alreadyApplied {
		// Acknowledge without touching state: the originator's durable outbox
		// only needs the ACK it lost, and re-applying would change nothing.
		clearSecretFanoutHoldersForIncarnation(sandboxID, incarnationID)
		return nil
	}
	if s.store != nil {
		err = s.store.ApplyPeerSecretDelete(ctx, sandboxID, incarnationID, generation)
	} else if p := s.provider(); p != nil {
		err = p.Delete(secrets.ContextWithIncarnationID(ctx, incarnationID), sandboxID)
	}
	clearSecretFanoutHoldersForIncarnation(sandboxID, incarnationID)
	return err
}

// authorizePeerSecretDelete decides whether a peer DELETE may be applied.
// alreadyApplied reports that this node holds nothing at or below generation
// for the exact lifecycle and nothing can land later, so the caller must
// acknowledge without applying.
//
// Authorization evidence is transient: the ciphertext row disappears on the
// first successful apply and the authoritative placement disappears when the
// sandbox is destroyed. A retry after a lost ACK — the normal case for a
// durable outbox — therefore has to be recognized from the local tomb, not
// re-authorized from evidence that no longer exists, or the originator's
// outbox row and tomb never retire.
func (s *Service) authorizePeerSecretDelete(ctx context.Context, sandboxID, incarnationID string, generation int64, peerNodeID string) (alreadyApplied bool, err error) {
	if s == nil || !s.cfg.EnableCluster {
		return false, nil
	}
	peerNodeID = strings.TrimSpace(peerNodeID)
	if peerNodeID == "" {
		return false, fmt.Errorf("%w: peer identity is required for secret delete", ErrClusterSecretOriginatorDenied)
	}
	denied := fmt.Errorf("%w: node %q cannot delete sandbox %q secrets", ErrClusterSecretOriginatorDenied, peerNodeID, sandboxID)
	// Prefer the exact local lifecycle record. It remains authoritative for a
	// delayed cleanup after a sandbox ID has been reused by a new placement.
	var rec *store.ClusterSecretRecord
	if s.store != nil {
		rec, err = s.store.GetClusterSecretForSandboxIncarnation(ctx, sandboxID, incarnationID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return false, fmt.Errorf("authorize peer secret delete from local record: %w", err)
		}
		if rec != nil && secrets.RecipientAllowed(rec.Recipients, peerNodeID) {
			return false, nil
		}
		if rec == nil {
			// Tombs are only ever written by an authorized delete (this node as
			// originator, or a peer that passed this check), so a tomb at or
			// above the requested generation is proof the work is already done.
			tombGen, tombErr := s.store.ClusterSecretTombGenerationForIncarnation(ctx, sandboxID, incarnationID)
			if tombErr != nil {
				return false, fmt.Errorf("authorize peer secret delete from local tomb: %w", tombErr)
			}
			if tombGen >= generation {
				return true, nil
			}
		}
	}
	c := s.Cluster()
	if c == nil {
		return false, ErrClusterSecretPlacementUnavailable
	}
	placements, err := c.AuthoritativePlacementsByIDs(ctx, []string{sandboxID})
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrClusterSecretPlacementUnavailable, err)
	}
	if placement, ok := placements[sandboxID]; ok && strings.TrimSpace(placement.IncarnationID) == incarnationID {
		if peerSecretDeleteAuthorizedByPlacement(placement, peerNodeID) {
			return false, nil
		}
		return false, denied
	}
	if rec != nil {
		// Ciphertext is present but neither the row nor the authoritative
		// lifecycle names the peer: only the retirement scan may remove it.
		return false, denied
	}
	// No local ciphertext, no covering tomb, and the authoritative lifecycle
	// is gone (destroyed, or the ID was reused by a new incarnation) — the
	// first fan-out attempt can land here when the peer never received the
	// PUT and the placement removal won the race. A PUT for this incarnation
	// can only pass validatePeerSecretBlob while the local FSM snapshot still
	// shows the lifecycle live, and both checks run under lockSecretSandboxOps,
	// so that snapshot is the last evidence that can authorize a tomb.
	live, ok, liveErr := s.liveSecretPlacement(sandboxID)
	if liveErr != nil {
		return false, fmt.Errorf("%w: %v", ErrClusterSecretPlacementUnavailable, liveErr)
	}
	if ok && strings.TrimSpace(live.IncarnationID) == incarnationID {
		if peerSecretDeleteAuthorizedByPlacement(live, peerNodeID) {
			return false, nil
		}
		return false, denied
	}
	// Nothing to delete and nothing can arrive: acknowledge so the originator's
	// outbox retires. No tomb is minted on an unauthenticated say-so.
	return true, nil
}

func peerSecretDeleteAuthorizedByPlacement(placement cluster.Placement, peerNodeID string) bool {
	return strings.TrimSpace(placement.OwnerNodeID) == peerNodeID || secrets.RecipientAllowed(placement.SecretRecipients, peerNodeID)
}

// ReconcileSecretDeleteOutbox retries durable peer DELETEs after boot / crash
// and on the periodic ticker. Work is dispatched through the bounded delete
// fan-out pool so a large outbox cannot serialize the reconciler for minutes.
//
// Without cluster mode there is no transport to the peers these rows name and
// never will be; see retireStandaloneSecretOutbox for what happens to them.
func (s *Service) ReconcileSecretDeleteOutbox(ctx context.Context) error {
	return s.reconcileSecretDeleteOutboxAt(ctx, secretLifecycleNow())
}

// secretOutboxPass describes one sweep of a durable peer-obligation queue.
//
// ignoreBackoff is the rejoin override: a member that just came back is worth
// one immediate try for every obligation to it, however far those rows had
// backed off. It is an explicit flag rather than a clock placed past the
// backoff cap because the clock is also what decides whether a row this pass
// has already attempted still looks due — with a shifted clock every page
// re-listed the rows the previous page had just tried, and one rejoin cost a
// 1024-row backlog six rounds of peer calls before the schedule caught up.
//
// rejoinedNodes narrows that override to the obligations it is actually about.
// Without it, one member flap made every node re-attempt every backed-off row
// it held, and at 100,000 sandboxes across 2,000 nodes a single flap became a
// fleet-wide push storm aimed mostly at peers that never left.
type secretOutboxPass struct {
	now           time.Time
	ignoreBackoff bool
	rejoinedNodes map[string]struct{}
}

// targetsRejoinedNode reports whether an obligation is owed to a member that
// just came back. An empty rejoinedNodes set means the pass is not a rejoin
// pass and every row qualifies (boot, manual reconcile).
func (p secretOutboxPass) targetsRejoinedNode(recipients []string) bool {
	if len(p.rejoinedNodes) == 0 {
		return true
	}
	for _, id := range recipients {
		if _, ok := p.rejoinedNodes[strings.TrimSpace(id)]; ok {
			return true
		}
	}
	return false
}

// reconcileSecretDeleteOutboxAt is ReconcileSecretDeleteOutbox with an explicit
// "now" for the retry schedule. The rejoin path does not use it: it overrides
// the schedule outright with secretOutboxPass.ignoreBackoff.
func (s *Service) reconcileSecretDeleteOutboxAt(ctx context.Context, now time.Time) error {
	return s.reconcileSecretDeleteOutboxPass(ctx, secretOutboxPass{now: now})
}

func (s *Service) reconcileSecretDeleteOutboxPass(ctx context.Context, pass secretOutboxPass) error {
	if s == nil || s.store == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer s.refreshSecretLifecycleMetrics(ctx)
	if s.secretPeerPusher() == nil {
		if !s.cfg.EnableCluster {
			return s.retireStandaloneSecretOutbox(ctx)
		}
		return nil // cluster mode, transport not attached yet: keep the durable jobs
	}
	return s.sweepSecretOutbox(ctx, pass, secretOutboxSweep{
		sem:      deleteReconcileSem,
		inflight: &deleteReconcileInflight,
		listDue: func(ctx context.Context, pass secretOutboxPass, limit int) ([]secretOutboxRow, error) {
			var recs []store.SecretDeleteOutboxRecord
			var err error
			if pass.ignoreBackoff {
				recs, err = s.store.ListSecretDeleteOutboxBatch(ctx, limit)
			} else {
				recs, err = s.store.ListSecretDeleteOutboxDue(ctx, pass.now.UTC(), limit)
			}
			if err != nil {
				return nil, err
			}
			rows := make([]secretOutboxRow, 0, len(recs))
			for _, rec := range recs {
				if !pass.targetsRejoinedNode(rec.Recipients) {
					continue
				}
				// Only a staged reseal reads the placement; a plain delete
				// is actionable without one.
				rows = append(rows, secretOutboxRow{sandboxID: rec.SandboxID, incarnationID: rec.IncarnationID, generation: rec.Generation, needsPlacement: rec.AwaitingPromotion})
			}
			return rows, nil
		},
		deferRow: func(ctx context.Context, row secretOutboxRow) error {
			return s.store.TouchSecretDeleteOutbox(ctx, row.sandboxID, row.incarnationID, row.generation)
		},
		process: func(ctx context.Context, row secretOutboxRow, placements map[string]cluster.Placement) {
			s.reconcileSecretDeleteOutboxIncarnationWithPlacements(ctx, row.sandboxID, row.incarnationID, placements)
		},
	})
}

// secretOutboxRow is what the shared sweep needs to know about one durable
// peer obligation, whichever table it came from.
type secretOutboxRow struct {
	sandboxID, incarnationID string
	generation               int64
	// needsPlacement marks rows whose handling reads the authoritative
	// placement (every PUT; a staged DELETE awaiting promotion).
	needsPlacement bool
}

// secretOutboxSweep is the shape both durable peer-obligation queues share.
// The tables and the per-row decisions differ; the sweep does not: page the
// due rows oldest-first, resolve authoritative placements once per page, hand
// each row to a bounded worker pool behind an in-flight set so the boot pass
// and the ticker never double-process one lifecycle, and stop when a page
// yields nothing or the time budget is spent.
type secretOutboxSweep struct {
	sem      chan struct{}
	inflight *sync.Map
	// listDue returns one page of rows whose retry backoff has elapsed, or of
	// every pending row when the pass overrides the schedule.
	listDue func(ctx context.Context, pass secretOutboxPass, limit int) ([]secretOutboxRow, error)
	// deferRow moves a row to the back of the fair queue without counting an
	// attempt: the page's placements could not be read, so nothing was tried.
	deferRow func(ctx context.Context, row secretOutboxRow) error
	// process handles one row with the page's placements.
	process func(ctx context.Context, row secretOutboxRow, placements map[string]cluster.Placement)
}

func (s *Service) sweepSecretOutbox(ctx context.Context, pass secretOutboxPass, sw secretOutboxSweep) error {
	sweepCtx, cancel := context.WithTimeout(ctx, secretDeleteReconcileBudget)
	defer cancel()
	// One attempt per obligation per pass. Every page is a fresh read of the
	// queue, and a row can still match the listing right after this pass
	// handled it: a rejoin pass ignores the schedule outright, and the paths
	// that defer a row (an unpromoted reseal, an unreadable placement) move it
	// without counting an attempt, which leaves it due. Without this set those
	// rows come straight back on the next page and the same backlog is worked
	// over and over until the time budget runs out.
	//
	// Keyed by lifecycle, like the in-flight guard: process resolves the row
	// from (sandbox, incarnation), so a second page listing another generation
	// of the same lifecycle would only redo the work this one just did.
	attempted := make(map[string]struct{})
	for {
		page, err := sw.listDue(sweepCtx, pass, secretDeleteReconcileBatch)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				return nil
			}
			return err
		}
		if len(page) == 0 {
			return nil
		}
		rows := make([]secretOutboxRow, 0, len(page))
		for _, row := range page {
			if _, done := attempted[secretDeleteReconcileKey(row.sandboxID, row.incarnationID)]; done {
				continue
			}
			rows = append(rows, row)
		}
		// A page of nothing but rows this pass already handled means the queue
		// has no further work for it, however the listing is filtered.
		if len(rows) == 0 {
			return nil
		}
		placementIDs := make([]string, 0, len(rows))
		for _, row := range rows {
			if row.needsPlacement {
				placementIDs = append(placementIDs, row.sandboxID)
			}
		}
		placements, err := s.authoritativeSecretPlacements(sweepCtx, placementIDs)
		if err != nil {
			for _, row := range rows {
				if row.needsPlacement {
					_ = sw.deferRow(context.Background(), row)
				}
			}
			return err
		}
		jobs := make(chan secretOutboxRow)
		var wg sync.WaitGroup
		var processed atomic.Int64
		workers := min(deleteReconcileWorkers, len(rows))
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for row := range jobs {
					key := secretDeleteReconcileKey(row.sandboxID, row.incarnationID)
					if _, loaded := sw.inflight.LoadOrStore(key, struct{}{}); loaded {
						continue
					}
					select {
					case sw.sem <- struct{}{}:
						sw.process(sweepCtx, row, placements)
						processed.Add(1)
						<-sw.sem
						sw.inflight.Delete(key)
					case <-sweepCtx.Done():
						sw.inflight.Delete(key)
						return
					}
				}
			}()
		}
		for _, row := range rows {
			// Marked on dispatch, not on completion: a row another goroutine is
			// already handling, or one this pass ran out of time for, has had
			// its turn either way and must not re-enter the next page.
			attempted[secretDeleteReconcileKey(row.sandboxID, row.incarnationID)] = struct{}{}
			select {
			case jobs <- row:
			case <-sweepCtx.Done():
				close(jobs)
				wg.Wait()
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return nil
			}
		}
		close(jobs)
		wg.Wait()
		if sweepCtx.Err() != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return nil
		}
		if processed.Load() == 0 || len(rows) < secretDeleteReconcileBatch {
			return nil
		}
		// The time budget is the usual end of a long pass; this bounds the
		// per-pass set itself so a fleet-sized backlog cannot grow it without
		// limit. What is left stays durable and is picked up next tick.
		if len(attempted) >= secretOutboxSweepMaxRows {
			return nil
		}
	}
}

const (
	secretTombPruneBatch    = 1024
	secretTombPruneInterval = 10 * time.Minute
)

func (s *Service) refreshSecretLifecycleMetrics(ctx context.Context) {
	if s == nil || s.store == nil {
		return
	}
	stats, err := s.store.SecretLifecycleStats(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: secret lifecycle stats failed", "err", err)
		}
		return
	}
	secretDeleteOutboxPending.Set(stats.OutboxPending)
	secretPutOutboxPending.Set(stats.PutOutboxPending)
	secretTombstones.Set(stats.Tombstones)
	queueAge := func(oldest time.Time) int64 {
		if oldest.IsZero() {
			return 0
		}
		age := int64(time.Since(oldest).Seconds())
		if age < 0 {
			return 0
		}
		return age
	}
	age := queueAge(stats.OldestOutbox)
	secretDeleteOutboxOldestAgeSeconds.Set(age)
	secretPutOutboxOldestAgeSeconds.Set(queueAge(stats.OldestPutOutbox))
}

func (s *Service) pruneClusterSecretTombs(ctx context.Context) error {
	if s == nil || s.store == nil || s.cfg.SecretTombRetentionDays <= 0 {
		return nil
	}
	cutoff := time.Now().UTC().Add(-time.Duration(s.cfg.SecretTombRetentionDays) * 24 * time.Hour)
	pruned, err := s.store.PruneClusterSecretTombs(ctx, cutoff, secretTombPruneBatch)
	if err != nil {
		return err
	}
	if pruned > 0 && s.logger != nil {
		s.logger.Info("cluster: pruned expired secret tombstones", "count", pruned)
	}
	s.refreshSecretLifecycleMetrics(ctx)
	return nil
}

func (s *Service) pruneClusterAuditACL(ctx context.Context) error {
	// The Raft stub is bounded by the deleted-sandbox grace, not by local
	// retention; with grace disabled nothing is ever written, so nothing to sweep.
	if s == nil || s.cfg.AuditDeletedGrace <= 0 {
		return nil
	}
	c := s.Cluster()
	if c == nil {
		return nil
	}
	return c.PruneAuditACL(ctx, time.Now().UTC())
}

// secretLifecycleNow is the clock the standalone retirement reads; tests
// advance it instead of aging rows.
var secretLifecycleNow = time.Now

// retireStandaloneSecretOutbox is what a node without cluster mode does with
// peer obligations. The rows were written when it was a cluster member (or by
// destroying a cluster-created sandbox after the downgrade): "push this
// ciphertext to peers X", "tell peers X to delete theirs". Standalone, neither
// can ever be sent — there is no transport and no membership — so keeping the
// rows is not durability, it is a leak that also pins tombstones forever.
//
// The rows are retired after SB_SECRET_OUTBOX_STANDALONE_GRACE (measured from
// their last attempt), so a short cluster-off restart keeps them and a node
// that rejoins within the grace still owes and retries them. What is given up
// is bounded: peers retire ciphertext themselves when its placement is gone,
// and a rejoining node's boot re-fanout re-pushes anything still live. Every
// retirement is counted and the peers named in the log, so the operator knows
// which nodes may still hold ciphertext for which lifecycles.
func (s *Service) retireStandaloneSecretOutbox(ctx context.Context) error {
	if s == nil || s.store == nil {
		return nil
	}
	cutoff := secretLifecycleNow().UTC().Add(-s.cfg.SecretOutboxStandaloneGrace)
	sweepCtx, cancel := context.WithTimeout(ctx, secretDeleteReconcileBudget)
	defer cancel()
	var (
		deletesRetired, putsRetired int
		samplePeers                 = map[string]struct{}{}
		sample                      []string
	)
	notePeers := func(recipients []string) {
		for _, id := range nonSelfRecipients(recipients, s.selfNodeID()) {
			if _, seen := samplePeers[id]; seen || len(sample) >= 8 {
				continue
			}
			samplePeers[id] = struct{}{}
			sample = append(sample, id)
		}
	}
	// Oldest first: the first batch that contains nothing past the cutoff
	// ends the sweep, so a large young backlog costs one page per tick.
	for {
		rows, err := s.store.ListSecretDeleteOutboxBatch(sweepCtx, secretDeleteReconcileBatch)
		if err != nil {
			return err
		}
		retired := 0
		for _, rec := range rows {
			if rec.UpdatedAt.After(cutoff) {
				break
			}
			if err := s.store.DeleteSecretDeleteOutbox(sweepCtx, rec.SandboxID, rec.IncarnationID, rec.Generation); err != nil {
				return err
			}
			clearSecretFanoutHoldersForIncarnation(rec.SandboxID, rec.IncarnationID)
			notePeers(rec.Recipients)
			retired++
		}
		deletesRetired += retired
		if retired == 0 || retired < len(rows) {
			break
		}
	}
	for {
		rows, err := s.store.ListSecretPutOutboxBatch(sweepCtx, secretDeleteReconcileBatch)
		if err != nil {
			return err
		}
		retired := 0
		for _, rec := range rows {
			if rec.UpdatedAt.After(cutoff) {
				break
			}
			if err := s.store.DeleteSecretPutOutbox(sweepCtx, rec.SandboxID, rec.IncarnationID, rec.SealGeneration); err != nil {
				return err
			}
			notePeers(rec.Recipients)
			retired++
		}
		putsRetired += retired
		if retired == 0 || retired < len(rows) {
			break
		}
	}
	if deletesRetired == 0 && putsRetired == 0 {
		return nil
	}
	secretDeleteOutboxRetiredStandalone.Add(int64(deletesRetired))
	secretPutOutboxRetiredStandalone.Add(int64(putsRetired))
	if s.logger != nil {
		s.logger.Warn("standalone: retired peer secret obligations this node can never discharge (cluster mode is off); the named peers may still hold ciphertext until their own retirement scan removes it",
			"delete_obligations", deletesRetired, "put_obligations", putsRetired,
			"grace", s.cfg.SecretOutboxStandaloneGrace, "peers_sample", sample)
	}
	return nil
}

// StartSecretDeleteOutboxReconcile runs the secret-lifecycle maintenance loop:
// periodic peer-delete and peer-put retries so offline recipients are not
// permanently abandoned after the boot pass, tombstone and audit-ACL pruning,
// holder possession refresh, and the stale-ciphertext retirement scan. When
// membership gains a newly-alive node, reconcile runs immediately and secrets
// are re-fanout so holders re-ACK after rejoin.
//
// It runs in every mode. Standalone, the cluster-only steps are no-ops and the
// outbox/ciphertext steps retire what a node without peers can never finish
// (retireStandaloneSecretOutbox, runSecretRetirementScan) — the four lifecycle
// tables must never depend on cluster mode being on to be garbage collected.
func (s *Service) StartSecretDeleteOutboxReconcile(ctx context.Context) {
	if s == nil || s.store == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		tombTicker := time.NewTicker(secretTombPruneInterval)
		defer tombTicker.Stop()
		if err := s.pruneClusterSecretTombs(ctx); err != nil && s.logger != nil {
			s.logger.Warn("cluster: secret tombstone prune failed", "err", err)
		}
		if err := s.pruneClusterAuditACL(ctx); err != nil && s.logger != nil {
			s.logger.Warn("cluster: retained audit ACL prune failed", "err", err)
		}
		s.refreshSecretLifecycleMetrics(ctx)
		prevAlive := s.aliveMemberSet()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				alive := s.aliveMemberSet()
				rejoined := make(map[string]struct{})
				for id := range alive {
					if _, ok := prevAlive[id]; !ok {
						rejoined[id] = struct{}{}
					}
				}
				prevAlive = alive
				// A member came back: every obligation TO THAT MEMBER is worth
				// one immediate try regardless of how far it had backed off.
				// The pass says so outright instead of moving its clock past
				// the backoff cap, which also made rows this pass had just
				// tried look due to the next page (see secretOutboxPass), and
				// it names the returning nodes so a flap does not re-attempt
				// obligations owed to peers that never left.
				pass := secretOutboxPass{now: secretLifecycleNow(), ignoreBackoff: len(rejoined) > 0, rejoinedNodes: rejoined}
				if err := s.reconcileSecretDeleteOutboxPass(ctx, pass); err != nil && s.logger != nil {
					s.logger.Warn("cluster: secret delete-outbox reconcile failed", "err", err)
				}
				if err := s.reconcileSecretPutOutboxPass(ctx, pass); err != nil && s.logger != nil {
					s.logger.Warn("cluster: secret put-outbox reconcile failed", "err", err)
				}
				s.refreshSecretHolderPossession(ctx)
				// A node whose storage an operator attested destroyed, but
				// which is alive again, can ACK — so its attestation is
				// withdrawn and its obligations become pending once more.
				s.reapLiveNodeStorageRetirements(ctx)
				if len(rejoined) > 0 {
					// Only the secrets whose recipient set contains a
					// returning node need retransmitting. Re-fanning out
					// every local secret on every flap is what turns one
					// member restart into a fleet-wide storm: each node
					// re-pushes its whole holdings AND asks the Raft leader
					// for a placement snapshot per page.
					if err := s.ReFanoutClusterSecretsForNodes(ctx, rejoined); err != nil && s.logger != nil {
						s.logger.Warn("cluster: secret re-fanout after member rejoin failed", "err", err)
					}
				}
			case <-tombTicker.C:
				if err := s.pruneClusterSecretTombs(ctx); err != nil && s.logger != nil {
					s.logger.Warn("cluster: secret tombstone prune failed", "err", err)
				}
				if err := s.pruneClusterAuditACL(ctx); err != nil && s.logger != nil {
					s.logger.Warn("cluster: retained audit ACL prune failed", "err", err)
				}
				// Reconcile ciphertext whose lifecycle placement disappeared after
				// an owner crashed mid-delete. This periodic pass retires only stale
				// rows; active ciphertext is re-fanned out by boot/rejoin and holder
				// repair, avoiding a full-fleet retransmit every ten minutes.
				s.startSecretRetirementScan(ctx)
			}
		}
	}()
}

func (s *Service) aliveMemberSet() map[string]struct{} {
	out := map[string]struct{}{}
	if s == nil {
		return out
	}
	c := s.Cluster()
	if c == nil {
		return out
	}
	// Liveness is gossip's own answer. Members() on an agent is a
	// control-plane round trip carrying every peer (~850 B each, ~1.7 MB at
	// 2k nodes) and this runs on a 30s maintenance tick on every node — so
	// read the local SWIM view and fall back only when it is empty.
	members := c.LocalMembers()
	if len(members) == 0 {
		members = c.Members()
	}
	for _, m := range members {
		if m.Alive && m.NodeID != "" {
			out[m.NodeID] = struct{}{}
		}
	}
	if id := c.SelfNodeID(); id != "" {
		out[id] = struct{}{}
	}
	return out
}

const (
	// secretHolderRefreshBatch caps fair-queue work per node and tick. At the
	// 100k/2k-node target, each worker owns only its local placement/replica
	// partition; 4096 also leaves headroom for temporary skew without turning a
	// tick into unbounded fan-out. Raise only with refresh latency budgets in
	// mind — each job may probe + re-push peers under the budget below.
	secretHolderRefreshBatch   = 4096
	secretHolderRefreshWorkers = 64
	secretHolderProbeTimeout   = 5 * time.Second
	secretHolderRefreshBudget  = 25 * time.Second
)

// refreshSecretHolderPossession re-probes intended remote recipients that are
// approaching ACK TTL. Targets are independent from confirmed ACKs, so a
// timeout or 404 can recover on a later pass without a membership flap.
// Missing holders trigger a re-push of the local sealed blob when loadable.
// When any frozen target is dead, recipients are replaced via
// Raft + recipient-bound AAD reseal (SelectReplacementRecipients) before
// holder targets advance — pushing the old ciphertext would fail Open.
// secretHolderPlacements resolves every tracked holder's placement in ONE
// batch per maintenance tick. Returns ok=false when the view is unavailable;
// callers must skip rather than treat the empty result as "these placements
// are gone", because a missing placement retires holder state.
//
// Parity note: this is the non-authoritative batch, matching the PlacementOf
// point read it replaces. Holder sets are in-memory bookkeeping rebuilt by
// the next fan-out, not durable state, so they do not need the authoritative
// read that destructive placement reconcilers use.
func (s *Service) secretHolderPlacements() (map[string]cluster.Placement, bool) {
	if s == nil || !s.cfg.EnableCluster {
		return nil, true
	}
	c := s.Cluster()
	if c == nil {
		return nil, false
	}
	seen := make(map[string]struct{})
	ids := make([]string, 0, 64)
	secretFanoutHolders.Range(func(key, _ any) bool {
		holderKey, _ := key.(secretHolderKey)
		if holderKey.sandboxID == "" {
			return true
		}
		if _, dup := seen[holderKey.sandboxID]; dup {
			return true
		}
		seen[holderKey.sandboxID] = struct{}{}
		ids = append(ids, holderKey.sandboxID)
		return true
	})
	if len(ids) == 0 {
		return map[string]cluster.Placement{}, true
	}
	out := c.PlacementsByIDs(ids)
	if out == nil {
		return nil, false
	}
	return out, true
}

func (s *Service) refreshSecretHolderPossession(ctx context.Context) {
	if s == nil {
		return
	}
	pusher := s.secretPeerPusher()
	if pusher == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	refreshCtx, cancel := context.WithTimeout(ctx, secretHolderRefreshBudget)
	defer cancel()
	selfID := s.selfNodeID()
	alive := s.aliveMemberSet()
	// One batch for the whole tick. Both passes below used to call
	// PlacementOf per tracked holder — on an agent that is a control-plane
	// round trip each, twice per holder per tick, and it ran BEFORE
	// secretHolderRefreshBatch so the cap never bounded it.
	placements, placementsOK := s.secretHolderPlacements()
	if !placementsOK {
		// Not authoritative. A missing placement retires a holder, so an
		// unavailable read must never stand in for absence: that would drop
		// every holder set on this node during a control-plane blip.
		return
	}
	type job struct {
		sandboxID     string
		incarnationID string
		gen           int64
		peers         []string
		lastProbe     time.Time
		lastExpand    time.Time
	}
	var expandJobs []job
	secretFanoutHolders.Range(func(key, val any) bool {
		if refreshCtx.Err() != nil {
			return false
		}
		holderKey, _ := key.(secretHolderKey)
		sandboxID := holderKey.sandboxID
		hs, _ := val.(*holderNodeSet)
		if sandboxID == "" || holderKey.incarnationID == "" || hs == nil {
			return true
		}
		var placementGeneration int64
		if s.cfg.EnableCluster {
			placement, ok := placements[sandboxID]
			if !ok || placement.IsDeleting() || strings.TrimSpace(placement.IncarnationID) != holderKey.incarnationID {
				secretFanoutHolders.Delete(holderKey)
				return true
			}
			placementGeneration = placement.SecretSealGeneration
		}
		hs.mu.Lock()
		holderGeneration := hs.gen
		lastExpand := hs.lastExpand
		needs := s.anySecretTargetDead(mapKeys(hs.targets), alive, selfID) ||
			(placementGeneration > 0 && holderGeneration > placementGeneration)
		hs.mu.Unlock()
		if needs {
			expandJobs = append(expandJobs, job{
				sandboxID: sandboxID, incarnationID: holderKey.incarnationID,
				gen: holderGeneration, lastExpand: lastExpand,
			})
		}
		return true
	})
	sort.Slice(expandJobs, func(i, j int) bool {
		if expandJobs[i].lastExpand.Equal(expandJobs[j].lastExpand) {
			return expandJobs[i].sandboxID < expandJobs[j].sandboxID
		}
		if expandJobs[i].lastExpand.IsZero() {
			return true
		}
		if expandJobs[j].lastExpand.IsZero() {
			return false
		}
		return expandJobs[i].lastExpand.Before(expandJobs[j].lastExpand)
	})
	if len(expandJobs) > secretHolderRefreshBatch {
		expandJobs = expandJobs[:secretHolderRefreshBatch]
	}
	expandIDs := make([]string, 0, len(expandJobs))
	expandIncarnations := make(map[string]string, len(expandJobs))
	expandAttemptedAt := time.Now()
	for _, j := range expandJobs {
		expandIDs = append(expandIDs, j.sandboxID)
		expandIncarnations[j.sandboxID] = j.incarnationID
		if val, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: j.sandboxID, incarnationID: j.incarnationID}); ok {
			hs := val.(*holderNodeSet)
			hs.mu.Lock()
			if hs.gen == j.gen {
				hs.lastExpand = expandAttemptedAt
			}
			hs.mu.Unlock()
		}
	}
	var expandPlacements map[string]cluster.Placement
	if s.cfg.EnableCluster && len(expandIDs) > 0 {
		var err error
		expandPlacements, err = s.authoritativeSecretPlacements(refreshCtx, expandIDs)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("cluster: authoritative placement read for secret reseal sweep failed", "err", err, "sandboxes", len(expandIDs))
			}
			expandIDs = nil
		}
	}
	for _, sandboxID := range expandIDs {
		if refreshCtx.Err() != nil {
			break
		}
		var err error
		if s.cfg.EnableCluster {
			placement, ok := expandPlacements[sandboxID]
			if !ok || placement.IsDeleting() || strings.TrimSpace(placement.IncarnationID) != expandIncarnations[sandboxID] {
				clearSecretFanoutHolders(sandboxID)
				continue
			}
			err = s.expandAndResealDeadSecretTargetsForPlacement(refreshCtx, s.Cluster(), placement)
		} else {
			err = s.expandAndResealDeadSecretTargets(refreshCtx, sandboxID)
		}
		if err != nil && s.logger != nil {
			s.logger.Warn("cluster: secret recipient expansion/reseal failed",
				"sandbox_id", sandboxID, "err", err)
		}
	}

	var jobs []job
	now := time.Now()
	// Refresh after two thirds of the TTL, leaving one full ticker interval to
	// retry before an ACK expires.
	refreshBefore := now.Add(-(secretHolderACKTTL * 2 / 3))
	secretFanoutHolders.Range(func(key, val any) bool {
		if refreshCtx.Err() != nil {
			return false
		}
		holderKey, _ := key.(secretHolderKey)
		sandboxID := holderKey.sandboxID
		hs, _ := val.(*holderNodeSet)
		if sandboxID == "" || holderKey.incarnationID == "" || hs == nil {
			return true
		}
		if s.cfg.EnableCluster {
			placement, ok := placements[sandboxID]
			if !ok || placement.IsDeleting() || strings.TrimSpace(placement.IncarnationID) != holderKey.incarnationID {
				secretFanoutHolders.Delete(holderKey)
				return true
			}
		}
		hs.mu.Lock()
		incarnationID := holderKey.incarnationID
		gen := hs.gen
		peers := make([]string, 0, len(hs.targets))
		needsProbe := false
		for id := range hs.targets {
			if id == "" || id == selfID {
				continue
			}
			peers = append(peers, id)
			at := hs.nodes[id]
			if at.IsZero() || at.Before(refreshBefore) {
				needsProbe = true
			}
		}
		lastProbe := hs.lastProbe
		hs.mu.Unlock()
		if !needsProbe || len(peers) == 0 || incarnationID == "" || gen <= 0 {
			return true
		}
		sort.Strings(peers)
		jobs = append(jobs, job{sandboxID: sandboxID, incarnationID: incarnationID, gen: gen, peers: peers, lastProbe: lastProbe})
		return true
	})
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].lastProbe.Equal(jobs[j].lastProbe) {
			return jobs[i].sandboxID < jobs[j].sandboxID
		}
		if jobs[i].lastProbe.IsZero() {
			return true
		}
		if jobs[j].lastProbe.IsZero() {
			return false
		}
		return jobs[i].lastProbe.Before(jobs[j].lastProbe)
	})
	if len(jobs) > secretHolderRefreshBatch {
		jobs = jobs[:secretHolderRefreshBatch]
	}
	if s.cfg.EnableCluster && len(jobs) > 0 {
		ids := make([]string, 0, len(jobs))
		for _, j := range jobs {
			ids = append(ids, j.sandboxID)
		}
		placements, err := s.authoritativeSecretPlacements(refreshCtx, ids)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("cluster: authoritative placement read for secret holder refresh failed", "err", err, "sandboxes", len(jobs))
			}
			return
		}
		validated := jobs[:0]
		for _, j := range jobs {
			placement, ok := placements[j.sandboxID]
			placementPeers := nonSelfRecipients(secrets.NormalizeRecipients(placement.SecretRecipients), selfID)
			sort.Strings(placementPeers)
			if !ok || placement.IsDeleting() || strings.TrimSpace(placement.IncarnationID) != j.incarnationID ||
				placement.SecretSealGeneration != j.gen || !sameStringSlice(placementPeers, j.peers) {
				clearSecretFanoutHoldersForIncarnation(j.sandboxID, j.incarnationID)
				continue
			}
			validated = append(validated, j)
		}
		jobs = validated
	}
	for _, j := range jobs {
		if v, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: j.sandboxID, incarnationID: j.incarnationID}); ok {
			hs := v.(*holderNodeSet)
			hs.mu.Lock()
			if hs.gen == j.gen {
				hs.lastProbe = now
			}
			hs.mu.Unlock()
		}
	}

	sem := make(chan struct{}, secretHolderRefreshWorkers)
	var wg sync.WaitGroup
	var probeFailures struct {
		sync.Mutex
		count int
		first error
	}
	for _, j := range jobs {
		if refreshCtx.Err() != nil {
			break
		}
		j := j
		select {
		case sem <- struct{}{}:
		case <-refreshCtx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			probeCtx, probeCancel := context.WithTimeout(refreshCtx, secretHolderProbeTimeout)
			holding, probeErr := pusher.ProbeSecretOnPeers(probeCtx, j.sandboxID, j.incarnationID, j.peers, j.gen)
			probeCancel()
			if probeErr != nil {
				probeFailures.Lock()
				probeFailures.count++
				if probeFailures.first == nil {
					probeFailures.first = probeErr
				}
				probeFailures.Unlock()
			}
			missing := make([]string, 0)
			hs := holderSetFor(j.sandboxID, j.incarnationID)
			hs.mu.Lock()
			if hs.gen != j.gen && hs.gen != 0 {
				hs.mu.Unlock()
				return
			}
			hs.gen = j.gen
			if hs.nodes == nil {
				hs.nodes = make(map[string]time.Time)
			}
			confirmed := make(map[string]struct{}, len(holding))
			for _, id := range holding {
				if id = strings.TrimSpace(id); id != "" {
					confirmed[id] = struct{}{}
				}
			}
			confirmedAt := time.Now()
			if selfID != "" {
				hs.nodes[selfID] = confirmedAt
			}
			for _, id := range j.peers {
				if _, ok := hs.targets[id]; !ok {
					continue
				}
				if _, ok := confirmed[id]; ok {
					hs.nodes[id] = confirmedAt
				} else if probeErr == nil {
					delete(hs.nodes, id)
					missing = append(missing, id)
				}
			}
			hs.mu.Unlock()
			if len(missing) == 0 || probeErr != nil || s.store == nil {
				return
			}
			rec, loadErr := s.store.GetClusterSecretForSandboxIncarnation(refreshCtx, j.sandboxID, j.incarnationID)
			if loadErr != nil || rec == nil || rec.SealGeneration < j.gen {
				return
			}
			parsed, parseErr := secrets.ParseRef(rec.Ref)
			if parseErr != nil || parsed.SandboxID != rec.SandboxID || parsed.Version != rec.Version || parsed.IncarnationID != j.incarnationID {
				recordSecretFanoutFailure()
				return
			}
			blob := secrets.SecretBlob{
				Ref:            rec.Ref,
				SandboxID:      rec.SandboxID,
				IncarnationID:  parsed.IncarnationID,
				Version:        rec.Version,
				Recipients:     append([]string(nil), rec.Recipients...),
				SealedPayload:  rec.SealedPayload,
				SealGeneration: rec.SealGeneration,
			}
			pushCtx, pushCancel := context.WithTimeout(refreshCtx, secretHolderProbeTimeout)
			acked, pushErr := pusher.PushSecretBlobToPeers(pushCtx, blob, missing)
			pushCancel()
			if len(acked) > 0 {
				addSecretHolderNodes(j.sandboxID, j.incarnationID, j.gen, acked...)
			}
			if pushErr != nil {
				probeFailures.Lock()
				probeFailures.count++
				if probeFailures.first == nil {
					probeFailures.first = pushErr
				}
				probeFailures.Unlock()
			}
		}()
	}
	wg.Wait()
	probeFailures.Lock()
	failureCount, firstProbeErr := probeFailures.count, probeFailures.first
	probeFailures.Unlock()
	if failureCount > 0 && s.logger != nil {
		s.logger.Warn("cluster: secret holder possession refresh incomplete",
			"failed_sandboxes", failureCount, "attempted_sandboxes", len(jobs), "first_error", firstProbeErr)
	}
}

func mapKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	return out
}

// expandAndResealDeadSecretTargets replaces frozen seal recipients when any
// non-self target is dead. Recipients are authenticated in
// envelope AAD (KeyAADBound/PayloadAADBound), so the existing ciphertext cannot
// be pushed to new nodes. We Open locally, atomically stage the new seal and
// retired-recipient cleanup, ACK a replacement, Raft-CAS the recipient set,
// promote cleanup, and then fan out the remainder. Owner-only: non-owners skip
// so concurrent ticks cannot race reseals.
func (s *Service) expandAndResealDeadSecretTargets(ctx context.Context, sandboxID string) error {
	if s == nil || strings.TrimSpace(sandboxID) == "" {
		return nil
	}
	c := s.Cluster()
	if c == nil {
		return nil
	}
	placements, err := c.AuthoritativePlacementsByIDs(ctx, []string{sandboxID})
	if err != nil {
		return fmt.Errorf("authoritative placement read before secret reseal: %w", err)
	}
	placement, ok := placements[sandboxID]
	if !ok {
		if s.cfg.EnableCluster {
			clearSecretFanoutHolders(sandboxID)
		}
		return nil
	}
	return s.expandAndResealDeadSecretTargetsForPlacement(ctx, c, placement)
}

func (s *Service) expandAndResealDeadSecretTargetsForPlacement(ctx context.Context, c cluster.Client, placement cluster.Placement) error {
	sandboxID := strings.TrimSpace(placement.SandboxID)
	if sandboxID == "" || strings.TrimSpace(placement.IncarnationID) == "" {
		return errors.New("authoritative placement is missing its secret lifecycle identity")
	}
	if placement.IsDeleting() {
		clearSecretFanoutHoldersForIncarnation(sandboxID, placement.IncarnationID)
		return nil
	}
	selfID := s.selfNodeID()
	secretsHandle := cluster.PlacementSecrets{
		Ref: placement.SecretRef, Version: placement.SecretVersion,
		Recipients:    append([]string(nil), placement.SecretRecipients...),
		IncarnationID: placement.IncarnationID, SealGeneration: placement.SecretSealGeneration,
	}
	ownerID := strings.TrimSpace(placement.OwnerNodeID)
	// Owner-only reseal. Control-plane / empty-owner secrets may be
	// coordinated by the Raft leader instead.
	if ownerID != "" && ownerID != selfID {
		return nil
	}
	if ownerID == "" && c.Leader() != "" && c.Leader() != selfID {
		return nil
	}

	// A reseal is a two-phase local/peer/Raft operation. If the process crashed after
	// Put committed generation G+1 (and its outbox) but before the final Raft
	// handle update, finish that commit before evaluating recipient health. The
	// new recipient set may be entirely healthy, so the dead-target trigger alone
	// would otherwise never repair this generation split.
	unlock := lockSecretSandboxOps(sandboxID)
	defer unlock()
	if s.store != nil && placement.SecretSealGeneration > 0 {
		local, err := s.store.GetClusterSecretForSandboxIncarnation(ctx, sandboxID, placement.IncarnationID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("load local secret generation: %w", err)
		}
		if local != nil && local.SealGeneration > placement.SecretSealGeneration {
			parsed, parseErr := secrets.ParseRef(local.Ref)
			if parseErr == nil && parsed.IncarnationID == placement.IncarnationID &&
				(placement.SecretRef == "" || local.Ref == placement.SecretRef) {
				return s.finalizeResealedSecret(ctx, c, placement, local)
			}
		}
	}
	alive := s.aliveMemberSet()

	holderIncarnationID := strings.TrimSpace(secretsHandle.IncarnationID)
	if holderIncarnationID == "" {
		holderIncarnationID = s.secretIncarnationForSeal(sandboxID)
	}
	if holderIncarnationID == "" {
		return errors.New("current placement secret incarnation is required for reseal")
	}
	hs := holderSetFor(sandboxID, holderIncarnationID)
	hs.mu.Lock()
	frozen := mapKeys(hs.targets)
	gen := hs.gen
	hs.mu.Unlock()
	// Raft is the durable source of truth for both retirement and the CAS
	// generation. Holder memory is only an ACK cache and may be incomplete or
	// stale after restart; using it here can forget a retired ciphertext copy.
	if len(placement.SecretRecipients) > 0 {
		frozen = secrets.NormalizeRecipients(placement.SecretRecipients)
		if placement.SecretSealGeneration > 0 {
			gen = placement.SecretSealGeneration
		}
	}
	if !s.anySecretTargetDead(frozen, alive, selfID) {
		return nil
	}

	replacements := s.selectReplacementRecipients(sandboxID, ownerID, s.SecretRecipientBackupCount())
	if len(replacements) == 0 {
		return fmt.Errorf("no live worker/mixed recipients for reseal")
	}
	sort.Strings(replacements)
	sortedFrozen := append([]string(nil), frozen...)
	sort.Strings(sortedFrozen)
	if sameStringSlice(sortedFrozen, replacements) {
		return nil
	}

	p := s.provider()
	if p == nil || s.store == nil {
		return fmt.Errorf("cluster secret store is not configured")
	}
	if secretsHandle.Ref == "" {
		loadIncarnationID := strings.TrimSpace(secretsHandle.IncarnationID)
		if loadIncarnationID == "" {
			loadIncarnationID = s.secretIncarnationForSeal(sandboxID)
		}
		if loadIncarnationID == "" {
			return errors.New("current placement secret incarnation is required for reseal")
		}
		rec, err := s.store.GetClusterSecretForSandboxIncarnation(ctx, sandboxID, loadIncarnationID)
		if err != nil || rec == nil {
			return fmt.Errorf("no local sealed secret to reseal")
		}
		secretsHandle.Ref = rec.Ref
		secretsHandle.Version = rec.Version
		secretsHandle.SealGeneration = rec.SealGeneration
	}
	if gen <= 0 {
		gen = placement.SecretSealGeneration
	}
	if secretsHandle.IncarnationID == "" {
		secretsHandle.IncarnationID = placement.IncarnationID
	}
	expectedInc := secretsHandle.IncarnationID
	if expectedInc == "" {
		expectedInc = s.secretIncarnationForSeal(sandboxID)
	}
	if expectedInc == "" {
		return errors.New("current placement secret incarnation is required for reseal")
	}
	expectedGen := gen
	if expectedGen <= 0 {
		if maxGen, _, maxErr := s.store.ClusterSecretSealGeneration(ctx, sandboxID, expectedInc); maxErr == nil {
			expectedGen = maxGen
		}
	}

	previousRecipients := append([]string(nil), sortedFrozen...)

	incarnationID := expectedInc
	openCtx := ctx
	if incarnationID != "" {
		openCtx = secrets.ContextWithIncarnationID(ctx, incarnationID)
	}
	bag, err := p.Open(openCtx, sandboxID, secrets.Handle{
		Ref: secretsHandle.Ref, Version: secretsHandle.Version, SealGeneration: secretsHandle.SealGeneration,
	}, selfID)
	if err != nil {
		return fmt.Errorf("open for reseal: %w", err)
	}
	if bag.IsEmpty() {
		return nil
	}
	// Journal remaining peers atomically with the resealed row so a crash
	// between Put and the post-ACK Upsert cannot drop replication work.
	resealPeers := nonSelfRecipients(replacements, selfID)
	putCtx := openCtx
	if len(resealPeers) > 0 {
		putCtx = secrets.ContextWithPutOutbox(openCtx, incarnationID, resealPeers)
	}
	retired := retiredSecretRecipients(previousRecipients, replacements, selfID)
	if len(retired) > 0 {
		putCtx = secrets.ContextWithRetiredRecipients(putCtx, retired)
	}
	handle, err := p.Put(putCtx, sandboxID, bag, replacements)
	if err != nil {
		return fmt.Errorf("reseal put: %w", err)
	}
	if handle.Ref == "" || handle.Version != secrets.RefVersion || handle.SealGeneration <= 0 {
		return errors.New("reseal provider returned an incomplete current-format handle")
	}
	newHandle := cluster.PlacementSecrets{
		Ref:            handle.Ref,
		Version:        handle.Version,
		Recipients:     append([]string(nil), replacements...),
		IncarnationID:  incarnationID,
		SealGeneration: handle.SealGeneration,
	}
	blobRec, err := s.store.GetClusterSecret(ctx, handle.Ref)
	if err != nil || blobRec == nil {
		return fmt.Errorf("load resealed blob: %v", err)
	}
	newGen := blobRec.SealGeneration
	if newGen <= 0 {
		return errors.New("resealed blob is missing its seal generation")
	}
	if handle.Ref != blobRec.Ref || handle.Version != blobRec.Version || handle.SealGeneration != newGen {
		return fmt.Errorf("reseal provider handle does not match persisted blob (handle ref=%q version=%d generation=%d; blob ref=%q version=%d generation=%d)",
			handle.Ref, handle.Version, handle.SealGeneration, blobRec.Ref, blobRec.Version, newGen)
	}
	parsedBlobRef, parseErr := secrets.ParseRef(blobRec.Ref)
	if parseErr != nil || parsedBlobRef.SandboxID != blobRec.SandboxID || parsedBlobRef.IncarnationID != incarnationID || parsedBlobRef.Version != blobRec.Version {
		return errors.New("resealed blob ref does not match the current sandbox lifecycle")
	}
	blob := secrets.SecretBlob{
		Ref:            blobRec.Ref,
		SandboxID:      blobRec.SandboxID,
		IncarnationID:  incarnationID,
		Version:        blobRec.Version,
		Recipients:     append([]string(nil), replacements...),
		SealedPayload:  blobRec.SealedPayload,
		SealGeneration: newGen,
	}
	pusher := s.secretPeerPusher()
	remoteTargets := nonSelfRecipients(replacements, selfID)
	if len(remoteTargets) == 0 {
		return errors.New("no live replacement backup is available for reseal")
	}
	if pusher == nil && len(remoteTargets) > 0 {
		return fmt.Errorf("secret peer transport unavailable; reseal remains staged locally")
	}
	var acked []string
	var pushErr error
	if pusher != nil && len(remoteTargets) > 0 {
		pushCtx, pushCancel := context.WithTimeout(ctx, secretHolderProbeTimeout)
		acked, pushErr = pusher.PushSecretBlobToPeers(pushCtx, blob, replacements)
		pushCancel()
		if len(nonSelfRecipients(acked, selfID)) == 0 {
			if pushErr == nil {
				pushErr = errors.New("no replacement peer acknowledged resealed secret")
			}
			return fmt.Errorf("replicate resealed secret before Raft promotion: %w", pushErr)
		}
	}
	// Only now make the new generation discoverable. Before this CAS, the old
	// placement and old peer copies remain a complete recovery path; after it,
	// the owner plus at least one authenticated replacement hold the new bytes.
	// expectedOwner is the node this reseal believes coordinates the secret:
	// ownerID is either selfID or "" (the leader-coordinated ownerless case)
	// by the guard at the top of expandAndResealDeadSecretTargetsForPlacement.
	// Fencing on it stops a promotion that outlived a reassignment.
	if err := c.UpdatePlacementSecretRecipients(ctx, sandboxID, replacements, newHandle, expectedInc, ownerID, expectedGen); err != nil {
		return fmt.Errorf("raft promote resealed secret: %w", err)
	}
	resetSecretHoldersForGeneration(sandboxID, blob.IncarnationID, newGen, selfID)
	setSecretHolderTargets(sandboxID, blob.IncarnationID, newGen, replacements)
	if len(acked) > 0 {
		addSecretHolderNodes(sandboxID, blob.IncarnationID, newGen, acked...)
	}
	pending := pendingRecipientsAfterAck(replacements, acked, selfID)
	if len(pending) > 0 {
		if upErr := s.persistSecretPutOutboxRecipients(context.Background(), sandboxID, blob.IncarnationID, pending, newGen); upErr != nil {
			recordSecretPutOutboxFailure()
			if s.logger != nil {
				s.logger.Warn("cluster: reseal put-outbox shrink failed",
					"sandbox_id", sandboxID, "err", upErr)
			}
		}
		if pushErr != nil {
			recordSecretFanoutFailure()
		}
	} else if delErr := s.store.DeleteSecretPutOutbox(context.Background(), sandboxID, blob.IncarnationID, newGen); delErr != nil {
		recordSecretPutOutboxFailure()
	}
	if len(retired) > 0 {
		if err := s.store.UpsertSecretDeleteOutbox(ctx, sandboxID, blob.IncarnationID, retired, newGen); err != nil {
			return fmt.Errorf("journal retired secret recipients: %w", err)
		}
		s.maybeAsyncDeleteFanout(sandboxID, blob.IncarnationID)
	}
	s.enqueueSecretFanout(sandboxID, blob, replacements, pusher)
	return nil
}

// finalizeResealedSecret recovers the crash window after the local generation
// and durable put-outbox committed but before Raft promotion. It proves a live
// replacement holds the staged generation before publishing it, then journals
// deletion of recipients retired by the transition.
func (s *Service) finalizeResealedSecret(ctx context.Context, c cluster.Client, placement cluster.Placement, local *store.ClusterSecretRecord) error {
	if local == nil {
		return nil
	}
	parsed, parseErr := secrets.ParseRef(local.Ref)
	if parseErr != nil || parsed.SandboxID != local.SandboxID || parsed.Version != local.Version || parsed.IncarnationID == "" ||
		parsed.IncarnationID != strings.TrimSpace(placement.IncarnationID) || local.SealGeneration <= 0 {
		return errors.New("interrupted reseal has an invalid current-format identity")
	}
	selfID := s.selfNodeID()
	recipients := secrets.NormalizeRecipients(local.Recipients)
	remoteTargets := nonSelfRecipients(recipients, selfID)
	if len(nonSelfRecipients(placement.SecretRecipients, selfID)) > 0 && len(remoteTargets) == 0 {
		return errors.New("interrupted reseal has no remote replacement backup")
	}
	pusher := s.secretPeerPusher()
	var holding []string
	if len(remoteTargets) > 0 {
		if pusher == nil {
			return errors.New("secret peer transport unavailable while finalizing reseal")
		}
		probeCtx, cancel := context.WithTimeout(ctx, secretHolderProbeTimeout)
		holding, _ = pusher.ProbeSecretOnPeers(probeCtx, local.SandboxID, placement.IncarnationID, remoteTargets, local.SealGeneration)
		cancel()
		if len(holding) == 0 {
			blob := secrets.SecretBlob{
				Ref: local.Ref, SandboxID: local.SandboxID, IncarnationID: placement.IncarnationID,
				Version: local.Version, Recipients: recipients, SealedPayload: local.SealedPayload,
				SealGeneration: local.SealGeneration,
			}
			pushCtx, pushCancel := context.WithTimeout(ctx, secretHolderProbeTimeout)
			holding, _ = pusher.PushSecretBlobToPeers(pushCtx, blob, remoteTargets)
			pushCancel()
		}
		if len(nonSelfRecipients(holding, selfID)) == 0 {
			return errors.New("resealed secret has no acknowledged replacement backup")
		}
	}
	handle := cluster.PlacementSecrets{
		Ref: local.Ref, Version: local.Version, Recipients: recipients,
		IncarnationID: placement.IncarnationID, SealGeneration: local.SealGeneration,
	}
	if err := c.UpdatePlacementSecretRecipients(ctx, local.SandboxID, recipients, handle, placement.IncarnationID, placement.OwnerNodeID, placement.SecretSealGeneration); err != nil {
		return fmt.Errorf("finalize interrupted secret reseal: %w", err)
	}
	pending := pendingRecipientsAfterAck(recipients, holding, selfID)
	if err := s.persistSecretPutOutboxRecipients(context.Background(), local.SandboxID, placement.IncarnationID, pending, local.SealGeneration); err != nil {
		return err
	}
	if retired := retiredSecretRecipients(placement.SecretRecipients, recipients, selfID); len(retired) > 0 {
		if err := s.store.UpsertSecretDeleteOutbox(ctx, local.SandboxID, placement.IncarnationID, retired, local.SealGeneration); err != nil {
			return err
		}
		s.maybeAsyncDeleteFanout(local.SandboxID, placement.IncarnationID)
	}
	resetSecretHoldersForGeneration(local.SandboxID, placement.IncarnationID, local.SealGeneration, selfID)
	setSecretHolderTargets(local.SandboxID, placement.IncarnationID, local.SealGeneration, recipients)
	return nil
}

func retiredSecretRecipients(previous, current []string, selfID string) []string {
	keep := make(map[string]struct{}, len(current)+1)
	for _, id := range current {
		keep[strings.TrimSpace(id)] = struct{}{}
	}
	keep[strings.TrimSpace(selfID)] = struct{}{}
	var retired []string
	for _, id := range secrets.NormalizeRecipients(previous) {
		if _, ok := keep[id]; !ok {
			retired = append(retired, id)
		}
	}
	return retired
}

// persistSecretPutOutboxRecipients normally shrinks the row atomically created
// with the sealed blob. If an interrupted operation left no matching row,
// recreate it rather than treating a zero-row UPDATE as durable success and
// losing the remaining replication work.
func (s *Service) persistSecretPutOutboxRecipients(ctx context.Context, sandboxID, incarnationID string, recipients []string, sealGeneration int64) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("cluster secret store is not configured")
	}
	err := s.store.UpdateSecretPutOutboxRecipients(ctx, sandboxID, incarnationID, recipients, sealGeneration)
	if errors.Is(err, store.ErrNotFound) && len(recipients) > 0 {
		return s.store.UpsertSecretPutOutbox(ctx, sandboxID, incarnationID, sealGeneration, recipients)
	}
	return err
}

// ReconcileSecretPutOutbox retries durable create-path peer PUTs left when the
// in-memory fan-out queue was saturated or an async push partially failed.
// Work is dispatched through a bounded worker pool mirroring delete reconcile
// so a large outbox cannot serialize the reconciler for minutes.
func (s *Service) ReconcileSecretPutOutbox(ctx context.Context) error {
	return s.reconcileSecretPutOutboxAt(ctx, secretLifecycleNow())
}

func (s *Service) reconcileSecretPutOutboxAt(ctx context.Context, now time.Time) error {
	return s.reconcileSecretPutOutboxPass(ctx, secretOutboxPass{now: now})
}

func (s *Service) reconcileSecretPutOutboxPass(ctx context.Context, pass secretOutboxPass) error {
	if s == nil || s.store == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer s.refreshSecretLifecycleMetrics(ctx)
	if s.secretPeerPusher() == nil {
		// Cluster mode with the transport not attached yet keeps the rows.
		// Standalone, both outboxes are retired by one sweep owned by the
		// delete reconciler (retireStandaloneSecretOutbox) so a tick never
		// retires twice.
		return nil
	}
	return s.sweepSecretOutbox(ctx, pass, secretOutboxSweep{
		sem:      putReconcileSem,
		inflight: &putReconcileInflight,
		listDue: func(ctx context.Context, pass secretOutboxPass, limit int) ([]secretOutboxRow, error) {
			var recs []store.SecretPutOutboxRecord
			var err error
			if pass.ignoreBackoff {
				recs, err = s.store.ListSecretPutOutboxBatch(ctx, limit)
			} else {
				recs, err = s.store.ListSecretPutOutboxDue(ctx, pass.now.UTC(), limit)
			}
			if err != nil {
				return nil, err
			}
			rows := make([]secretOutboxRow, 0, len(recs))
			for _, rec := range recs {
				if !pass.targetsRejoinedNode(rec.Recipients) {
					continue
				}
				rows = append(rows, secretOutboxRow{sandboxID: rec.SandboxID, incarnationID: rec.IncarnationID, generation: rec.SealGeneration, needsPlacement: true})
			}
			return rows, nil
		},
		deferRow: func(ctx context.Context, row secretOutboxRow) error {
			return s.store.TouchSecretPutOutbox(ctx, row.sandboxID, row.incarnationID, row.generation)
		},
		process: func(ctx context.Context, row secretOutboxRow, placements map[string]cluster.Placement) {
			s.reconcileSecretPutOutboxIncarnationWithPlacements(ctx, row.sandboxID, row.incarnationID, placements)
		},
	})
}

func (s *Service) reconcileSecretPutOutboxIncarnation(parent context.Context, sandboxID, incarnationID string) {
	if s == nil || s.store == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	rec, err := s.store.GetSecretPutOutboxForIncarnation(parent, sandboxID, incarnationID)
	if err != nil || rec == nil {
		return
	}
	placements, err := s.authoritativeSecretPlacements(parent, []string{sandboxID})
	if err != nil {
		_ = s.store.TouchSecretPutOutbox(context.Background(), sandboxID, incarnationID, rec.SealGeneration)
		if s.logger != nil {
			s.logger.Warn("cluster: authoritative placement read for secret put-outbox failed", "sandbox_id", sandboxID, "err", err)
		}
		return
	}
	s.reconcileSecretPutOutboxRecord(parent, rec, placements)
}

func (s *Service) reconcileSecretPutOutboxIncarnationWithPlacements(parent context.Context, sandboxID, incarnationID string, placements map[string]cluster.Placement) {
	rec, err := s.store.GetSecretPutOutboxForIncarnation(parent, sandboxID, incarnationID)
	if err != nil || rec == nil {
		return
	}
	s.reconcileSecretPutOutboxRecord(parent, rec, placements)
}

func (s *Service) reconcileSecretPutOutboxRecord(parent context.Context, rec *store.SecretPutOutboxRecord, placements map[string]cluster.Placement) {
	if s == nil || s.store == nil || rec == nil {
		return
	}
	sandboxID := rec.SandboxID
	if s.cfg.EnableCluster {
		if placements == nil {
			_ = s.store.TouchSecretPutOutbox(context.Background(), sandboxID, rec.IncarnationID, rec.SealGeneration)
			return
		}
		placement, ok := placements[sandboxID]
		if !ok || placement.IsDeleting() || strings.TrimSpace(placement.IncarnationID) != strings.TrimSpace(rec.IncarnationID) {
			// The put belongs to a lifecycle that is no longer authoritative.
			// Atomically turn replication work into exact-incarnation deletion
			// work so remote ciphertext cannot be stranded after ID reuse.
			peers := nonSelfRecipients(rec.Recipients, s.selfNodeID())
			if _, err := s.store.DeleteClusterSecretsOriginatorWithOutbox(parent, sandboxID, rec.IncarnationID, peers); err != nil {
				recordSecretPutOutboxFailure()
				_ = s.store.BumpSecretPutOutboxAttempt(context.Background(), sandboxID, rec.IncarnationID, rec.SealGeneration)
				if s.logger != nil {
					s.logger.Warn("cluster: stale secret put-outbox retirement failed", "sandbox_id", sandboxID, "err", err)
				}
				return
			}
			clearSecretFanoutHoldersForIncarnation(sandboxID, rec.IncarnationID)
			return
		}
		ownerID := strings.TrimSpace(placement.OwnerNodeID)
		if ownerID == "" {
			if c := s.Cluster(); c != nil {
				ownerID = strings.TrimSpace(c.Leader())
			}
		}
		if ownerID == "" || ownerID != s.selfNodeID() {
			// PUT outboxes are originator work. After reassignment the retained
			// ciphertext may still be a valid backup, but this node must no longer
			// push it as though it owned the lifecycle.
			_ = s.store.DeleteSecretPutOutbox(context.Background(), sandboxID, rec.IncarnationID, rec.SealGeneration)
			return
		}
	}
	selfID := s.selfNodeID()
	peers := nonSelfRecipients(rec.Recipients, selfID)
	if len(peers) == 0 {
		_ = s.store.UpdateSecretPutOutboxRecipients(context.Background(), sandboxID, rec.IncarnationID, nil, rec.SealGeneration)
		return
	}
	pusher := s.secretPeerPusher()
	if pusher == nil {
		return
	}
	blobRec, loadErr := s.store.GetClusterSecretForSandboxIncarnation(parent, sandboxID, rec.IncarnationID)
	if loadErr != nil && !errors.Is(loadErr, store.ErrNotFound) {
		recordSecretPutOutboxFailure()
		_ = s.store.BumpSecretPutOutboxAttempt(context.Background(), sandboxID, rec.IncarnationID, rec.SealGeneration)
		if s.logger != nil {
			s.logger.Warn("cluster: secret put-outbox local blob load failed",
				"sandbox_id", sandboxID, "err", loadErr)
		}
		return
	}
	if errors.Is(loadErr, store.ErrNotFound) || blobRec == nil {
		// Atomic destroy/reseal removes or supersedes this row in the same TX.
		// Missing ciphertext with a surviving outbox is therefore corruption or
		// data loss. Keep the obligation visible instead of falsely ACKing it.
		recordSecretPutOutboxFailure()
		_ = s.store.BumpSecretPutOutboxAttempt(context.Background(), sandboxID, rec.IncarnationID, rec.SealGeneration)
		if s.logger != nil {
			s.logger.Error("cluster: secret put-outbox ciphertext is missing; retaining recovery obligation",
				"sandbox_id", sandboxID, "seal_generation", rec.SealGeneration)
		}
		return
	}
	if blobRec.SealGeneration > rec.SealGeneration && rec.SealGeneration > 0 {
		// Stale outbox after reseal — drop; newer seal owns fan-out.
		_ = s.store.DeleteSecretPutOutbox(context.Background(), sandboxID, rec.IncarnationID, rec.SealGeneration)
		return
	}
	if blobRec.SealGeneration > 0 && blobRec.SealGeneration < rec.SealGeneration {
		recordSecretPutOutboxFailure()
		_ = s.store.BumpSecretPutOutboxAttempt(context.Background(), sandboxID, rec.IncarnationID, rec.SealGeneration)
		if s.logger != nil {
			s.logger.Error("cluster: secret put-outbox generation is newer than local ciphertext; retaining recovery obligation",
				"sandbox_id", sandboxID, "outbox_generation", rec.SealGeneration, "local_generation", blobRec.SealGeneration)
		}
		return
	}
	parsed, parseErr := secrets.ParseRef(blobRec.Ref)
	if parseErr != nil || parsed.SandboxID != blobRec.SandboxID || parsed.Version != blobRec.Version || parsed.IncarnationID == "" ||
		parsed.IncarnationID != strings.TrimSpace(rec.IncarnationID) || blobRec.SealGeneration <= 0 || rec.SealGeneration <= 0 {
		recordSecretPutOutboxFailure()
		_ = s.store.BumpSecretPutOutboxAttempt(context.Background(), sandboxID, rec.IncarnationID, rec.SealGeneration)
		if s.logger != nil {
			s.logger.Error("cluster: retained put-outbox with invalid current-format blob identity", "sandbox_id", sandboxID)
		}
		return
	}
	blob := secrets.SecretBlob{
		Ref:            blobRec.Ref,
		SandboxID:      blobRec.SandboxID,
		IncarnationID:  rec.IncarnationID,
		Version:        blobRec.Version,
		Recipients:     append([]string(nil), blobRec.Recipients...),
		SealedPayload:  blobRec.SealedPayload,
		SealGeneration: blobRec.SealGeneration,
	}
	ctx, cancel := context.WithTimeout(parent, secretDeleteAttemptTimeout)
	defer cancel()
	acked, pushErr := pusher.PushSecretBlobToPeers(ctx, blob, peers)
	_ = s.store.BumpSecretPutOutboxAttempt(context.Background(), sandboxID, rec.IncarnationID, rec.SealGeneration)
	if len(acked) > 0 {
		addSecretHolderNodes(sandboxID, blob.IncarnationID, blob.SealGeneration, acked...)
	}
	if pushErr != nil {
		recordSecretFanoutFailure()
		recordSecretPutOutboxFailure()
		if s.logger != nil {
			s.logger.Warn("cluster: secret put-outbox incomplete",
				"sandbox_id", sandboxID, "acked", len(acked), "err", pushErr)
		}
	}
	pending := pendingRecipientsAfterAck(peers, acked, selfID)
	if err := s.persistSecretPutOutboxRecipients(context.Background(), sandboxID, rec.IncarnationID, pending, rec.SealGeneration); err != nil {
		recordSecretPutOutboxFailure()
		if s.logger != nil {
			s.logger.Warn("cluster: secret put-outbox recipient update failed",
				"sandbox_id", sandboxID, "err", err)
		}
	}
}

func (s *Service) reconcileSecretDeleteOutboxIncarnation(parent context.Context, sandboxID, incarnationID string) {
	if s == nil || s.store == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	rec, err := s.store.GetSecretDeleteOutboxForIncarnation(parent, sandboxID, incarnationID)
	if err != nil || rec == nil {
		return
	}
	var placements map[string]cluster.Placement
	if rec.AwaitingPromotion {
		placements, err = s.authoritativeSecretPlacements(parent, []string{sandboxID})
		if err != nil {
			_ = s.store.TouchSecretDeleteOutbox(context.Background(), sandboxID, incarnationID, rec.Generation)
			if s.logger != nil {
				s.logger.Warn("cluster: authoritative placement read for staged secret retirement failed", "sandbox_id", sandboxID, "err", err)
			}
			return
		}
	}
	s.reconcileSecretDeleteOutboxRecord(parent, rec, placements)
}

func (s *Service) reconcileSecretDeleteOutboxIncarnationWithPlacements(parent context.Context, sandboxID, incarnationID string, placements map[string]cluster.Placement) {
	rec, err := s.store.GetSecretDeleteOutboxForIncarnation(parent, sandboxID, incarnationID)
	if err != nil || rec == nil {
		return
	}
	s.reconcileSecretDeleteOutboxRecord(parent, rec, placements)
}

func (s *Service) reconcileSecretDeleteOutboxRecord(parent context.Context, rec *store.SecretDeleteOutboxRecord, placements map[string]cluster.Placement) {
	if s == nil || s.store == nil || rec == nil {
		return
	}
	sandboxID := rec.SandboxID
	if rec.AwaitingPromotion {
		// A reseal stages this row before the Raft CAS so a post-CAS crash cannot
		// forget retired holders. Never act on it while the old placement is still
		// authoritative; the old replicas may be the only recoverable copies.
		if placements == nil {
			_ = s.store.TouchSecretDeleteOutbox(context.Background(), sandboxID, rec.IncarnationID, rec.Generation)
			return
		}
		placement, ok := placements[sandboxID]
		if ok && strings.TrimSpace(placement.IncarnationID) == rec.IncarnationID && placement.SecretSealGeneration < rec.Generation {
			// Yield this deferred row to the back of the oldest-first queue so
			// a full batch of unpromoted reseals cannot starve actionable deletes.
			// A touch, not an attempt: nothing was tried, so the row must stay
			// due on the next tick rather than back off. A missing placement
			// or a different incarnation makes this old lifecycle safe to
			// retire immediately.
			_ = s.store.TouchSecretDeleteOutbox(context.Background(), sandboxID, rec.IncarnationID, rec.Generation)
			return
		}
		promoted, err := s.store.MarkSecretDeleteOutboxPromoted(parent, sandboxID, rec.IncarnationID, rec.Generation)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("cluster: mark staged secret retirement promoted", "sandbox_id", sandboxID, "err", err)
			}
			_ = s.store.BumpSecretDeleteOutboxAttempt(context.Background(), sandboxID, rec.IncarnationID, rec.Generation)
			return
		}
		if !promoted {
			// A concurrent reseal/destroy replaced this generation. Reload on the
			// next tick rather than acting on a stale recipient snapshot.
			return
		}
		rec.AwaitingPromotion = false
	}
	// Standalone / no non-self recipients: nothing to fan out — drop the job
	// so destroy does not accumulate forever-reconciled tomb+outbox rows.
	selfID := s.selfNodeID()
	// Never discard an obligation merely because membership no longer returns
	// the peer. A removed node may still have a disk containing the ciphertext
	// and may later rejoin; the cluster transport keeps unknown/dead recipients
	// pending until an authenticated delete ACK is received.
	peers := nonSelfRecipients(rec.Recipients, selfID)
	// The one sanctioned exception: an operator has attested, for this exact
	// node identity, that its storage was destroyed. Those obligations are
	// discharged without an ACK and their evidence says so explicitly. The
	// attestation is fenced by the obligation's journalling time, so a reused
	// node id inherits nothing. See node_storage_retirement.go.
	if retired := s.nodeStorageRetirements(parent); len(retired) > 0 {
		remaining, discharged := dischargeRetiredStorageRecipients(peers, retired, rec.CreatedAt)
		if len(discharged) > 0 {
			s.recordStorageRetirementDischarge(sandboxID, rec.IncarnationID, rec.Generation, discharged)
			peers = remaining
			if err := s.store.UpdateSecretDeleteOutboxRecipients(context.Background(), sandboxID, rec.IncarnationID, peers, rec.Generation); err != nil && s.logger != nil {
				s.logger.Warn("cluster: secret delete-outbox discharge update failed",
					"sandbox_id", sandboxID, "err", err)
			}
		}
	}
	if len(peers) == 0 {
		_ = s.store.UpdateSecretDeleteOutboxRecipients(context.Background(), sandboxID, rec.IncarnationID, nil, rec.Generation)
		return
	}
	pusher := s.secretPeerPusher()
	if pusher == nil {
		// No cluster transport yet; keep the durable job for a later tick.
		return
	}
	ctx, cancel := context.WithTimeout(parent, secretDeleteAttemptTimeout)
	defer cancel()
	acked, delErr := pusher.DeleteSecretOnPeers(ctx, sandboxID, rec.IncarnationID, peers, rec.Generation)
	_ = s.store.BumpSecretDeleteOutboxAttempt(context.Background(), sandboxID, rec.IncarnationID, rec.Generation)
	pending := pendingRecipientsAfterAck(peers, acked, selfID)
	if delErr != nil {
		recordSecretFanoutFailure()
		if s.logger != nil {
			s.logger.Warn("cluster: secret delete-outbox incomplete",
				"sandbox_id", sandboxID, "pending", len(pending), "err", delErr)
		}
	}
	if err := s.store.UpdateSecretDeleteOutboxRecipients(context.Background(), sandboxID, rec.IncarnationID, pending, rec.Generation); err != nil && s.logger != nil {
		s.logger.Warn("cluster: secret delete-outbox recipient update failed",
			"sandbox_id", sandboxID, "err", err)
	}
}

func (s *Service) selfNodeID() string {
	if s == nil {
		return ""
	}
	if c := s.Cluster(); c != nil {
		return strings.TrimSpace(c.SelfNodeID())
	}
	return ""
}

func nonSelfRecipients(recipients []string, selfID string) []string {
	out := make([]string, 0, len(recipients))
	for _, id := range recipients {
		id = strings.TrimSpace(id)
		if id == "" || id == selfID {
			continue
		}
		out = append(out, id)
	}
	return out
}

// deleteReconcileWorkers caps concurrent peer-delete retries so a mass destroy
// wave cannot spawn one long-lived goroutine per sandbox.
const deleteReconcileWorkers = 64

// One retry must not monopolize a worker across multiple 30-second scheduler
// passes. Cluster-internal DELETE is idempotent; slower peers remain durable
// pending work and are retried fairly.
const secretDeleteAttemptTimeout = 15 * time.Second

// A sweep keeps filling the bounded worker pool until this batch is drained or
// its time budget expires. Attempted rows move to the back via updated_at and
// back off per store.SecretOutboxRetryDelay, so persistent failures neither
// starve fresh work nor cost a delivery attempt every tick forever.
const (
	secretDeleteReconcileBatch  = 1024
	secretDeleteReconcileBudget = 25 * time.Second
	// secretOutboxSweepMaxRows caps how many distinct obligations one pass
	// tracks (and therefore handles). Sixty-four pages is far more than the
	// time budget allows in practice — every row is a peer round-trip — so it
	// is a memory bound on the per-pass set, not a throughput limit.
	secretOutboxSweepMaxRows = 64 * secretDeleteReconcileBatch
)

var (
	deleteReconcileSem      = make(chan struct{}, deleteReconcileWorkers)
	deleteReconcileInflight sync.Map // sandboxID + incarnationID -> struct{}
	putReconcileSem         = make(chan struct{}, deleteReconcileWorkers)
	putReconcileInflight    sync.Map // sandboxID + incarnationID -> struct{}
)

func secretDeleteReconcileKey(sandboxID, incarnationID string) string {
	return strings.TrimSpace(sandboxID) + "\x00" + strings.TrimSpace(incarnationID)
}

func (s *Service) maybeAsyncDeleteFanout(sandboxID, incarnationID string) {
	sandboxID = strings.TrimSpace(sandboxID)
	incarnationID = strings.TrimSpace(incarnationID)
	if sandboxID == "" || incarnationID == "" {
		return
	}
	key := secretDeleteReconcileKey(sandboxID, incarnationID)
	if _, loaded := deleteReconcileInflight.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	select {
	case deleteReconcileSem <- struct{}{}:
		go func() {
			defer func() {
				<-deleteReconcileSem
				deleteReconcileInflight.Delete(key)
			}()
			s.reconcileSecretDeleteOutboxIncarnation(context.Background(), sandboxID, incarnationID)
		}()
	default:
		deleteReconcileInflight.Delete(key)
		// Saturated: durable outbox remains for the periodic reconciler.
	}
}

// RedactClusterSecrets returns a copy of req with credentials stripped — safe
// to replicate via raft. The Registry field's Server/Username are preserved
// (not secret) but Password is cleared; mount Credentials maps are dropped
// per-entry. Maps and slices that the caller might mutate are deep-copied so
// the original req is left untouched.
//
// Env is always cleared from the Raft spec and rides in the provider bag
// instead (§5c / T9).
//
// Mount Source and Options are kept on purpose. They are not secrets by
// contract — the read API returns them, and models.MountSpec.Validate refuses
// credential-shaped names in them at intake (an rclone connection-string
// parameter, an extra_args flag, an NFS option, an invented options key) —
// and the replicated spec must carry them to re-run the mount on the new
// owner. Everything the adapters treat as a credential rides in Credentials,
// which is sealed. Do not scrub Options here: a value removed from the spec
// but absent from the sealed bag would break the recreate it exists for.
//
// Lives next to Put/Open because the two are always called as a pair: put
// returns the provider handle, redact returns the safe-to-replicate spec, and
// writing one without the other would either leak secrets (no redact) or lose
// them on failover (no put).
func RedactClusterSecrets(req models.CreateSandboxRequest) models.CreateSandboxRequest {
	out := req
	if out.Registry != nil {
		regCopy := *out.Registry
		regCopy.Password = ""
		out.Registry = &regCopy
	}
	if len(out.Mounts) > 0 {
		ms := make([]models.MountSpec, len(out.Mounts))
		for i, m := range out.Mounts {
			mc := m
			mc.Credentials = nil
			if len(m.Options) > 0 {
				opt := make(map[string]string, len(m.Options))
				for k, v := range m.Options {
					opt[k] = v
				}
				mc.Options = opt
			}
			ms[i] = mc
		}
		out.Mounts = ms
	}
	if len(out.PlatformVolumes) > 0 {
		out.PlatformVolumes = append([]models.PlatformVolumeMount(nil), out.PlatformVolumes...)
	}
	out.Env = nil
	if out.Failover != nil {
		failover := *out.Failover
		out.Failover = &failover
	}
	return out
}

func mergeClusterSecrets(redacted models.CreateSandboxRequest, bag secrets.Secrets) models.CreateSandboxRequest {
	out := redacted
	if bag.Registry != nil {
		if out.Registry != nil && bag.Registry.Password != "" {
			registry := *out.Registry
			registry.Password = bag.Registry.Password
			out.Registry = &registry
		}
	}
	if len(bag.MountCreds) > 0 && len(out.Mounts) > 0 {
		ms := make([]models.MountSpec, len(out.Mounts))
		for i, m := range out.Mounts {
			mc := m
			if creds, ok := bag.MountCreds[m.Target]; ok {
				cp := make(map[string]string, len(creds))
				for k, v := range creds {
					cp[k] = v
				}
				mc.Credentials = cp
			}
			ms[i] = mc
		}
		out.Mounts = ms
	}
	if len(bag.Env) > 0 {
		env := make(map[string]string, len(bag.Env))
		for k, v := range bag.Env {
			env[k] = v
		}
		out.Env = env
	}
	return out
}
