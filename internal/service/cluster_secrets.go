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

func (s *Service) secretsFromRequest(req models.CreateSandboxRequest) secrets.Secrets {
	return secretsFromRequest(req)
}

// OpenClusterSecretsForNode resolves a replicated secret handle and merges the
// decrypted credentials back into a redacted spec. The handle (Ref/Version)
// is the only carrier — placements never embed sealed bytes.
//
// sandboxID is preferred for the audit event; when empty it is parsed from
// placement.Ref (cluster-secret://sandbox/{id}/vN).
func (s *Service) OpenClusterSecretsForNode(ctx context.Context, sandboxID string, redacted models.CreateSandboxRequest, placement cluster.PlacementSecrets, nodeID string) (out models.CreateSandboxRequest, err error) {
	if placement.Ref == "" {
		return redacted, nil
	}
	if strings.TrimSpace(sandboxID) == "" {
		sandboxID = sandboxIDFromSecretRef(placement.Ref)
	}
	actor := nodeID
	if actor == "" {
		actor = s.auditActor()
	}
	done := beginSecretAuditInc(s.secretAuditSink(), sandboxID, placement.Ref, actor, correlationIDFromContext(ctx), s.secretIncarnationForSeal(sandboxID))
	defer func() { done(err) }()
	p := s.provider()
	if p == nil {
		return redacted, errors.New("cluster secret store is not configured")
	}
	bag, openErr := p.Open(ctx, sandboxID, secrets.Handle{
		Ref: placement.Ref, Version: placement.Version, SealGeneration: placement.SealGeneration,
	}, nodeID)
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

func (s *Service) DeleteClusterSecrets(ctx context.Context, sandboxID string) error {
	if s == nil {
		return nil
	}
	unlock := lockSecretSandboxOps(sandboxID)
	defer unlock()
	// Capture recipients before local delete so durable outbox / fan-out knows
	// which peers may hold a copy.
	recipients := s.secretRecipientsForSandbox(ctx, sandboxID)
	err := s.deleteClusterSecretsOriginator(ctx, sandboxID, recipients)
	s.maybeAsyncDeleteFanout(sandboxID, recipients)
	return err
}

// deleteClusterSecretsOriginator tombs, deletes local rows, and enqueues the
// peer-delete outbox in one SQLite transaction when fan-out is enabled and
// there is at least one non-self recipient. Standalone destroys must not leave
// forever-pending outbox rows or permanent tombs.
func (s *Service) deleteClusterSecretsOriginator(ctx context.Context, sandboxID string, recipients []string) error {
	if s == nil {
		return nil
	}
	clearSecretFanoutHolders(sandboxID)
	var peers []string
	if len(recipients) > 0 {
		// Avoid SelfNodeID() when there is nothing to filter — rollback/test
		// stubs may panic on identity lookup during seal-failure retract.
		peers = nonSelfRecipients(recipients, s.selfNodeID())
	}
	if s.store != nil && len(peers) > 0 {
		_, err := s.store.DeleteClusterSecretsOriginatorWithOutbox(ctx, sandboxID, peers)
		return err
	}
	if p := s.provider(); p != nil {
		return p.Delete(ctx, sandboxID)
	}
	if s.store != nil {
		return s.store.DeleteClusterSecretsRowsOnly(ctx, sandboxID)
	}
	return nil
}

// DeleteClusterSecretsLocal applies a peer DELETE with generation gating and
// a local tombstone so delayed PUTs cannot resurrect deleted credentials.
func (s *Service) DeleteClusterSecretsLocal(ctx context.Context, sandboxID string, generation int64) error {
	if s == nil {
		return nil
	}
	unlock := lockSecretSandboxOps(sandboxID)
	defer unlock()
	var err error
	if s.store != nil {
		err = s.store.ApplyPeerSecretDelete(ctx, sandboxID, generation)
	} else if p := s.provider(); p != nil {
		err = p.Delete(ctx, sandboxID)
	}
	clearSecretFanoutHolders(sandboxID)
	return err
}

// ReconcileSecretDeleteOutbox retries durable peer DELETEs after boot / crash
// and on the periodic ticker. Work is dispatched through the bounded delete
// fan-out pool so a large outbox cannot serialize the reconciler for minutes.
func (s *Service) ReconcileSecretDeleteOutbox(ctx context.Context) error {
	if s == nil || s.store == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer s.refreshSecretLifecycleMetrics(ctx)
	if s.secretPeerPusher() == nil {
		return nil
	}
	sweepCtx, cancel := context.WithTimeout(ctx, secretDeleteReconcileBudget)
	defer cancel()
	for {
		rows, err := s.store.ListSecretDeleteOutboxBatch(sweepCtx, secretDeleteReconcileBatch)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				return nil
			}
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		jobs := make(chan string)
		var wg sync.WaitGroup
		var processed atomic.Int64
		workers := min(deleteReconcileWorkers, len(rows))
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for sandboxID := range jobs {
					if _, loaded := deleteReconcileInflight.LoadOrStore(sandboxID, struct{}{}); loaded {
						continue
					}
					select {
					case deleteReconcileSem <- struct{}{}:
						s.reconcileSecretDeleteOutboxOnceContext(sweepCtx, sandboxID)
						processed.Add(1)
						<-deleteReconcileSem
						deleteReconcileInflight.Delete(sandboxID)
					case <-sweepCtx.Done():
						deleteReconcileInflight.Delete(sandboxID)
						return
					}
				}
			}()
		}
		for _, rec := range rows {
			select {
			case jobs <- rec.SandboxID:
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
	if s == nil || s.cfg.SecretAuditRetentionDays <= 0 {
		return nil
	}
	c := s.Cluster()
	if c == nil {
		return nil
	}
	return c.PruneAuditACL(ctx, time.Now().UTC())
}

// StartSecretDeleteOutboxReconcile runs periodic peer-delete retries so offline
// recipients are not permanently abandoned after the boot pass. When membership
// gains a newly-alive node, reconcile runs immediately and secrets are re-fanout
// so holders re-ACK after rejoin.
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
				rejoined := false
				for id := range alive {
					if _, ok := prevAlive[id]; !ok {
						rejoined = true
						break
					}
				}
				prevAlive = alive
				if err := s.ReconcileSecretDeleteOutbox(ctx); err != nil && s.logger != nil {
					s.logger.Warn("cluster: secret delete-outbox reconcile failed", "err", err)
				}
				if err := s.ReconcileSecretPutOutbox(ctx); err != nil && s.logger != nil {
					s.logger.Warn("cluster: secret put-outbox reconcile failed", "err", err)
				}
				s.refreshSecretHolderPossession(ctx)
				if rejoined {
					if err := s.ReFanoutClusterSecrets(ctx); err != nil && s.logger != nil {
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
	for _, m := range c.Members() {
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
	// secretHolderRefreshBatch caps fair-queue work per tick so a 100k fleet
	// can still refresh within ACK TTL (90s) across ~3×30s ticks at 4096/tick.
	// Raise further only with holder-refresh latency budgets in mind — each
	// job may probe + re-push peers under secretHolderRefreshBudget.
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
	type job struct {
		sandboxID string
		gen       int64
		peers     []string
		lastProbe time.Time
	}
	var expandIDs []string
	secretFanoutHolders.Range(func(key, val any) bool {
		if refreshCtx.Err() != nil {
			return false
		}
		sandboxID, _ := key.(string)
		hs, _ := val.(*holderNodeSet)
		if sandboxID == "" || hs == nil {
			return true
		}
		hs.mu.Lock()
		needs := s.anySecretTargetDead(mapKeys(hs.targets), alive, selfID)
		hs.mu.Unlock()
		if needs {
			expandIDs = append(expandIDs, sandboxID)
		}
		return true
	})
	sort.Strings(expandIDs)
	if len(expandIDs) > secretHolderRefreshBatch {
		expandIDs = expandIDs[:secretHolderRefreshBatch]
	}
	for _, sandboxID := range expandIDs {
		if refreshCtx.Err() != nil {
			break
		}
		if err := s.expandAndResealDeadSecretTargets(refreshCtx, sandboxID); err != nil && s.logger != nil {
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
		sandboxID, _ := key.(string)
		hs, _ := val.(*holderNodeSet)
		if sandboxID == "" || hs == nil {
			return true
		}
		hs.mu.Lock()
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
		if !needsProbe || len(peers) == 0 || gen <= 0 {
			return true
		}
		sort.Strings(peers)
		jobs = append(jobs, job{sandboxID: sandboxID, gen: gen, peers: peers, lastProbe: lastProbe})
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
	for _, j := range jobs {
		if v, ok := secretFanoutHolders.Load(j.sandboxID); ok {
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
			holding, probeErr := pusher.ProbeSecretOnPeers(probeCtx, j.sandboxID, j.peers, j.gen)
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
			hs := holderSetFor(j.sandboxID)
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
			rec, loadErr := s.store.GetClusterSecretForSandbox(refreshCtx, j.sandboxID)
			if loadErr != nil || rec == nil || rec.SealGeneration < j.gen {
				return
			}
			blob := secrets.SecretBlob{
				Ref:            rec.Ref,
				SandboxID:      rec.SandboxID,
				Version:        rec.Version,
				Recipients:     append([]string(nil), rec.Recipients...),
				SealedPayload:  rec.SealedPayload,
				SealGeneration: rec.SealGeneration,
			}
			if parsed, parseErr := secrets.ParseRef(rec.Ref); parseErr == nil {
				blob.IncarnationID = parsed.IncarnationID
			}
			pushCtx, pushCancel := context.WithTimeout(refreshCtx, secretHolderProbeTimeout)
			acked, pushErr := pusher.PushSecretBlobToPeers(pushCtx, blob, missing)
			pushCancel()
			if len(acked) > 0 {
				addSecretHolderNodes(j.sandboxID, j.gen, acked...)
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
	selfID := s.selfNodeID()
	placement, hasPlacement := c.PlacementOf(sandboxID)
	if hasPlacement {
		ownerID := strings.TrimSpace(placement.OwnerNodeID)
		// Owner-only reseal. Control-plane / empty-owner secrets may be
		// coordinated by the Raft leader instead.
		if ownerID != "" && ownerID != selfID {
			return nil
		}
		if ownerID == "" && c.Leader() != "" && c.Leader() != selfID {
			return nil
		}
	}

	// A reseal is a two-phase local/peer/Raft operation. If the process crashed after
	// Put committed generation G+1 (and its outbox) but before the final Raft
	// handle update, finish that commit before evaluating recipient health. The
	// new recipient set may be entirely healthy, so the dead-target trigger alone
	// would otherwise never repair this generation split.
	unlock := lockSecretSandboxOps(sandboxID)
	defer unlock()
	if hasPlacement && s.store != nil && placement.SecretSealGeneration > 0 {
		local, err := s.store.GetClusterSecretForSandbox(ctx, sandboxID)
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

	hs := holderSetFor(sandboxID)
	hs.mu.Lock()
	frozen := mapKeys(hs.targets)
	gen := hs.gen
	hs.mu.Unlock()
	if !s.anySecretTargetDead(frozen, alive, selfID) {
		// Fall back to placement recipients when holder memory is empty but
		// the FSM still lists dead backups.
		if hasPlacement && len(placement.SecretRecipients) > 0 {
			frozen = append([]string(nil), placement.SecretRecipients...)
			if !s.anySecretTargetDead(frozen, alive, selfID) {
				return nil
			}
		} else if p, ok := c.PlacementOf(sandboxID); ok && len(p.SecretRecipients) > 0 {
			frozen = append([]string(nil), p.SecretRecipients...)
			if !s.anySecretTargetDead(frozen, alive, selfID) {
				return nil
			}
		} else {
			return nil
		}
	}

	replacements := s.SelectReplacementRecipients(sandboxID, s.SecretRecipientBackupCount())
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
	secretsHandle := c.SecretsOf(sandboxID)
	if secretsHandle.Ref == "" {
		rec, err := s.store.GetClusterSecretForSandbox(ctx, sandboxID)
		if err != nil || rec == nil {
			return fmt.Errorf("no local sealed secret to reseal")
		}
		secretsHandle.Ref = rec.Ref
		secretsHandle.Version = rec.Version
		secretsHandle.SealGeneration = rec.SealGeneration
	}
	if hasPlacement {
		if gen <= 0 {
			gen = placement.SecretSealGeneration
		}
		if secretsHandle.IncarnationID == "" {
			secretsHandle.IncarnationID = placement.IncarnationID
		}
	}
	expectedInc := secretsHandle.IncarnationID
	if expectedInc == "" {
		expectedInc = s.secretIncarnationForSeal(sandboxID)
	}
	expectedGen := gen
	if expectedGen <= 0 {
		if maxGen, maxErr := s.store.MaxClusterSecretSealGeneration(ctx, sandboxID); maxErr == nil {
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
	newHandle := cluster.PlacementSecrets{
		Ref:            handle.Ref,
		Version:        handle.Version,
		Recipients:     append([]string(nil), replacements...),
		IncarnationID:  incarnationID,
		SealGeneration: handle.SealGeneration,
	}
	if newHandle.SealGeneration <= 0 {
		if blobRec, loadErr := s.store.GetClusterSecretForSandbox(ctx, sandboxID); loadErr == nil && blobRec != nil {
			newHandle.SealGeneration = blobRec.SealGeneration
		}
	}
	blobRec, err := s.store.GetClusterSecretForSandbox(ctx, sandboxID)
	if err != nil || blobRec == nil {
		return fmt.Errorf("load resealed blob: %v", err)
	}
	newGen := blobRec.SealGeneration
	if newGen <= 0 {
		newGen = expectedGen + 1
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
	if blob.IncarnationID == "" {
		if parsed, parseErr := secrets.ParseRef(blobRec.Ref); parseErr == nil {
			blob.IncarnationID = parsed.IncarnationID
		}
	}
	pusher := s.secretPeerPusher()
	remoteTargets := nonSelfRecipients(replacements, selfID)
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
	if err := c.UpdatePlacementSecretRecipients(ctx, sandboxID, replacements, newHandle, expectedInc, expectedGen); err != nil {
		return fmt.Errorf("raft promote resealed secret: %w", err)
	}
	resetSecretHoldersForGeneration(sandboxID, newGen, selfID)
	setSecretHolderTargets(sandboxID, newGen, replacements)
	if len(acked) > 0 {
		addSecretHolderNodes(sandboxID, newGen, acked...)
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
		if err := s.store.UpsertSecretDeleteOutbox(ctx, sandboxID, retired, newGen); err != nil {
			return fmt.Errorf("journal retired secret recipients: %w", err)
		}
		go s.reconcileSecretDeleteOutboxOnce(sandboxID)
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
	selfID := s.selfNodeID()
	recipients := secrets.NormalizeRecipients(local.Recipients)
	remoteTargets := nonSelfRecipients(recipients, selfID)
	pusher := s.secretPeerPusher()
	var holding []string
	if len(remoteTargets) > 0 {
		if pusher == nil {
			return errors.New("secret peer transport unavailable while finalizing reseal")
		}
		probeCtx, cancel := context.WithTimeout(ctx, secretHolderProbeTimeout)
		holding, _ = pusher.ProbeSecretOnPeers(probeCtx, local.SandboxID, remoteTargets, local.SealGeneration)
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
	if err := c.UpdatePlacementSecretRecipients(ctx, local.SandboxID, recipients, handle, placement.IncarnationID, placement.SecretSealGeneration); err != nil {
		return fmt.Errorf("finalize interrupted secret reseal: %w", err)
	}
	pending := pendingRecipientsAfterAck(recipients, holding, selfID)
	if err := s.persistSecretPutOutboxRecipients(context.Background(), local.SandboxID, placement.IncarnationID, pending, local.SealGeneration); err != nil {
		return err
	}
	if retired := retiredSecretRecipients(placement.SecretRecipients, recipients, selfID); len(retired) > 0 {
		if err := s.store.UpsertSecretDeleteOutbox(ctx, local.SandboxID, retired, local.SealGeneration); err != nil {
			return err
		}
		go s.reconcileSecretDeleteOutboxOnce(local.SandboxID)
	}
	resetSecretHoldersForGeneration(local.SandboxID, local.SealGeneration, selfID)
	setSecretHolderTargets(local.SandboxID, local.SealGeneration, recipients)
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

func setSecretHolderTargetsUnlocked(hs *holderNodeSet, gen int64, nodeIDs []string) {
	if hs == nil {
		return
	}
	if gen > 0 && hs.gen != 0 && hs.gen != gen {
		hs.nodes = make(map[string]time.Time)
		hs.lastProbe = time.Time{}
	}
	if gen > 0 {
		hs.gen = gen
	}
	targets := make(map[string]struct{}, len(nodeIDs))
	for _, id := range nodeIDs {
		if id = strings.TrimSpace(id); id != "" {
			targets[id] = struct{}{}
		}
	}
	hs.targets = targets
	for id := range hs.nodes {
		if _, ok := targets[id]; !ok {
			delete(hs.nodes, id)
		}
	}
}

// ReconcileSecretPutOutbox retries durable create-path peer PUTs left when the
// in-memory fan-out queue was saturated or an async push partially failed.
// Work is dispatched through a bounded worker pool mirroring delete reconcile
// so a large outbox cannot serialize the reconciler for minutes.
func (s *Service) ReconcileSecretPutOutbox(ctx context.Context) error {
	if s == nil || s.store == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer s.refreshSecretLifecycleMetrics(ctx)
	if s.secretPeerPusher() == nil {
		return nil
	}
	sweepCtx, cancel := context.WithTimeout(ctx, secretDeleteReconcileBudget)
	defer cancel()
	for {
		rows, err := s.store.ListSecretPutOutboxBatch(sweepCtx, secretDeleteReconcileBatch)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				return nil
			}
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		jobs := make(chan string)
		var wg sync.WaitGroup
		var processed atomic.Int64
		workers := min(deleteReconcileWorkers, len(rows))
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for sandboxID := range jobs {
					if _, loaded := putReconcileInflight.LoadOrStore(sandboxID, struct{}{}); loaded {
						continue
					}
					select {
					case putReconcileSem <- struct{}{}:
						s.reconcileSecretPutOutboxOnceContext(sweepCtx, sandboxID)
						processed.Add(1)
						<-putReconcileSem
						putReconcileInflight.Delete(sandboxID)
					case <-sweepCtx.Done():
						putReconcileInflight.Delete(sandboxID)
						return
					}
				}
			}()
		}
		for _, rec := range rows {
			select {
			case jobs <- rec.SandboxID:
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
	}
}

func (s *Service) reconcileSecretPutOutboxOnceContext(parent context.Context, sandboxID string) {
	if s == nil || s.store == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	rec, err := s.store.GetSecretPutOutbox(parent, sandboxID)
	if err != nil || rec == nil {
		return
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
	blobRec, loadErr := s.store.GetClusterSecretForSandbox(parent, sandboxID)
	if loadErr != nil || blobRec == nil {
		// Local row gone (destroy/reseal race) — drop the durable job.
		_ = s.store.DeleteSecretPutOutbox(context.Background(), sandboxID, rec.IncarnationID, rec.SealGeneration)
		return
	}
	if blobRec.SealGeneration > 0 && rec.SealGeneration > 0 && blobRec.SealGeneration != rec.SealGeneration {
		// Stale outbox after reseal — drop; newer seal owns fan-out.
		_ = s.store.DeleteSecretPutOutbox(context.Background(), sandboxID, rec.IncarnationID, rec.SealGeneration)
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
	if blob.IncarnationID == "" {
		if parsed, parseErr := secrets.ParseRef(blobRec.Ref); parseErr == nil {
			blob.IncarnationID = parsed.IncarnationID
		}
	}
	ctx, cancel := context.WithTimeout(parent, secretDeleteAttemptTimeout)
	defer cancel()
	acked, pushErr := pusher.PushSecretBlobToPeers(ctx, blob, peers)
	_ = s.store.BumpSecretPutOutboxAttempt(context.Background(), sandboxID, rec.IncarnationID, rec.SealGeneration)
	if len(acked) > 0 {
		addSecretHolderNodes(sandboxID, blob.SealGeneration, acked...)
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

func (s *Service) reconcileSecretDeleteOutboxOnce(sandboxID string) {
	s.reconcileSecretDeleteOutboxOnceContext(context.Background(), sandboxID)
}

func (s *Service) reconcileSecretDeleteOutboxOnceContext(parent context.Context, sandboxID string) {
	if s == nil || s.store == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	rec, err := s.store.GetSecretDeleteOutbox(parent, sandboxID)
	if err != nil || rec == nil {
		return
	}
	if rec.AwaitingPromotion {
		// A reseal stages this row before the Raft CAS so a post-CAS crash cannot
		// forget retired holders. Never act on it while the old placement is still
		// authoritative; the old replicas may be the only recoverable copies.
		c := s.Cluster()
		if c == nil {
			_ = s.store.BumpSecretDeleteOutboxAttempt(context.Background(), sandboxID)
			return
		}
		placement, ok := c.PlacementOf(sandboxID)
		if !ok || placement.SecretSealGeneration < rec.Generation {
			// Yield this deferred row to the back of the oldest-first queue so
			// a full batch of unpromoted reseals cannot starve actionable deletes.
			_ = s.store.BumpSecretDeleteOutboxAttempt(context.Background(), sandboxID)
			return
		}
		promoted, err := s.store.MarkSecretDeleteOutboxPromoted(parent, sandboxID, rec.Generation)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("cluster: mark staged secret retirement promoted", "sandbox_id", sandboxID, "err", err)
			}
			_ = s.store.BumpSecretDeleteOutboxAttempt(context.Background(), sandboxID)
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
	if len(peers) == 0 {
		_ = s.store.UpdateSecretDeleteOutboxRecipients(context.Background(), sandboxID, nil, rec.Generation)
		return
	}
	pusher := s.secretPeerPusher()
	if pusher == nil {
		// No cluster transport yet; keep the durable job for a later tick.
		return
	}
	ctx, cancel := context.WithTimeout(parent, secretDeleteAttemptTimeout)
	defer cancel()
	_, pending, delErr := pusher.DeleteSecretOnPeers(ctx, sandboxID, peers, rec.Generation)
	_ = s.store.BumpSecretDeleteOutboxAttempt(context.Background(), sandboxID)
	if delErr != nil {
		recordSecretFanoutFailure()
		if s.logger != nil {
			s.logger.Warn("cluster: secret delete-outbox incomplete",
				"sandbox_id", sandboxID, "pending", len(pending), "err", delErr)
		}
	}
	if err := s.store.UpdateSecretDeleteOutboxRecipients(context.Background(), sandboxID, pending, rec.Generation); err != nil && s.logger != nil {
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
// its time budget expires. Attempted rows move to the back via updated_at, so
// persistent failures cannot starve fresh work.
const (
	secretDeleteReconcileBatch  = 1024
	secretDeleteReconcileBudget = 25 * time.Second
)

var (
	deleteReconcileSem      = make(chan struct{}, deleteReconcileWorkers)
	deleteReconcileInflight sync.Map // sandboxID -> struct{}
	putReconcileSem         = make(chan struct{}, deleteReconcileWorkers)
	putReconcileInflight    sync.Map // sandboxID -> struct{}
)

func (s *Service) maybeAsyncDeleteFanout(sandboxID string, recipients []string) {
	_ = recipients
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return
	}
	if _, loaded := deleteReconcileInflight.LoadOrStore(sandboxID, struct{}{}); loaded {
		return
	}
	select {
	case deleteReconcileSem <- struct{}{}:
		go func() {
			defer func() {
				<-deleteReconcileSem
				deleteReconcileInflight.Delete(sandboxID)
			}()
			s.reconcileSecretDeleteOutboxOnce(sandboxID)
		}()
	default:
		deleteReconcileInflight.Delete(sandboxID)
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
