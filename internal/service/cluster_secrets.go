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
	done := beginSecretAudit(s.secretAuditSink(), sandboxID, placement.Ref, actor, correlationIDFromContext(ctx))
	defer func() { done(err) }()
	p := s.provider()
	if p == nil {
		return redacted, errors.New("cluster secret store is not configured")
	}
	bag, openErr := p.Open(ctx, sandboxID, secrets.Handle{Ref: placement.Ref, Version: placement.Version}, nodeID)
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
	secretTombstones.Set(stats.Tombstones)
	age := int64(0)
	if !stats.OldestOutbox.IsZero() {
		age = int64(time.Since(stats.OldestOutbox).Seconds())
		if age < 0 {
			age = 0
		}
	}
	secretDeleteOutboxOldestAgeSeconds.Set(age)
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
	secretHolderRefreshBatch   = 512
	secretHolderRefreshWorkers = 64
	secretHolderProbeTimeout   = 5 * time.Second
)

// refreshSecretHolderPossession re-probes intended remote recipients that are
// approaching ACK TTL. Targets are independent from confirmed ACKs, so a
// timeout or 404 can recover on a later pass without a membership flap.
func (s *Service) refreshSecretHolderPossession(ctx context.Context) {
	if s == nil {
		return
	}
	pusher := s.secretPeerPusher()
	if pusher == nil {
		return
	}
	selfID := s.selfNodeID()
	type job struct {
		sandboxID string
		gen       int64
		peers     []string
		lastProbe time.Time
	}
	var jobs []job
	now := time.Now()
	// Refresh after two thirds of the TTL, leaving one full ticker interval to
	// retry before an ACK expires.
	refreshBefore := now.Add(-(secretHolderACKTTL * 2 / 3))
	secretFanoutHolders.Range(func(key, val any) bool {
		if ctx.Err() != nil {
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
		if ctx.Err() != nil {
			break
		}
		j := j
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			probeCtx, cancel := context.WithTimeout(ctx, secretHolderProbeTimeout)
			holding, probeErr := pusher.ProbeSecretOnPeers(probeCtx, j.sandboxID, j.peers, j.gen)
			cancel()
			if probeErr != nil {
				probeFailures.Lock()
				probeFailures.count++
				if probeFailures.first == nil {
					probeFailures.first = probeErr
				}
				probeFailures.Unlock()
			}
			hs := holderSetFor(j.sandboxID)
			hs.mu.Lock()
			defer hs.mu.Unlock()
			if hs.gen != j.gen && hs.gen != 0 {
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
				}
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
	// Standalone / no non-self recipients: nothing to fan out — drop the job
	// so destroy does not accumulate forever-reconciled tomb+outbox rows.
	selfID := s.selfNodeID()
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
