package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
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

// Aliases kept so existing tests and call sites that reference the old
// package-local constants keep compiling after the move into pkg/secrets.
const (
	clusterSecretVersion         = secrets.RefVersion
	clusterSecretEnvelopeVersion = secrets.EnvelopeVersion
)

// provider returns the configured secrets.Provider, lazily building a
// LocalProvider from store (+ cipher when present) when tests construct
// &Service{...} without going through New. Store alone is enough to surface
// ErrNotFound on Open; Put still requires cipher. Non-local backends must be
// installed via ConfigureSecretProvider / secretProvider assignment.
func (s *Service) provider() secrets.Provider {
	if s == nil {
		return nil
	}
	if s.secretProvider != nil {
		return s.secretProvider
	}
	if s.store == nil {
		return nil
	}
	if secrets.NormalizeProviderName(s.cfg.SecretProvider) != secrets.ProviderLocal {
		return nil
	}
	s.secretProvider = secrets.NewLocalProvider(s.cipher, newSecretBlobStore(s.store))
	return s.secretProvider
}

// secretsFromRequest extracts the credential-bearing portions of req into the
// Provider Secrets bag. MountCreds is keyed by MountSpec.Target. Env is only
// included when includeEnv is true (SB_SECRET_ENV_SEAL_ENABLED) so default
// creates do not suddenly get a secret ref (outside-voice #2).
func secretsFromRequest(req models.CreateSandboxRequest) secrets.Secrets {
	return secretsFromRequestOpts(req, false)
}

func secretsFromRequestOpts(req models.CreateSandboxRequest, includeEnv bool) secrets.Secrets {
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
	if includeEnv && len(req.Env) > 0 {
		env := make(map[string]string, len(req.Env))
		for k, v := range req.Env {
			env[k] = v
		}
		bag.Env = env
	}
	return bag
}

func (s *Service) secretsFromRequest(req models.CreateSandboxRequest) secrets.Secrets {
	includeEnv := s != nil && s.cfg.SecretEnvSealEnabled
	return secretsFromRequestOpts(req, includeEnv)
}

// SealClusterSecretsForRecipient extracts secret-bearing portions of req and
// seals them to a single recipient. Used by tests and any in-memory seal path
// that does not persist a provider row. Prefer PutClusterSecretsForRecipient
// for cluster placement.
func (s *Service) SealClusterSecretsForRecipient(req models.CreateSandboxRequest, recipient string) ([]byte, error) {
	bag := s.secretsFromRequest(req)
	if s == nil || s.cipher == nil {
		if bag.IsEmpty() {
			return nil, nil
		}
		return nil, errors.New("cluster secrets cipher is not configured")
	}
	return secrets.SealEnvelope(s.cipher, bag, []string{recipient})
}

// PutClusterSecretsForRecipient stores the credential-bearing parts of req
// behind a provider ref for a single recipient. Prefer SealAndDistribute at
// create sites so HA sandboxes get recipient-set sealing + async fan-out.
func (s *Service) PutClusterSecretsForRecipient(ctx context.Context, sandboxID string, req models.CreateSandboxRequest, recipient string) (cluster.PlacementSecrets, error) {
	return s.SealAndDistribute(ctx, sandboxID, req, []string{recipient}, SealStrict)
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

func (s *Service) OpenClusterSecrets(ctx context.Context, redacted models.CreateSandboxRequest, placement cluster.PlacementSecrets) (models.CreateSandboxRequest, error) {
	return s.OpenClusterSecretsForNode(ctx, "", redacted, placement, "")
}

func (s *Service) DeleteClusterSecrets(ctx context.Context, sandboxID string) error {
	if s == nil {
		return nil
	}
	unlock := lockSecretSandboxOps(sandboxID)
	defer unlock()
	// Capture recipients before local delete so durable outbox / fan-out knows
	// which peers may hold a copy.
	var recipients []string
	if s.cfg.SecretRecipientFanoutEnabled {
		recipients = s.secretRecipientsForSandbox(ctx, sandboxID)
	}
	err := s.deleteClusterSecretsOriginator(ctx, sandboxID, recipients)
	if s.cfg.SecretRecipientFanoutEnabled {
		s.maybeAsyncDeleteFanout(sandboxID, recipients)
	}
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
	if s.store != nil && s.cfg.SecretRecipientFanoutEnabled && len(peers) > 0 {
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
	if s == nil || s.store == nil || !s.cfg.SecretRecipientFanoutEnabled {
		return nil
	}
	rows, err := s.store.ListSecretDeleteOutbox(ctx)
	if err != nil {
		return err
	}
	for _, rec := range rows {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.maybeAsyncDeleteFanout(rec.SandboxID, rec.Recipients)
	}
	return nil
}

// StartSecretDeleteOutboxReconcile runs periodic peer-delete retries so offline
// recipients are not permanently abandoned after the boot pass. When membership
// gains a newly-alive node, reconcile runs immediately and secrets are re-fanout
// so holders re-ACK after rejoin.
func (s *Service) StartSecretDeleteOutboxReconcile(ctx context.Context) {
	if s == nil || s.store == nil || !s.cfg.SecretRecipientFanoutEnabled {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
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

// refreshSecretHolderPossession re-probes in-memory remote holders that are
// approaching ACK TTL. It deliberately does not scan the full cluster_secrets
// table (that would be O(sandboxes)×RF probes per tick at fleet scale).
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
	}
	var jobs []job
	refreshBefore := time.Now().Add(secretHolderACKTTL / 3)
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
		peers := make([]string, 0, len(hs.nodes))
		needsProbe := false
		for id, at := range hs.nodes {
			if id == "" || id == selfID {
				continue
			}
			peers = append(peers, id)
			if at.IsZero() || at.Before(refreshBefore) {
				needsProbe = true
			}
		}
		hs.mu.Unlock()
		if !needsProbe || len(peers) == 0 || gen <= 0 {
			return true
		}
		jobs = append(jobs, job{sandboxID: sandboxID, gen: gen, peers: peers})
		// Hard cap per tick so a partitioned peer cannot stretch past ACK TTL.
		return len(jobs) < deleteReconcileWorkers
	})
	for _, j := range jobs {
		if ctx.Err() != nil {
			return
		}
		holding, probeErr := pusher.ProbeSecretOnPeers(ctx, j.sandboxID, j.peers, j.gen)
		if probeErr != nil && s.logger != nil {
			s.logger.Warn("cluster: secret holder possession probe incomplete",
				"sandbox_id", j.sandboxID, "err", probeErr)
		}
		hs := holderSetFor(j.sandboxID)
		hs.mu.Lock()
		if hs.gen == j.gen || hs.gen == 0 {
			hs.gen = j.gen
			if hs.nodes == nil {
				hs.nodes = make(map[string]time.Time)
			}
			for id := range hs.nodes {
				if id == selfID {
					continue
				}
				delete(hs.nodes, id)
			}
			now := time.Now()
			if selfID != "" {
				hs.nodes[selfID] = now
			}
			for _, id := range holding {
				id = strings.TrimSpace(id)
				if id != "" {
					hs.nodes[id] = now
				}
			}
		}
		hs.mu.Unlock()
	}
}

func (s *Service) reconcileSecretDeleteOutboxOnce(sandboxID string) {
	if s == nil || s.store == nil {
		return
	}
	rec, err := s.store.GetSecretDeleteOutbox(context.Background(), sandboxID)
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
// Env is deep-copied by default (pre-env-seal). Prefer
// RedactClusterSecretsOpts / Service.redactClusterSecrets when
// SB_SECRET_ENV_SEAL_ENABLED so Env is cleared from the raft spec and rides
// in the provider bag instead (§5c / T9).
//
// Lives next to Put/Open because the two are always called as a pair: put
// returns the provider handle, redact returns the safe-to-replicate spec, and
// writing one without the other would either leak secrets (no redact) or lose
// them on failover (no put).
func RedactClusterSecrets(req models.CreateSandboxRequest) models.CreateSandboxRequest {
	return RedactClusterSecretsOpts(req, false)
}

// RedactClusterSecretsOpts is RedactClusterSecrets with an explicit env-seal
// switch. When sealEnv is true, out.Env is nil (plaintext must not enter Raft).
func RedactClusterSecretsOpts(req models.CreateSandboxRequest, sealEnv bool) models.CreateSandboxRequest {
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
	if sealEnv {
		out.Env = nil
	} else if len(out.Env) > 0 {
		env := make(map[string]string, len(out.Env))
		for k, v := range out.Env {
			env[k] = v
		}
		out.Env = env
	}
	if out.Failover != nil {
		failover := *out.Failover
		out.Failover = &failover
	}
	return out
}

func (s *Service) redactClusterSecrets(req models.CreateSandboxRequest) models.CreateSandboxRequest {
	sealEnv := s != nil && s.cfg.SecretEnvSealEnabled
	return RedactClusterSecretsOpts(req, sealEnv)
}

// UnsealClusterSecrets opens a sealed bag and merges the credentials back
// into the previously-redacted spec. Returns the merged spec; the input
// is not mutated. An empty sealed payload returns redacted unchanged so
// callers don't have to short-circuit themselves.
func (s *Service) UnsealClusterSecrets(redacted models.CreateSandboxRequest, sealed []byte) (models.CreateSandboxRequest, error) {
	return s.UnsealClusterSecretsForNode(redacted, sealed, "")
}

func (s *Service) UnsealClusterSecretsForNode(redacted models.CreateSandboxRequest, sealed []byte, nodeID string) (models.CreateSandboxRequest, error) {
	if len(sealed) == 0 {
		return redacted, nil
	}
	if s == nil || s.cipher == nil {
		return redacted, errors.New("cluster secrets cipher is not configured")
	}
	bag, err := secrets.OpenEnvelope(s.cipher, sealed, nodeID)
	if err != nil {
		return redacted, fmt.Errorf("decrypt cluster secrets: %w", err)
	}
	return mergeClusterSecrets(redacted, bag), nil
}

func mergeClusterSecrets(redacted models.CreateSandboxRequest, bag secrets.Secrets) models.CreateSandboxRequest {
	out := redacted
	if bag.Registry != nil {
		if out.Registry != nil {
			ra := *out.Registry
			if bag.Registry.Password != "" {
				ra.Password = bag.Registry.Password
			}
			// Sealed payload usually mirrors Server/Username for completeness;
			// fall back to it if redacted dropped them (older replication).
			if ra.Server == "" {
				ra.Server = bag.Registry.Server
			}
			if ra.Username == "" {
				ra.Username = bag.Registry.Username
			}
			out.Registry = &ra
		} else {
			regCopy := *bag.Registry
			out.Registry = &regCopy
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

// Thin wrappers around pkg/secrets helpers. Kept so coverage tests that call
// the old package-local names continue to exercise the crypto path without
// touching s.cipher for Put/Open (those go through provider()).

func (s *Service) sealClusterSecretEnvelope(plain []byte, recipients []string) ([]byte, error) {
	if s == nil || s.cipher == nil {
		return nil, errors.New("cluster secrets cipher is not configured")
	}
	return secrets.SealRawEnvelope(s.cipher, plain, recipients)
}

func (s *Service) openClusterSecretPayload(sealed []byte, nodeID string) ([]byte, error) {
	if s == nil || s.cipher == nil {
		return nil, errors.New("cluster secrets cipher is not configured")
	}
	return secrets.OpenRawEnvelope(s.cipher, sealed, nodeID)
}

func openClusterSecretEnvelopePayload(dek []byte, sealed []byte, recipients []string) ([]byte, error) {
	return secrets.OpenEnvelopePayload(dek, sealed, recipients)
}

// Type aliases so coverage tests that still construct/unmarshal the old
// package-local shapes keep compiling after the move into pkg/secrets.
type clusterSealedSecrets = secrets.Secrets

// clusterSealedSecretsEnvelope mirrors the on-wire JSON envelope for tests
// that craft v2/v3 payloads by hand.
type clusterSealedSecretsEnvelope struct {
	Version    int      `json:"version"`
	Recipients []string `json:"recipients,omitempty"`
	WrappedKey []byte   `json:"wrapped_key,omitempty"`
	Payload    []byte   `json:"payload"`
}

func normalizeClusterSecretRecipients(in []string) []string {
	return secrets.NormalizeRecipients(in)
}

func clusterSecretRecipientAllowed(recipients []string, nodeID string) bool {
	return secrets.RecipientAllowed(recipients, nodeID)
}

func clusterSecretAAD(recipients []string) []byte {
	return secrets.V2AAD(recipients)
}

func clusterSecretKeyAAD(recipients []string) []byte {
	return secrets.KeyAAD(recipients)
}

func clusterSecretPayloadAAD(recipients []string) []byte {
	return secrets.PayloadAAD(recipients)
}

func clusterSecretRef(sandboxID string, version int) string {
	return secrets.FormatRef(sandboxID, version)
}
