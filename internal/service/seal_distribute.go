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

// SealPolicy governs LOCAL seal behaviour only. Async peer fan-out never
// fails a create (plans/secrets-hardening §3e / D6). A short sync MinACK wait
// may run before return to shrink GAP-1; it still never fails the create.
type SealPolicy int

const (
	// SealStrict: local seal must succeed or return error (API create paths).
	SealStrict SealPolicy = iota
	// SealBestEffort: local seal failure → metric + continue without ref
	// (boot ownership replay backfill).
	SealBestEffort
)

const defaultSecretFanoutMinACKWait = 2 * time.Second

// secretFanoutHolders tracks successful holder count per sandbox (local put
// counts as 1; each peer ACK increments). In-memory — rebuilt at boot by
// ReFanoutClusterSecrets (local=1, then peer ACKs bump).
var secretFanoutHolders sync.Map // sandboxID -> int

// SealAndDistribute seals to recipients, stores locally, and fans out when
// the feature flag is on, the sandbox is recreate-HA, and len(recipients) > 1.
// Policy governs LOCAL seal only.
//
// Boot-path note: default creates are unchanged (seal-to-self, no fan-out).
// HA creates: local seal + optional bounded sync wait for ≥1 peer ACK
// (SB_SECRET_FANOUT_MIN_ACK_WAIT, default 2s) to shrink GAP-1; remaining
// peers / retries continue asynchronously and never fail the create.
func (s *Service) SealAndDistribute(ctx context.Context, sandboxID string, req models.CreateSandboxRequest, recipients []string, policy SealPolicy) (cluster.PlacementSecrets, error) {
	if len(recipients) == 0 {
		if c := s.Cluster(); c != nil {
			recipients = []string{c.SelfNodeID()}
		}
	}
	out, err := s.putClusterSecretsForRecipients(ctx, sandboxID, req, recipients)
	if err != nil {
		if policy == SealBestEffort {
			recordClusterSecretSealBestEffortFailure()
			if s.logger != nil {
				s.logger.Warn("cluster: seal best-effort failed; placement will ship without secret ref",
					"sandbox_id", sandboxID, "err", err)
			}
			return cluster.PlacementSecrets{}, nil
		}
		return cluster.PlacementSecrets{}, err
	}
	if out.Ref == "" {
		return out, nil
	}
	secretFanoutHolders.Store(sandboxID, 1)
	s.fanoutSecretAfterSeal(ctx, sandboxID, req, recipients, out)
	return out, nil
}

func (s *Service) putClusterSecretsForRecipients(ctx context.Context, sandboxID string, req models.CreateSandboxRequest, recipients []string) (cluster.PlacementSecrets, error) {
	bag := s.secretsFromRequest(req)
	if bag.IsEmpty() {
		return cluster.PlacementSecrets{}, nil
	}
	p := s.provider()
	if p == nil {
		if s == nil || s.cipher == nil {
			return cluster.PlacementSecrets{}, errors.New("cluster secrets cipher is not configured")
		}
		return cluster.PlacementSecrets{}, errors.New("cluster secret store is not configured")
	}
	if s.store != nil {
		_ = s.store.ClearClusterSecretTomb(ctx, sandboxID)
	}
	h, err := p.Put(ctx, sandboxID, bag, recipients)
	if err != nil {
		return cluster.PlacementSecrets{}, err
	}
	return cluster.PlacementSecrets{Ref: h.Ref, Version: h.Version, Recipients: append([]string(nil), recipients...)}, nil
}

// fanoutSecretAfterSeal runs a bounded sync MinACK wait (when configured),
// then always kicks an async full fan-out for remaining peers / retries.
func (s *Service) fanoutSecretAfterSeal(parent context.Context, sandboxID string, req models.CreateSandboxRequest, recipients []string, handle cluster.PlacementSecrets) {
	if s == nil || !s.cfg.SecretRecipientFanoutEnabled {
		return
	}
	if req.Failover == nil || !req.Failover.ShouldRecreate() {
		return
	}
	if len(recipients) <= 1 || handle.Ref == "" {
		return
	}
	pusher := s.secretPeerPusher()
	if pusher == nil {
		return
	}
	blob, err := s.loadSecretBlob(context.Background(), handle.Ref)
	if err != nil || blob == nil {
		if s.logger != nil {
			s.logger.Warn("cluster: secret fan-out skipped; local blob missing after put",
				"sandbox_id", sandboxID, "ref", handle.Ref, "err", err)
		}
		return
	}

	wait := s.secretFanoutMinACKWait()
	if wait > 0 {
		waitCtx, cancel := context.WithTimeout(parent, wait)
		acked, waitErr := pusher.PushSecretBlobToPeers(waitCtx, *blob, recipients)
		cancel()
		if acked > 0 {
			bumpSecretFanoutHolders(sandboxID, acked)
		}
		if waitErr != nil && s.logger != nil && acked == 0 {
			s.logger.Warn("cluster: secret fan-out min-ACK wait got no peer; continuing async",
				"sandbox_id", sandboxID, "wait", wait, "err", waitErr)
		}
	}
	go s.runSecretFanout(sandboxID, *blob, recipients, pusher)
}

func (s *Service) secretFanoutMinACKWait() time.Duration {
	if s == nil {
		return defaultSecretFanoutMinACKWait
	}
	return s.cfg.SecretFanoutMinACKWait
}

func (s *Service) runSecretFanout(sandboxID string, blob secrets.SecretBlob, recipients []string, pusher cluster.SecretPeerPusher) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	acked, err := pusher.PushSecretBlobToPeers(ctx, blob, recipients)
	if acked > 0 {
		// Idempotent re-push may ACK peers already counted in the min-ACK
		// wait. Cap at 1 (local) + number of non-self recipients.
		setSecretFanoutHoldersAtLeast(sandboxID, 1+acked)
	}
	if err != nil {
		recordSecretFanoutFailure()
		if s.logger != nil {
			s.logger.Warn("cluster: secret fan-out incomplete",
				"sandbox_id", sandboxID, "acked", acked, "err", err)
		}
	}
}

// ReFanoutClusterSecrets rebuilds in-memory holder counts from local
// cluster_secrets rows and asynchronously re-pushes multi-recipient blobs to
// peers. Call once after cluster attach / ownership replay on worker boot so
// failover_ready is not stuck false forever after a restart.
func (s *Service) ReFanoutClusterSecrets(ctx context.Context) error {
	if s == nil || s.store == nil || !s.cfg.SecretRecipientFanoutEnabled {
		return nil
	}
	rows, err := s.store.ListClusterSecrets(ctx)
	if err != nil {
		return err
	}
	pusher := s.secretPeerPusher()
	for _, rec := range rows {
		if len(rec.Recipients) == 0 {
			continue
		}
		// Local row ⇒ this node holds the blob.
		secretFanoutHolders.Store(rec.SandboxID, 1)
		if len(rec.Recipients) <= 1 || pusher == nil {
			continue
		}
		blob := secrets.SecretBlob{
			Ref:           rec.Ref,
			SandboxID:     rec.SandboxID,
			Version:       rec.Version,
			Recipients:    append([]string(nil), rec.Recipients...),
			SealedPayload: append([]byte(nil), rec.SealedPayload...),
		}
		go s.runSecretFanout(rec.SandboxID, blob, rec.Recipients, pusher)
	}
	return nil
}

func (s *Service) secretPeerPusher() cluster.SecretPeerPusher {
	if s == nil {
		return nil
	}
	if s.testSecretPeerPusher != nil {
		return s.testSecretPeerPusher
	}
	c := s.Cluster()
	if c == nil {
		return nil
	}
	if p, ok := c.(cluster.SecretPeerPusher); ok {
		return p
	}
	return nil
}

func (s *Service) loadSecretBlob(ctx context.Context, ref string) (*secrets.SecretBlob, error) {
	if s == nil || s.store == nil || ref == "" {
		return nil, nil
	}
	adapter := newSecretBlobStore(s.store)
	if adapter == nil {
		return nil, nil
	}
	return adapter.Get(ctx, ref)
}

// UpsertClusterSecretBlob stores a peer-pushed sealed blob without re-sealing.
// Idempotent (store UPSERT). Used by POST /v1/cluster/internal/secrets.
//
// Rejects blobs whose ref does not match sandbox_id/version, whose declared
// recipients omit this node, or whose sealed envelope recipients disagree /
// omit this node — so a compromised tenant token (if it ever reached the
// handler) cannot poison arbitrary peer rows.
func (s *Service) UpsertClusterSecretBlob(ctx context.Context, blob secrets.SecretBlob) error {
	if s == nil || s.store == nil {
		return errors.New("cluster secret store is not configured")
	}
	if err := validatePeerSecretBlob(ctx, s, blob); err != nil {
		return err
	}
	return newSecretBlobStore(s.store).Put(ctx, blob)
}

// ErrInvalidClusterSecretBlob is a client-fixable peer-push body (ref /
// version / recipients shape). Mapped to HTTP 400 by the internal handler.
var ErrInvalidClusterSecretBlob = errors.New("invalid cluster secret blob")

func validatePeerSecretBlob(ctx context.Context, s *Service, blob secrets.SecretBlob) error {
	sandboxID := strings.TrimSpace(blob.SandboxID)
	ref := strings.TrimSpace(blob.Ref)
	if sandboxID == "" || ref == "" || len(blob.SealedPayload) == 0 {
		return fmt.Errorf("%w: ref, sandbox_id, and sealed_payload are required", ErrInvalidClusterSecretBlob)
	}
	if blob.Version < 1 {
		return fmt.Errorf("%w: version must be >= 1", ErrInvalidClusterSecretBlob)
	}
	wantRef := secrets.FormatRef(sandboxID, blob.Version)
	if ref != wantRef {
		return fmt.Errorf("%w: ref %q does not match sandbox_id/version (want %q)", ErrInvalidClusterSecretBlob, ref, wantRef)
	}

	wireRecipients := secrets.NormalizeRecipients(blob.Recipients)
	envelopeRecipients, err := secrets.EnvelopeRecipients(blob.SealedPayload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidClusterSecretBlob, err)
	}
	if !sameStringSlice(wireRecipients, envelopeRecipients) {
		return fmt.Errorf("%w: wire recipients do not match sealed envelope", ErrInvalidClusterSecretBlob)
	}

	selfID := ""
	if c := s.Cluster(); c != nil {
		selfID = strings.TrimSpace(c.SelfNodeID())
	}
	if selfID == "" {
		return fmt.Errorf("%w: receiving node identity is unknown", ErrInvalidClusterSecretBlob)
	}
	if !secrets.RecipientAllowed(envelopeRecipients, selfID) {
		return fmt.Errorf("%w: receiving node %q is not an intended recipient", secrets.ErrRecipientDenied, selfID)
	}
	if s.store != nil {
		tomb, err := s.store.HasClusterSecretTomb(ctx, sandboxID)
		if err != nil {
			return err
		}
		if tomb {
			return fmt.Errorf("%w: sandbox %q secret was deleted (tombstone)", ErrInvalidClusterSecretBlob, sandboxID)
		}
	}
	return nil
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SecretRecipientsForSeal returns the recorded Placement.SecretRecipients when
// present, otherwise [self]. Used by create-on-target seal sites.
func (s *Service) SecretRecipientsForSeal(sandboxID string) []string {
	c := s.Cluster()
	if c == nil {
		return nil
	}
	if p, ok := c.PlacementOf(sandboxID); ok && len(p.SecretRecipients) > 0 {
		return append([]string(nil), p.SecretRecipients...)
	}
	return []string{c.SelfNodeID()}
}

// WantsSecretRecipientFanout reports whether reserve/seal should use a
// multi-recipient set for this create request.
func (s *Service) WantsSecretRecipientFanout(req models.CreateSandboxRequest) bool {
	if s == nil || !s.cfg.SecretRecipientFanoutEnabled {
		return false
	}
	return req.Failover != nil && req.Failover.ShouldRecreate()
}

// SecretRecipientBackupCount returns the configured backup count (default 2).
func (s *Service) SecretRecipientBackupCount() int {
	if s == nil {
		return 2
	}
	n := s.cfg.SecretRecipientBackupCount
	if n < 0 {
		return 0
	}
	return n
}

// SecretEnvSealEnabled reports whether sealed sandbox_env + Raft Env redaction
// are active (SB_SECRET_ENV_SEAL_ENABLED).
func (s *Service) SecretEnvSealEnabled() bool {
	return s != nil && s.cfg.SecretEnvSealEnabled
}

// RedactClusterSecretsConfigured applies RedactClusterSecretsOpts using this
// service's SecretEnvSealEnabled flag.
func (s *Service) RedactClusterSecretsConfigured(req models.CreateSandboxRequest) models.CreateSandboxRequest {
	return s.redactClusterSecrets(req)
}

func bumpSecretFanoutHolders(sandboxID string, delta int) {
	if delta <= 0 || sandboxID == "" {
		return
	}
	for {
		curAny, _ := secretFanoutHolders.LoadOrStore(sandboxID, 1)
		cur, _ := curAny.(int)
		if secretFanoutHolders.CompareAndSwap(sandboxID, cur, cur+delta) {
			return
		}
	}
}

func setSecretFanoutHoldersAtLeast(sandboxID string, n int) {
	if sandboxID == "" || n <= 0 {
		return
	}
	for {
		curAny, loaded := secretFanoutHolders.LoadOrStore(sandboxID, n)
		if !loaded {
			return
		}
		cur, _ := curAny.(int)
		if cur >= n {
			return
		}
		if secretFanoutHolders.CompareAndSwap(sandboxID, cur, n) {
			return
		}
	}
}

func secretHolderCount(sandboxID string) int {
	if v, ok := secretFanoutHolders.Load(sandboxID); ok {
		if n, ok := v.(int); ok {
			return n
		}
	}
	return 0
}

func clearSecretFanoutHolders(sandboxID string) {
	secretFanoutHolders.Delete(sandboxID)
}

// computeFailoverReady implements E1a: omit for non-recreate; otherwise true
// when holders >= 2 or the recipient set is single-node (len <= 1).
func (s *Service) computeFailoverReady(ctx context.Context, sb *models.Sandbox) *bool {
	if sb == nil || sb.Failover == nil || !sb.Failover.ShouldRecreate() {
		return nil
	}
	recipients := s.secretRecipientsForSandbox(ctx, sb.ID)
	holders := secretHolderCount(sb.ID)
	if holders == 0 && len(recipients) > 0 {
		// Restart amnesia: local sealed row implies this node holds the blob.
		holders = 1
		secretFanoutHolders.Store(sb.ID, 1)
	}
	ready := false
	switch {
	case len(recipients) <= 1:
		// Single-node / seal-to-self: HA N/A but report ready so operators
		// aren't stuck on false for non-HA recipient sets.
		ready = true
	case holders >= 2:
		ready = true
	default:
		ready = false
	}
	return &ready
}

func (s *Service) secretRecipientsForSandbox(ctx context.Context, sandboxID string) []string {
	if c := s.Cluster(); c != nil {
		if p, ok := c.PlacementOf(sandboxID); ok && len(p.SecretRecipients) > 0 {
			return p.SecretRecipients
		}
	}
	if s.store == nil {
		return nil
	}
	ref := secrets.FormatRef(sandboxID, secrets.RefVersion)
	blob, err := newSecretBlobStore(s.store).Get(ctx, ref)
	if err != nil || blob == nil {
		// Env-sealed bags may use RefVersionEnv=2.
		blob, err = newSecretBlobStore(s.store).Get(ctx, secrets.FormatRef(sandboxID, secrets.RefVersionEnv))
		if err != nil || blob == nil {
			return nil
		}
	}
	return blob.Recipients
}

func (s *Service) attachFailoverReady(ctx context.Context, sb *models.Sandbox) {
	if sb == nil {
		return
	}
	sb.FailoverReady = s.computeFailoverReady(ctx, sb)
}

func (s *Service) attachFailoverReadyAll(ctx context.Context, sandboxes []*models.Sandbox) {
	for _, sb := range sandboxes {
		s.attachFailoverReady(ctx, sb)
	}
}
