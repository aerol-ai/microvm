package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
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

// secretHolderACKTTL bounds how long an in-memory peer ACK counts toward
// failover_ready without a fresh push ACK or background possession probe.
// Alive=true alone is not enough: a peer can lose SQLite without flapping.
const secretHolderACKTTL = 90 * time.Second

// secretFanoutHolders tracks which node IDs have ACK'd holding a sealed blob
// (local put seeds self). Live failover_ready intersects this set with current
// membership — historical ACK counts alone are not enough after a backup dies.
var (
	secretFanoutHolders  sync.Map // sandboxID -> *holderNodeSet
	secretSandboxOpMu    sync.Map // sandboxID -> *sandboxOpLock
	secretSandboxOpEvict sync.Mutex
)

type sandboxOpLock struct {
	mu   sync.Mutex
	refs atomic.Int32
}

type holderNodeSet struct {
	mu        sync.Mutex
	gen       int64
	nodes     map[string]time.Time // nodeID -> last ACK / possession confirm
	targets   map[string]struct{}  // intended recipients, retained across probe failures
	lastProbe time.Time            // fair scheduling independent of holder ACK time
}

func lockSecretSandboxOps(sandboxID string) func() {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return func() {}
	}
	secretSandboxOpEvict.Lock()
	v, _ := secretSandboxOpMu.LoadOrStore(sandboxID, &sandboxOpLock{})
	l := v.(*sandboxOpLock)
	l.refs.Add(1)
	secretSandboxOpEvict.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		secretSandboxOpEvict.Lock()
		if l.refs.Add(-1) == 0 {
			secretSandboxOpMu.Delete(sandboxID)
		}
		secretSandboxOpEvict.Unlock()
	}
}

func holderSetFor(sandboxID string) *holderNodeSet {
	v, _ := secretFanoutHolders.LoadOrStore(sandboxID, &holderNodeSet{
		nodes:   make(map[string]time.Time),
		targets: make(map[string]struct{}),
	})
	return v.(*holderNodeSet)
}

// addSecretHolderNodes records generation-scoped ACKs. Stale-generation ACKs
// are ignored so delayed gen1 fan-out cannot keep failover_ready true for gen2.
func addSecretHolderNodes(sandboxID string, gen int64, nodeIDs ...string) {
	if strings.TrimSpace(sandboxID) == "" {
		return
	}
	hs := holderSetFor(sandboxID)
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if gen > 0 && hs.gen != 0 && gen != hs.gen {
		return
	}
	if gen > 0 && hs.gen == 0 {
		hs.gen = gen
	}
	if hs.nodes == nil {
		hs.nodes = make(map[string]time.Time)
	}
	if hs.targets == nil {
		hs.targets = make(map[string]struct{})
	}
	now := time.Now()
	for _, id := range nodeIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		hs.nodes[id] = now
		hs.targets[id] = struct{}{}
	}
}

// resetSecretHoldersForGeneration clears historical ACKs when the seal
// generation advances so stale peers cannot stay "ready" after reseal.
func resetSecretHoldersForGeneration(sandboxID string, gen int64, seed ...string) {
	if strings.TrimSpace(sandboxID) == "" {
		return
	}
	hs := holderSetFor(sandboxID)
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.gen != gen {
		hs.nodes = make(map[string]time.Time)
		hs.targets = make(map[string]struct{})
		hs.lastProbe = time.Time{}
		hs.gen = gen
	}
	if hs.nodes == nil {
		hs.nodes = make(map[string]time.Time)
	}
	if hs.targets == nil {
		hs.targets = make(map[string]struct{})
	}
	now := time.Now()
	for _, id := range seed {
		id = strings.TrimSpace(id)
		if id != "" {
			hs.nodes[id] = now
			hs.targets[id] = struct{}{}
		}
	}
}

// setSecretHolderTargets records the intended recipient set separately from
// confirmed holders. Probe failures may age holder ACKs out, but must not erase
// the nodes that need to be retried.
func setSecretHolderTargets(sandboxID string, gen int64, nodeIDs []string) {
	if strings.TrimSpace(sandboxID) == "" {
		return
	}
	hs := holderSetFor(sandboxID)
	hs.mu.Lock()
	defer hs.mu.Unlock()
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

func secretHolderGeneration(sandboxID string) int64 {
	v, ok := secretFanoutHolders.Load(sandboxID)
	if !ok {
		return 0
	}
	hs := v.(*holderNodeSet)
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return hs.gen
}

func secretHolderNodeIDs(sandboxID string) []string {
	v, ok := secretFanoutHolders.Load(sandboxID)
	if !ok {
		return nil
	}
	hs := v.(*holderNodeSet)
	hs.mu.Lock()
	defer hs.mu.Unlock()
	now := time.Now()
	out := make([]string, 0, len(hs.nodes))
	for id, at := range hs.nodes {
		if !at.IsZero() && now.Sub(at) > secretHolderACKTTL {
			delete(hs.nodes, id)
			continue
		}
		out = append(out, id)
	}
	return out
}

func secretHolderCount(sandboxID string) int {
	return len(secretHolderNodeIDs(sandboxID))
}

func clearSecretFanoutHolders(sandboxID string) {
	secretFanoutHolders.Delete(sandboxID)
}

// pruneDeadSecretHolders drops holders that are not currently alive so a peer
// that rejoins after losing its DB is not counted until it ACKs again.
func pruneDeadSecretHolders(sandboxID string, alive map[string]struct{}) {
	v, ok := secretFanoutHolders.Load(sandboxID)
	if !ok {
		return
	}
	hs := v.(*holderNodeSet)
	hs.mu.Lock()
	defer hs.mu.Unlock()
	now := time.Now()
	for id, at := range hs.nodes {
		if _, ok := alive[id]; !ok {
			delete(hs.nodes, id)
			continue
		}
		if !at.IsZero() && now.Sub(at) > secretHolderACKTTL {
			delete(hs.nodes, id)
		}
	}
}

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
	unlock := lockSecretSandboxOps(sandboxID)
	defer unlock()
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
	selfID := ""
	if c := s.Cluster(); c != nil {
		selfID = c.SelfNodeID()
	}
	gen := int64(1)
	if blob, err := s.loadSecretBlob(ctx, out.Ref); err == nil && blob != nil && blob.SealGeneration > 0 {
		gen = blob.SealGeneration
	}
	resetSecretHoldersForGeneration(sandboxID, gen, selfID)
	setSecretHolderTargets(sandboxID, gen, recipients)
	s.fanoutSecretAfterSeal(ctx, sandboxID, req, recipients, out)
	return out, nil
}

func (s *Service) putClusterSecretsForRecipients(ctx context.Context, sandboxID string, req models.CreateSandboxRequest, recipients []string) (cluster.PlacementSecrets, error) {
	bag := s.secretsFromRequest(req)
	if bag.IsEmpty() {
		return cluster.PlacementSecrets{}, nil
	}
	if err := s.assertEnvSealWriterGate(bag, recipients); err != nil {
		return cluster.PlacementSecrets{}, err
	}
	p := s.provider()
	if p == nil {
		if s == nil || s.cipher == nil {
			return cluster.PlacementSecrets{}, errors.New("cluster secrets cipher is not configured")
		}
		return cluster.PlacementSecrets{}, errors.New("cluster secret store is not configured")
	}
	// PutClusterSecret atomically clears tomb+outbox with the row write.
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
		if len(acked) > 0 {
			addSecretHolderNodes(sandboxID, blob.SealGeneration, acked...)
		}
		if waitErr != nil && s.logger != nil && len(acked) == 0 {
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
	if len(acked) > 0 {
		addSecretHolderNodes(sandboxID, blob.SealGeneration, acked...)
	}
	if err != nil {
		recordSecretFanoutFailure()
		if s.logger != nil {
			s.logger.Warn("cluster: secret fan-out incomplete",
				"sandbox_id", sandboxID, "acked", len(acked), "err", err)
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
		selfID := ""
		if c := s.Cluster(); c != nil {
			selfID = c.SelfNodeID()
		}
		gen := rec.SealGeneration
		if gen <= 0 {
			gen = 1
		}
		resetSecretHoldersForGeneration(rec.SandboxID, gen, selfID)
		setSecretHolderTargets(rec.SandboxID, gen, rec.Recipients)
		if len(rec.Recipients) <= 1 || pusher == nil {
			continue
		}
		blob := secrets.SecretBlob{
			Ref:            rec.Ref,
			SandboxID:      rec.SandboxID,
			Version:        rec.Version,
			Recipients:     append([]string(nil), rec.Recipients...),
			SealedPayload:  append([]byte(nil), rec.SealedPayload...),
			SealGeneration: gen,
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
	unlock := lockSecretSandboxOps(blob.SandboxID)
	defer unlock()
	if blob.SealGeneration <= 0 {
		if meta, err := secrets.EnvelopeBinding(blob.SealedPayload); err == nil && meta.Generation > 0 {
			blob.SealGeneration = meta.Generation
		}
	}
	if err := validatePeerSecretBlob(ctx, s, blob); err != nil {
		return err
	}
	if err := newSecretBlobStore(s.store).Put(ctx, blob); err != nil {
		if errors.Is(err, store.ErrClusterSecretTombBlocksPut) {
			return fmt.Errorf("%w: %v", ErrInvalidClusterSecretBlob, err)
		}
		return err
	}
	return nil
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
	meta, bindErr := secrets.EnvelopeBinding(blob.SealedPayload)
	if bindErr != nil {
		return fmt.Errorf("%w: %v", ErrInvalidClusterSecretBlob, bindErr)
	}
	// Peer ingress requires authenticated v4 binding. Legacy unbound v3 is
	// still openable locally for rolling upgrades, but must not poison peer rows.
	if meta.Version < secrets.EnvelopeVersion || strings.TrimSpace(meta.SandboxID) == "" {
		return fmt.Errorf("%w: peer secret ingress requires bound v4 envelope", ErrInvalidClusterSecretBlob)
	}
	if meta.SandboxID != sandboxID {
		return fmt.Errorf("%w: envelope sandbox_id does not match wire sandbox_id", ErrInvalidClusterSecretBlob)
	}
	if strings.TrimSpace(meta.Ref) == "" {
		return fmt.Errorf("%w: v4 envelope missing authenticated ref", ErrInvalidClusterSecretBlob)
	}
	if meta.Ref != ref {
		return fmt.Errorf("%w: envelope ref does not match wire ref", ErrInvalidClusterSecretBlob)
	}
	if meta.VersionField <= 0 {
		return fmt.Errorf("%w: v4 envelope missing authenticated ref_version", ErrInvalidClusterSecretBlob)
	}
	if meta.VersionField != blob.Version {
		return fmt.Errorf("%w: envelope ref version does not match wire version", ErrInvalidClusterSecretBlob)
	}
	if meta.Generation <= 0 {
		return fmt.Errorf("%w: v4 envelope missing authenticated generation", ErrInvalidClusterSecretBlob)
	}
	if blob.SealGeneration <= 0 {
		return fmt.Errorf("%w: seal_generation is required for peer secret ingress", ErrInvalidClusterSecretBlob)
	}
	if meta.Generation != blob.SealGeneration {
		return fmt.Errorf("%w: envelope generation does not match wire seal_generation", ErrInvalidClusterSecretBlob)
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
		tombGen, err := s.store.ClusterSecretTombGeneration(ctx, sandboxID)
		if err != nil {
			return err
		}
		if tombGen > 0 {
			if blob.SealGeneration <= tombGen {
				return fmt.Errorf("%w: sandbox %q secret was deleted (tombstone gen=%d)", ErrInvalidClusterSecretBlob, sandboxID, tombGen)
			}
			// Newer seal clears tomb atomically inside PutClusterSecret.
		}
		maxGen, err := s.store.MaxClusterSecretSealGeneration(ctx, sandboxID)
		if err != nil {
			return err
		}
		if maxGen > 0 && blob.SealGeneration < maxGen {
			return fmt.Errorf("%w: stale seal_generation %d < local %d", ErrInvalidClusterSecretBlob, blob.SealGeneration, maxGen)
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

// assertEnvSealWriterGate refuses env-bearing seals when any alive non-ingress
// recipient advertises MaxSecretRefVersion < RefVersionEnv (or 0 = pre-capability
// peer). Prevents silent empty-env recreate on mixed-version fleets (§5c).
func (s *Service) assertEnvSealWriterGate(bag secrets.Secrets, recipients []string) error {
	if s == nil || len(bag.Env) == 0 || !s.cfg.SecretEnvSealEnabled {
		return nil
	}
	need := secrets.RefVersionEnv
	c := s.Cluster()
	if c == nil {
		return nil
	}
	alive := make(map[string]cluster.Member, len(c.Members()))
	for _, m := range c.Members() {
		alive[m.NodeID] = m
	}
	for _, id := range recipients {
		id = strings.TrimSpace(id)
		if id == "" || id == c.SelfNodeID() {
			continue
		}
		m, ok := alive[id]
		if !ok || !m.Alive {
			continue
		}
		if strings.TrimSpace(m.Role) == config.NodeRoleIngress {
			continue
		}
		// 0 means older peer without the field — treat as RefVersion only.
		maxVer := m.MaxSecretRefVersion
		if maxVer == 0 {
			maxVer = secrets.RefVersion
		}
		if maxVer < need {
			return fmt.Errorf("secret env seal writer gate: peer %q max_secret_ref_version=%d < %d (roll fleet before enabling SB_SECRET_ENV_SEAL_ENABLED)",
				id, maxVer, need)
		}
	}
	return nil
}

// computeFailoverReady implements E1a: omit for non-recreate; otherwise true
// when live holders >= 2 or the recipient set is single-node (len <= 1).
//
// Intentionally synchronous-probe-free: Get/List must not pay N×peer RTT.
// Correctness comes from (1) local sealed-row possession for self, (2) pruning
// dead members out of ACK memory so a rejoined empty-DB peer is not counted
// until it ACKs again, (3) generation-scoped holder resets on reseal, and
// (4) ACK TTL so a peer that loses SQLite without an Alive=false flap stops
// counting until a fresh ACK / background possession refresh.
func (s *Service) computeFailoverReady(ctx context.Context, sb *models.Sandbox) *bool {
	if sb == nil || sb.Failover == nil || !sb.Failover.ShouldRecreate() {
		return nil
	}
	recipients := s.secretRecipientsForSandbox(ctx, sb.ID)
	selfID := ""
	alive := map[string]struct{}{}
	if c := s.Cluster(); c != nil {
		selfID = c.SelfNodeID()
		for _, m := range c.Members() {
			if m.Alive && m.NodeID != "" {
				alive[m.NodeID] = struct{}{}
			}
		}
		if selfID != "" {
			alive[selfID] = struct{}{}
		}
	}
	pruneDeadSecretHolders(sb.ID, alive)
	localGen, localHolds := s.localSealedSecretGeneration(ctx, sb.ID)
	if localGen > 0 && secretHolderGeneration(sb.ID) != localGen {
		seed := []string{}
		if localHolds && selfID != "" {
			seed = []string{selfID}
		}
		resetSecretHoldersForGeneration(sb.ID, localGen, seed...)
	}
	if localGen > 0 {
		setSecretHolderTargets(sb.ID, localGen, recipients)
	}
	holders := secretHolderNodeIDs(sb.ID)
	if len(holders) == 0 && len(recipients) > 0 && localHolds && selfID != "" {
		resetSecretHoldersForGeneration(sb.ID, localGen, selfID)
		holders = secretHolderNodeIDs(sb.ID)
	}

	liveHolders := 0
	for _, id := range holders {
		if _, ok := alive[id]; !ok {
			continue
		}
		if id == selfID && !localHolds {
			continue
		}
		liveHolders++
	}
	ready := false
	switch {
	case len(recipients) <= 1:
		ready = true
	case liveHolders >= 2:
		ready = true
	default:
		ready = false
	}
	return &ready
}

func (s *Service) localSealedSecretGeneration(ctx context.Context, sandboxID string) (gen int64, holds bool) {
	if s == nil || s.store == nil || strings.TrimSpace(sandboxID) == "" {
		return 0, false
	}
	gen, err := s.store.MaxClusterSecretSealGeneration(ctx, sandboxID)
	if err != nil || gen <= 0 {
		return 0, false
	}
	return gen, true
}

// HasLocalSealedSecretGeneration reports whether this node holds a sealed row
// with seal_generation >= minGeneration (peer HEAD probe target).
func (s *Service) HasLocalSealedSecretGeneration(ctx context.Context, sandboxID string, minGeneration int64) (bool, error) {
	if s == nil || s.store == nil {
		return false, nil
	}
	if minGeneration <= 0 {
		minGeneration = 1
	}
	gen, err := s.store.MaxClusterSecretSealGeneration(ctx, sandboxID)
	if err != nil {
		return false, err
	}
	return gen >= minGeneration, nil
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
