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
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

const (
	defaultSecretFanoutMinACKWait = 2 * time.Second
	secretRefanoutWorkers         = 64
	secretRefanoutBatch           = 32
	// secretCreateFanoutQueue bounds queued create-path fan-out jobs so a
	// create burst cannot allocate one goroutine (+ 2m timeout) per sandbox.
	secretCreateFanoutQueue = secretRefanoutWorkers * 4
)

// secretHolderACKTTL bounds how long an in-memory peer ACK counts toward
// failover_ready without a fresh push ACK or background possession probe.
// Alive=true alone is not enough: a peer can lose SQLite without flapping.
const secretHolderACKTTL = 90 * time.Second

// secretFanoutHolders tracks which node IDs have ACK'd holding a sealed blob
// (local put seeds self). Live failover_ready intersects this set with current
// membership — historical ACK counts alone are not enough after a backup dies.
var (
	secretFanoutHolders  sync.Map // secretHolderKey -> *holderNodeSet
	secretSandboxOpMu    sync.Map // sandboxID -> *sandboxOpLock
	secretSandboxOpEvict sync.Mutex

	secretCreateFanoutOnce     sync.Once
	secretCreateFanoutJobs     chan secretCreateFanoutJob
	secretCreateFanoutInflight sync.Map // secretHolderKey -> struct{}
)

type secretCreateFanoutJob struct {
	svc        *Service
	sandboxID  string
	blob       secrets.SecretBlob
	recipients []string
	pusher     cluster.SecretPeerPusher
}

type sandboxOpLock struct {
	mu   sync.Mutex
	refs atomic.Int32
}

type holderNodeSet struct {
	mu         sync.Mutex
	gen        int64
	nodes      map[string]time.Time // nodeID -> last ACK / possession confirm
	targets    map[string]struct{}  // intended recipients, retained across probe failures
	lastProbe  time.Time            // fair scheduling independent of holder ACK time
	lastExpand time.Time            // fair scheduling for reseal/finalization attempts
}

type secretHolderKey struct {
	sandboxID     string
	incarnationID string
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

func holderSetFor(sandboxID, incarnationID string) *holderNodeSet {
	key := secretHolderKey{sandboxID: strings.TrimSpace(sandboxID), incarnationID: strings.TrimSpace(incarnationID)}
	v, _ := secretFanoutHolders.LoadOrStore(key, &holderNodeSet{
		nodes:   make(map[string]time.Time),
		targets: make(map[string]struct{}),
	})
	return v.(*holderNodeSet)
}

// addSecretHolderNodes records generation-scoped ACKs. Stale-generation ACKs
// are ignored so delayed gen1 fan-out cannot keep failover_ready true for gen2.
func addSecretHolderNodes(sandboxID, incarnationID string, gen int64, nodeIDs ...string) {
	incarnationID = strings.TrimSpace(incarnationID)
	if strings.TrimSpace(sandboxID) == "" || incarnationID == "" {
		return
	}
	hs := holderSetFor(sandboxID, incarnationID)
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
func resetSecretHoldersForGeneration(sandboxID, incarnationID string, gen int64, seed ...string) {
	resetSecretHolders(sandboxID, incarnationID, gen, false, seed...)
}

// replaceSecretHoldersForGeneration resets from an authoritative durable row
// even when a corrupt/stale cache claims a higher generation.
func replaceSecretHoldersForGeneration(sandboxID, incarnationID string, gen int64, seed ...string) {
	resetSecretHolders(sandboxID, incarnationID, gen, true, seed...)
}

func resetSecretHolders(sandboxID, incarnationID string, gen int64, authoritative bool, seed ...string) {
	incarnationID = strings.TrimSpace(incarnationID)
	if strings.TrimSpace(sandboxID) == "" || incarnationID == "" {
		return
	}
	hs := holderSetFor(sandboxID, incarnationID)
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if !authoritative && gen > 0 && hs.gen > gen {
		return
	}
	if hs.gen != gen {
		hs.nodes = make(map[string]time.Time)
		hs.targets = make(map[string]struct{})
		hs.lastProbe = time.Time{}
		hs.lastExpand = time.Time{}
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
func setSecretHolderTargets(sandboxID, incarnationID string, gen int64, nodeIDs []string) {
	incarnationID = strings.TrimSpace(incarnationID)
	if strings.TrimSpace(sandboxID) == "" || incarnationID == "" {
		return
	}
	hs := holderSetFor(sandboxID, incarnationID)
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if gen > 0 && hs.gen > gen {
		return
	}
	if gen > 0 && hs.gen != 0 && hs.gen != gen {
		hs.nodes = make(map[string]time.Time)
		hs.lastProbe = time.Time{}
		hs.lastExpand = time.Time{}
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

func secretHolderGeneration(sandboxID, incarnationID string) int64 {
	v, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: strings.TrimSpace(sandboxID), incarnationID: strings.TrimSpace(incarnationID)})
	if !ok {
		return 0
	}
	hs := v.(*holderNodeSet)
	hs.mu.Lock()
	defer hs.mu.Unlock()
	return hs.gen
}

func secretHolderNodeIDs(sandboxID, incarnationID string) []string {
	v, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: strings.TrimSpace(sandboxID), incarnationID: strings.TrimSpace(incarnationID)})
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

func secretHolderCount(sandboxID, incarnationID string) int {
	return len(secretHolderNodeIDs(sandboxID, incarnationID))
}

func clearSecretFanoutHolders(sandboxID string) {
	sandboxID = strings.TrimSpace(sandboxID)
	secretFanoutHolders.Range(func(key, _ any) bool {
		if holderKey, ok := key.(secretHolderKey); ok && holderKey.sandboxID == sandboxID {
			secretFanoutHolders.Delete(holderKey)
		}
		return true
	})
}

func clearSecretFanoutHoldersForIncarnation(sandboxID, incarnationID string) {
	secretFanoutHolders.Delete(secretHolderKey{
		sandboxID:     strings.TrimSpace(sandboxID),
		incarnationID: strings.TrimSpace(incarnationID),
	})
}

// pruneDeadSecretHolders drops holders that are not currently alive so a peer
// that rejoins after losing its DB is not counted until it ACKs again.
func pruneDeadSecretHolders(sandboxID, incarnationID string, alive map[string]struct{}) {
	v, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: strings.TrimSpace(sandboxID), incarnationID: strings.TrimSpace(incarnationID)})
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
// the sandbox is recreate-HA and len(recipients) > 1.
// Boot-path note: default creates are unchanged (seal-to-self, no fan-out).
// HA creates: local seal + optional bounded sync wait for ≥1 peer ACK
// (SB_SECRET_FANOUT_MIN_ACK_WAIT, default 2s) to shrink GAP-1; remaining
// peers / retries continue asynchronously. A zero-ACK HA create is retracted.
func (s *Service) SealAndDistribute(ctx context.Context, sandboxID string, req models.CreateSandboxRequest, recipients []string) (cluster.PlacementSecrets, error) {
	return s.sealAndDistributeForIncarnation(ctx, sandboxID, req, recipients, "")
}

// ReservedSecretBinding returns the one leader-confirmed identity used by both
// legs of an overlapped reserved create. Resolving once before either leg
// starts prevents a follower-cache race from giving the sandbox row and its
// sealed credentials different incarnations.
func (s *Service) ReservedSecretBinding(ctx context.Context, sandboxID string) (binding cluster.PlacementSecrets, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			binding = cluster.PlacementSecrets{}
			err = fmt.Errorf("resolve reserved secret binding: %v", recovered)
		}
	}()
	if s == nil {
		return cluster.PlacementSecrets{}, errors.New("cluster service is unavailable")
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return cluster.PlacementSecrets{}, errors.New("reserved sandbox id is required")
	}
	c := s.Cluster()
	if c == nil {
		return cluster.PlacementSecrets{}, errors.New("cluster placement is unavailable")
	}
	placements, err := c.AuthoritativePlacementsByIDs(ctx, []string{sandboxID})
	if err != nil {
		return cluster.PlacementSecrets{}, fmt.Errorf("authoritative reserved placement read before secret seal: %w", err)
	}
	placement, ok := placements[sandboxID]
	if !ok || placement.SandboxID != sandboxID || !placement.IsReserved() {
		return cluster.PlacementSecrets{}, errors.New("reserved placement is no longer authoritative")
	}
	if ownerID := strings.TrimSpace(placement.OwnerNodeID); ownerID == "" || ownerID != s.selfNodeID() {
		return cluster.PlacementSecrets{}, errors.New("reserved placement is not owned by this node")
	}
	incarnationID := strings.TrimSpace(placement.IncarnationID)
	if incarnationID == "" {
		return cluster.PlacementSecrets{}, errors.New("reserved placement incarnation_id is required")
	}
	if placement.ExpiresUnix > 0 && time.Now().Unix() >= placement.ExpiresUnix {
		return cluster.PlacementSecrets{}, errors.New("reserved placement has expired")
	}
	recipients := secrets.NormalizeRecipients(placement.SecretRecipients)
	if len(recipients) == 0 {
		recipients = []string{s.selfNodeID()}
	}
	return cluster.PlacementSecrets{Recipients: recipients, IncarnationID: incarnationID}, nil
}

func (s *Service) sealAndDistributeForIncarnation(ctx context.Context, sandboxID string, req models.CreateSandboxRequest, recipients []string, incarnationID string) (cluster.PlacementSecrets, error) {
	if len(recipients) == 0 {
		if c := s.Cluster(); c != nil {
			recipients = []string{c.SelfNodeID()}
		}
	}
	unlock := lockSecretSandboxOps(sandboxID)
	defer unlock()
	out, err := s.putClusterSecretsForRecipientsAndIncarnation(ctx, sandboxID, req, recipients, incarnationID)
	if err != nil {
		return cluster.PlacementSecrets{}, err
	}
	if out.Ref == "" {
		return out, nil
	}
	selfID := ""
	if c := s.Cluster(); c != nil {
		selfID = c.SelfNodeID()
	}
	gen := out.SealGeneration
	resetSecretHoldersForGeneration(sandboxID, out.IncarnationID, gen, selfID)
	setSecretHolderTargets(sandboxID, out.IncarnationID, gen, recipients)
	if err := s.fanoutSecretAfterSeal(ctx, sandboxID, req, recipients, out); err != nil {
		// Enterprise HA never acknowledges a create whose only durable copy is
		// still on the owner. Retract the local row and durably enqueue deletes
		// in case a peer stored the blob but its ACK was lost.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cleanupErr := s.deleteClusterSecretsOriginator(cleanupCtx, sandboxID, out.IncarnationID, recipients)
		cancel()
		if cleanupErr != nil {
			return cluster.PlacementSecrets{}, errors.Join(err, fmt.Errorf("retract unreplicated secret: %w", cleanupErr))
		}
		return cluster.PlacementSecrets{}, err
	}
	return out, nil
}

func (s *Service) putClusterSecretsForRecipients(ctx context.Context, sandboxID string, req models.CreateSandboxRequest, recipients []string) (cluster.PlacementSecrets, error) {
	return s.putClusterSecretsForRecipientsAndIncarnation(ctx, sandboxID, req, recipients, "")
}

func (s *Service) putClusterSecretsForRecipientsAndIncarnation(ctx context.Context, sandboxID string, req models.CreateSandboxRequest, recipients []string, incarnationID string) (cluster.PlacementSecrets, error) {
	bag := secretsFromRequest(req)
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
	incarnationID = strings.TrimSpace(incarnationID)
	if incarnationID == "" {
		incarnationID = strings.TrimSpace(secrets.IncarnationIDFromContext(ctx))
	}
	if incarnationID == "" {
		incarnationID = s.secretIncarnationForSeal(sandboxID)
	}
	if incarnationID == "" {
		var incarnationErr error
		incarnationID, incarnationErr = s.prepareAuditIncarnation(ctx, sandboxID, "")
		if incarnationErr != nil {
			return cluster.PlacementSecrets{}, incarnationErr
		}
	}
	if incarnationID == "" {
		return cluster.PlacementSecrets{}, errors.New("cluster secret lifecycle incarnation is required")
	}
	if incarnationID != "" {
		ctx = secrets.ContextWithIncarnationID(ctx, incarnationID)
	}
	// Crash-vacuum: journal remaining peer PUTs in the same durability domain
	// as the sealed row (SQLite TX via BlobStore PutOutboxRecipients).
	peers := nonSelfRecipients(recipients, s.selfNodeID())
	if len(peers) > 0 {
		if s.store == nil {
			return cluster.PlacementSecrets{}, errors.New("cluster secret store is not configured for put-outbox")
		}
		ctx = secrets.ContextWithPutOutbox(ctx, incarnationID, peers)
	}
	// PutClusterSecret atomically clears tomb+delete-outbox with the row write
	// and, when ContextWithPutOutbox is set, inserts put-outbox in the same TX.
	h, err := p.Put(ctx, sandboxID, bag, recipients)
	if err != nil {
		return cluster.PlacementSecrets{}, err
	}
	if h.Ref == "" || h.Version != secrets.RefVersion || h.SealGeneration <= 0 {
		return cluster.PlacementSecrets{}, errors.New("secret provider returned an incomplete current-format handle")
	}
	parsed, parseErr := secrets.ParseRef(h.Ref)
	if parseErr != nil || parsed.SandboxID != strings.TrimSpace(sandboxID) || parsed.IncarnationID != incarnationID || parsed.Version != h.Version {
		return cluster.PlacementSecrets{}, errors.New("secret provider returned a handle outside the current sandbox lifecycle")
	}
	return cluster.PlacementSecrets{
		Ref:            h.Ref,
		Version:        h.Version,
		Recipients:     append([]string(nil), recipients...),
		IncarnationID:  incarnationID,
		SealGeneration: h.SealGeneration,
	}, nil
}

// fanoutSecretAfterSeal runs a bounded sync MinACK wait (when configured),
// then always kicks an async full fan-out for remaining peers / retries.
func (s *Service) fanoutSecretAfterSeal(parent context.Context, sandboxID string, req models.CreateSandboxRequest, recipients []string, handle cluster.PlacementSecrets) error {
	if s == nil {
		return nil
	}
	if req.Failover == nil || !req.Failover.ShouldRecreate() {
		return nil
	}
	if len(recipients) <= 1 || handle.Ref == "" {
		return nil
	}
	pusher := s.secretPeerPusher()
	if pusher == nil {
		return errors.New("secret fan-out requires an available peer pusher")
	}
	blob, err := s.loadSecretBlob(context.Background(), handle.Ref)
	if err != nil || blob == nil {
		if s.logger != nil {
			s.logger.Warn("cluster: secret fan-out skipped; local blob missing after put",
				"sandbox_id", sandboxID, "ref", handle.Ref, "err", err)
		}
		return fmt.Errorf("secret fan-out cannot load local sealed blob %q: %v", handle.Ref, err)
	}
	if blob.Ref != handle.Ref || blob.Version != handle.Version || blob.SealGeneration <= 0 || blob.SealGeneration != handle.SealGeneration ||
		strings.TrimSpace(blob.IncarnationID) == "" || blob.IncarnationID != handle.IncarnationID {
		return errors.New("secret fan-out local blob does not match the current placement handle")
	}

	wait := s.secretFanoutMinACKWait()
	var acked []string
	if wait > 0 {
		waitCtx, cancel := context.WithTimeout(parent, wait)
		var waitErr error
		if minACKPusher, ok := pusher.(cluster.SecretPeerMinACKPusher); ok {
			acked, waitErr = minACKPusher.PushSecretBlobToAnyPeer(waitCtx, *blob, recipients)
		} else {
			// Compatibility path for narrow test/custom pushers. Production
			// Cluster and Agent clients implement the first-ACK operation above.
			acked, waitErr = pusher.PushSecretBlobToPeers(waitCtx, *blob, recipients)
		}
		cancel()
		if len(acked) > 0 {
			addSecretHolderNodes(sandboxID, blob.IncarnationID, blob.SealGeneration, acked...)
		}
		if waitErr != nil && s.logger != nil && len(acked) == 0 {
			s.logger.Warn("cluster: secret fan-out min-ACK wait got no peer; retracting HA create",
				"sandbox_id", sandboxID, "wait", wait, "err", waitErr)
		}
	}
	if len(acked) == 0 {
		return errors.New("secret fan-out received no backup ACK")
	}
	// Shrink durable put-outbox to peers still pending after MinACK. Do not
	// delete until every non-self recipient has ACKed (or reconcile drains).
	pending := pendingRecipientsAfterAck(recipients, acked, s.selfNodeID())
	gen := blob.SealGeneration
	incarnationID := blob.IncarnationID
	if s.store != nil {
		if err := s.persistSecretPutOutboxRecipients(context.Background(), sandboxID, incarnationID, pending, gen); err != nil {
			recordSecretPutOutboxFailure()
			if s.logger != nil {
				s.logger.Warn("cluster: put-outbox shrink after MinACK failed",
					"sandbox_id", sandboxID, "err", err)
			}
		}
	}
	s.enqueueSecretFanout(sandboxID, *blob, recipients, pusher)
	return nil
}

func (s *Service) secretFanoutMinACKWait() time.Duration {
	if s == nil || s.cfg.SecretFanoutMinACKWait <= 0 {
		return defaultSecretFanoutMinACKWait
	}
	return s.cfg.SecretFanoutMinACKWait
}

func ensureSecretCreateFanoutWorkers() {
	secretCreateFanoutOnce.Do(func() {
		secretCreateFanoutJobs = make(chan secretCreateFanoutJob, secretCreateFanoutQueue)
		for range secretRefanoutWorkers {
			go func() {
				for job := range secretCreateFanoutJobs {
					job.svc.runSecretFanout(job.sandboxID, job.blob, job.recipients, job.pusher)
					secretCreateFanoutInflight.Delete(secretHolderKey{sandboxID: job.sandboxID, incarnationID: job.blob.IncarnationID})
				}
			}()
		}
	})
}

// enqueueSecretFanout schedules remaining peer pushes on the bounded create-path
// pool (same worker cap as restart re-fanout). Per-sandbox single-flight drops
// duplicate enqueues while a job is queued or running.
func (s *Service) enqueueSecretFanout(sandboxID string, blob secrets.SecretBlob, recipients []string, pusher cluster.SecretPeerPusher) {
	if s == nil || pusher == nil || strings.TrimSpace(sandboxID) == "" {
		return
	}
	if blob.SealGeneration <= 0 || strings.TrimSpace(blob.IncarnationID) == "" {
		recordSecretFanoutFailure()
		if s.logger != nil {
			s.logger.Error("cluster: refused to enqueue secret fan-out without current generation/incarnation", "sandbox_id", sandboxID)
		}
		return
	}
	key := secretHolderKey{sandboxID: strings.TrimSpace(sandboxID), incarnationID: strings.TrimSpace(blob.IncarnationID)}
	if _, loaded := secretCreateFanoutInflight.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	ensureSecretCreateFanoutWorkers()
	job := secretCreateFanoutJob{
		svc:        s,
		sandboxID:  sandboxID,
		blob:       blob,
		recipients: append([]string(nil), recipients...),
		pusher:     pusher,
	}
	select {
	case secretCreateFanoutJobs <- job:
	default:
		// Never block the create path on a saturated queue. Outbox already
		// exists from Put; keep it as the crash-recovery source of truth.
		secretCreateFanoutInflight.Delete(key)
		recordSecretFanoutFailure()
		pending := nonSelfRecipients(recipients, s.selfNodeID())
		if s.store != nil {
			if err := s.store.UpsertSecretPutOutbox(context.Background(), sandboxID, blob.IncarnationID, blob.SealGeneration, pending); err != nil {
				recordSecretPutOutboxFailure()
				if s.logger != nil {
					s.logger.Warn("cluster: secret fan-out queue full; put-outbox persist failed",
						"sandbox_id", sandboxID, "err", err)
				}
			}
		}
		if s.logger != nil {
			s.logger.Warn("cluster: secret fan-out queue full; deferred remaining peers to put outbox",
				"sandbox_id", sandboxID)
		}
	}
}

func (s *Service) runSecretFanout(sandboxID string, blob secrets.SecretBlob, recipients []string, pusher cluster.SecretPeerPusher) {
	if blob.SealGeneration <= 0 || strings.TrimSpace(blob.IncarnationID) == "" {
		recordSecretFanoutFailure()
		if s != nil && s.logger != nil {
			s.logger.Error("cluster: refused secret fan-out without current generation/incarnation", "sandbox_id", sandboxID)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	acked, err := pusher.PushSecretBlobToPeers(ctx, blob, recipients)
	if len(acked) > 0 {
		addSecretHolderNodes(sandboxID, blob.IncarnationID, blob.SealGeneration, acked...)
	}
	pending := pendingRecipientsAfterAck(recipients, acked, s.selfNodeID())
	gen := blob.SealGeneration
	if s.store == nil {
		return
	}
	if len(pending) > 0 {
		// Incomplete fan-out (dead/missing peers, dial failures, or silent
		// empty ACK) must leave a durable retry job — never clear outbox.
		if err == nil {
			err = fmt.Errorf("cluster: secret fan-out incomplete: acked %d pending %d", len(acked), len(pending))
		}
		recordSecretFanoutFailure()
		if s.logger != nil {
			s.logger.Warn("cluster: secret fan-out incomplete",
				"sandbox_id", sandboxID, "acked", len(acked), "pending", len(pending), "err", err)
		}
		if upErr := s.persistSecretPutOutboxRecipients(context.Background(), sandboxID, blob.IncarnationID, pending, gen); upErr != nil {
			recordSecretPutOutboxFailure()
			if s.logger != nil {
				s.logger.Warn("cluster: secret fan-out put-outbox update failed",
					"sandbox_id", sandboxID, "err", upErr)
			}
		}
		return
	}
	if delErr := s.store.DeleteSecretPutOutbox(context.Background(), sandboxID, blob.IncarnationID, gen); delErr != nil {
		recordSecretPutOutboxFailure()
		if s.logger != nil {
			s.logger.Warn("cluster: secret fan-out put-outbox delete failed",
				"sandbox_id", sandboxID, "err", delErr)
		}
	}
}

func pendingRecipientsAfterAck(recipients, acked []string, selfID string) []string {
	ackedSet := make(map[string]struct{}, len(acked)+1)
	for _, id := range acked {
		if id = strings.TrimSpace(id); id != "" {
			ackedSet[id] = struct{}{}
		}
	}
	if selfID != "" {
		ackedSet[selfID] = struct{}{}
	}
	out := make([]string, 0, len(recipients))
	for _, id := range recipients {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := ackedSet[id]; ok {
			continue
		}
		out = append(out, id)
	}
	return out
}

// ReFanoutClusterSecrets rebuilds in-memory holder counts from local
// cluster_secrets rows and asynchronously re-pushes multi-recipient blobs to
// peers. Call once after cluster attach / ownership replay on worker boot so
// failover_ready is not stuck false forever after a restart.
func (s *Service) ReFanoutClusterSecrets(ctx context.Context) error {
	if s == nil || s.store == nil {
		return nil
	}
	pusher := s.secretPeerPusher()
	var validationErr error
	afterRef := ""
	for {
		rows, err := s.store.ListClusterSecretsBatch(ctx, afterRef, secretRefanoutBatch)
		if err != nil {
			return errors.Join(validationErr, err)
		}
		if len(rows) == 0 {
			break
		}
		placements, err := s.secretRefanoutPlacements(ctx, rows)
		if err != nil {
			// Placement absence retires a stale lifecycle, but an unavailable
			// authoritative placement read must never be interpreted as absence:
			// doing so would delete every local secret during a control-plane
			// outage immediately after worker restart.
			return errors.Join(validationErr, err)
		}
		for _, rec := range rows {
			if _, err := s.prepareSecretRefanoutRecord(ctx, rec, true, placements, nil); err != nil {
				validationErr = errors.Join(validationErr, err)
			}
		}
		afterRef = rows[len(rows)-1].Ref
		if len(rows) < secretRefanoutBatch {
			break
		}
	}
	if pusher != nil && (validationErr == nil || !s.cfg.EnterpriseMode) {
		s.startSecretRefanoutScan(ctx, pusher)
	}
	return validationErr
}

// secretRefanoutPlacements returns one authoritative placement snapshot for a
// durable-secret page. Agent.AuthoritativePlacementsByIDs uses one leader RPC,
// keeping restart work O(pages) rather than O(secrets) without creating a
// destructive not-found/error ambiguity.
func (s *Service) secretRefanoutPlacements(ctx context.Context, rows []store.ClusterSecretRecord) (map[string]cluster.Placement, error) {
	ids := make([]string, 0, len(rows))
	for _, rec := range rows {
		if id := strings.TrimSpace(rec.SandboxID); id != "" {
			ids = append(ids, id)
		}
	}
	placements, err := s.authoritativeSecretPlacements(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("authoritative cluster placement snapshot during secret re-fanout: %w", err)
	}
	return placements, nil
}

// authoritativeSecretPlacements is the single fail-closed path used before a
// reconciler turns a placement result into destructive durable state. Cluster
// agents route it to the Raft leader; ordinary read paths remain distributable.
func (s *Service) authoritativeSecretPlacements(ctx context.Context, ids []string) (map[string]cluster.Placement, error) {
	if !s.cfg.EnableCluster || len(ids) == 0 {
		return nil, nil
	}
	c := s.Cluster()
	if c == nil {
		return nil, errors.New("cluster placement snapshot is unavailable")
	}
	unique := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) == 0 {
		return map[string]cluster.Placement{}, nil
	}
	if len(unique) > cluster.MaxPlacementPageLimit {
		return nil, fmt.Errorf("authoritative cluster placement snapshot exceeds %d IDs", cluster.MaxPlacementPageLimit)
	}
	placements, err := c.AuthoritativePlacementsByIDs(ctx, unique)
	if err != nil {
		return nil, err
	}
	if placements == nil {
		return nil, errors.New("authoritative cluster placement snapshot returned no result")
	}
	return placements, nil
}

// standaloneLiveIncarnations is the standalone authority for a page of sealed
// rows: which of their sandboxes still exist here, and under which lifecycle.
func (s *Service) standaloneLiveIncarnations(ctx context.Context, rows []store.ClusterSecretRecord) (map[string]string, error) {
	ids := make([]string, 0, len(rows))
	for _, rec := range rows {
		if id := strings.TrimSpace(rec.SandboxID); id != "" {
			ids = append(ids, id)
		}
	}
	live, err := s.store.SandboxAuditIncarnations(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("local sandbox lifecycles during standalone secret retirement: %w", err)
	}
	return live, nil
}

// retireStaleSecretRow tombs a sealed row whose lifecycle is gone and journals
// the peer deletes it implies. The same transaction serves both modes; only
// the authority that declared the row stale differs.
func (s *Service) retireStaleSecretRow(ctx context.Context, rec store.ClusterSecretRecord, incarnationID string) error {
	peers := nonSelfRecipients(rec.Recipients, s.selfNodeID())
	if _, err := s.store.DeleteClusterSecretsOriginatorWithOutbox(ctx, rec.SandboxID, incarnationID, peers); err != nil {
		return fmt.Errorf("retire stale cluster secret %q: %w", rec.Ref, err)
	}
	clearSecretFanoutHoldersForIncarnation(rec.SandboxID, incarnationID)
	secretCiphertextRetiredTotal.Add(1)
	return nil
}

func (s *Service) prepareSecretRefanoutRecord(ctx context.Context, rec store.ClusterSecretRecord, seedHolders bool, placements map[string]cluster.Placement, live map[string]string) (*secrets.SecretBlob, error) {
	parsed, parseErr := secrets.ParseRef(rec.Ref)
	if parseErr != nil || strings.TrimSpace(parsed.IncarnationID) == "" {
		return nil, fmt.Errorf("cluster secret %q lacks required incarnation binding", rec.Ref)
	}
	if !s.cfg.EnableCluster && live != nil {
		// Standalone: the row is someone's only if a local sandbox row carries
		// exactly this lifecycle. Rows younger than the standalone grace are
		// left alone so a node that rejoins a cluster within it keeps them.
		if inc, ok := live[rec.SandboxID]; !ok || inc != parsed.IncarnationID {
			if rec.UpdatedAt.After(secretLifecycleNow().UTC().Add(-s.cfg.SecretOutboxStandaloneGrace)) {
				return nil, nil
			}
			return nil, s.retireStaleSecretRow(ctx, rec, parsed.IncarnationID)
		}
		return nil, nil
	}
	if s.cfg.EnableCluster {
		binding, bindErr := secrets.EnvelopeBinding(rec.SealedPayload)
		if bindErr != nil || binding.IncarnationID != parsed.IncarnationID || binding.Ref != rec.Ref || binding.SandboxID != rec.SandboxID || binding.VersionField != rec.Version || binding.Generation != rec.SealGeneration {
			return nil, fmt.Errorf("cluster secret %q envelope binding does not match its durable row", rec.Ref)
		}
		durableRecipients := secrets.NormalizeRecipients(rec.Recipients)
		envelopeRecipients, recipientsErr := secrets.EnvelopeRecipients(rec.SealedPayload)
		if recipientsErr != nil || len(durableRecipients) == 0 || !sameStringSlice(durableRecipients, envelopeRecipients) {
			return nil, fmt.Errorf("cluster secret %q envelope recipients do not match its durable row", rec.Ref)
		}
		placement, placementOK := placements[rec.SandboxID]
		if !placementOK || placement.IsDeleting() || strings.TrimSpace(placement.IncarnationID) != parsed.IncarnationID {
			return nil, s.retireStaleSecretRow(ctx, rec, parsed.IncarnationID)
		}
		// Only the owner originates a retransmit. Every replica used to
		// re-push on boot/rejoin, so a membership flap stampeded the fleet
		// (and, via PUT validation, the leader) with one copy per holder.
		if ownerID := strings.TrimSpace(placement.OwnerNodeID); ownerID == "" || ownerID != s.selfNodeID() {
			return nil, nil
		}
	}
	if len(rec.Recipients) == 0 {
		return nil, nil
	}
	if rec.SealGeneration <= 0 {
		return nil, fmt.Errorf("cluster secret %q lacks required seal generation", rec.Ref)
	}
	if seedHolders {
		selfID := ""
		if c := s.Cluster(); c != nil {
			selfID = c.SelfNodeID()
		}
		replaceSecretHoldersForGeneration(rec.SandboxID, parsed.IncarnationID, rec.SealGeneration, selfID)
		setSecretHolderTargets(rec.SandboxID, parsed.IncarnationID, rec.SealGeneration, rec.Recipients)
	}
	if len(rec.Recipients) <= 1 {
		return nil, nil
	}
	return &secrets.SecretBlob{
		Ref: rec.Ref, SandboxID: rec.SandboxID, IncarnationID: parsed.IncarnationID,
		Version: rec.Version, Recipients: append([]string(nil), rec.Recipients...),
		SealedPayload: append([]byte(nil), rec.SealedPayload...), SealGeneration: rec.SealGeneration,
	}, nil
}

func (s *Service) startSecretRefanoutScan(ctx context.Context, pusher cluster.SecretPeerPusher) {
	s.startSecretMaintenanceScan(ctx, "cluster: paged secret re-fanout failed", func(scanCtx context.Context) error {
		return s.runSecretRefanoutScan(scanCtx, pusher)
	})
}

func (s *Service) startSecretRetirementScan(ctx context.Context) {
	if s == nil || s.store == nil {
		return
	}
	s.startSecretMaintenanceScan(ctx, "cluster: paged stale-secret retirement failed", s.runSecretRetirementScan)
}

// startSecretMaintenanceScan gives boot/rejoin fan-out and periodic stale-row
// retirement one shared single-flight gate. Both walk the same durable rows;
// overlapping them wastes placement RPCs and can race holder-cache rebuilds.
func (s *Service) startSecretMaintenanceScan(ctx context.Context, failureMessage string, scan func(context.Context) error) {
	if s == nil || scan == nil {
		return
	}
	s.secretRefanoutMu.Lock()
	if s.secretRefanoutRunning {
		s.secretRefanoutMu.Unlock()
		return
	}
	s.secretRefanoutRunning = true
	s.secretRefanoutMu.Unlock()
	go func() {
		defer func() {
			s.secretRefanoutMu.Lock()
			s.secretRefanoutRunning = false
			s.secretRefanoutMu.Unlock()
		}()
		if err := scan(ctx); err != nil && s.logger != nil {
			s.logger.Warn(failureMessage, "err", err)
		}
	}()
}

// runSecretRetirementScan validates exact lifecycle bindings and tombs rows
// whose authoritative lifecycle is absent/deleting/reused. It deliberately
// discards active blobs: periodic GC must not resend the entire active fleet.
//
// The authority is the Raft placement in cluster mode and the local sandboxes
// table standalone (a node without cluster mode has nothing else to ask, and
// a sealed row whose sandbox is not here belongs to no one it can serve).
func (s *Service) runSecretRetirementScan(ctx context.Context) error {
	afterRef := ""
	var validationErr error
	for {
		rows, err := s.store.ListClusterSecretsBatch(ctx, afterRef, secretRefanoutBatch)
		if err != nil {
			return errors.Join(validationErr, err)
		}
		if len(rows) == 0 {
			return validationErr
		}
		placements, err := s.secretRefanoutPlacements(ctx, rows)
		if err != nil {
			return errors.Join(validationErr, err)
		}
		var live map[string]string
		if !s.cfg.EnableCluster {
			live, err = s.standaloneLiveIncarnations(ctx, rows)
			if err != nil {
				return errors.Join(validationErr, err)
			}
		}
		for _, rec := range rows {
			if _, err := s.prepareSecretRefanoutRecord(ctx, rec, false, placements, live); err != nil {
				validationErr = errors.Join(validationErr, err)
			}
		}
		afterRef = rows[len(rows)-1].Ref
		if len(rows) < secretRefanoutBatch {
			return validationErr
		}
	}
}

// runSecretRefanoutScan streams indexed pages through one fixed worker set.
// Neither payload memory nor goroutine count grows with the sandbox fleet.
func (s *Service) runSecretRefanoutScan(ctx context.Context, pusher cluster.SecretPeerPusher) error {
	jobs := make(chan secrets.SecretBlob)
	var wg sync.WaitGroup
	wg.Add(secretRefanoutWorkers)
	for range secretRefanoutWorkers {
		go func() {
			defer wg.Done()
			for blob := range jobs {
				s.runSecretFanout(blob.SandboxID, blob, blob.Recipients, pusher)
			}
		}()
	}
	defer func() {
		close(jobs)
		wg.Wait()
	}()
	afterRef := ""
	var validationErr error
	for {
		rows, err := s.store.ListClusterSecretsBatch(ctx, afterRef, secretRefanoutBatch)
		if err != nil {
			return errors.Join(validationErr, err)
		}
		if len(rows) == 0 {
			return validationErr
		}
		placements, err := s.secretRefanoutPlacements(ctx, rows)
		if err != nil {
			return errors.Join(validationErr, err)
		}
		for _, rec := range rows {
			blob, err := s.prepareSecretRefanoutRecord(ctx, rec, false, placements, nil)
			if err != nil {
				validationErr = errors.Join(validationErr, err)
				continue
			}
			if blob == nil {
				continue
			}
			select {
			case jobs <- *blob:
			case <-ctx.Done():
				return errors.Join(validationErr, ctx.Err())
			}
		}
		afterRef = rows[len(rows)-1].Ref
		if len(rows) < secretRefanoutBatch {
			return validationErr
		}
	}
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
func (s *Service) UpsertClusterSecretBlob(ctx context.Context, blob secrets.SecretBlob, originatorNodeID string) error {
	if s == nil || s.store == nil {
		return errors.New("cluster secret store is not configured")
	}
	unlock := lockSecretSandboxOps(blob.SandboxID)
	defer unlock()
	if err := validatePeerSecretBlob(ctx, s, blob, originatorNodeID); err != nil {
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

var (
	ErrClusterSecretOriginatorDenied     = errors.New("cluster secret originator is not authoritative")
	ErrClusterSecretPlacementUnavailable = errors.New("cluster secret placement is unavailable")
)

func validatePeerSecretBlob(ctx context.Context, s *Service, blob secrets.SecretBlob, originatorNodeID string) error {
	sandboxID := strings.TrimSpace(blob.SandboxID)
	ref := strings.TrimSpace(blob.Ref)
	if sandboxID == "" || ref == "" || len(blob.SealedPayload) == 0 {
		return fmt.Errorf("%w: ref, sandbox_id, and sealed_payload are required", ErrInvalidClusterSecretBlob)
	}
	if blob.Version < 1 {
		return fmt.Errorf("%w: version must be >= 1", ErrInvalidClusterSecretBlob)
	}
	parsed, parseErr := secrets.ParseRef(ref)
	if parseErr != nil || parsed.SandboxID != sandboxID || parsed.Version != blob.Version {
		return fmt.Errorf("%w: ref %q does not match sandbox_id/version", ErrInvalidClusterSecretBlob, ref)
	}
	if strings.TrimSpace(blob.IncarnationID) == "" || strings.TrimSpace(parsed.IncarnationID) == "" {
		return fmt.Errorf("%w: incarnation_id is required", ErrInvalidClusterSecretBlob)
	}
	if blob.IncarnationID != parsed.IncarnationID {
		return fmt.Errorf("%w: incarnation_id does not match ref", ErrInvalidClusterSecretBlob)
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
	if meta.Version != secrets.EnvelopeVersion || strings.TrimSpace(meta.SandboxID) == "" {
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
	if meta.IncarnationID != blob.IncarnationID {
		return fmt.Errorf("%w: envelope incarnation_id does not match wire incarnation_id", ErrInvalidClusterSecretBlob)
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
	// Once a tombstone ages out, live placement intent becomes the permanent
	// anti-resurrection fence: deleted sandboxes have no placement, and a peer
	// may only store the exact recipient set committed before sealing. This
	// keeps tomb GC bounded without opening a stale-PUT vacuum after retention.
	//
	// The read is the local/distributable FSM snapshot, not a leader HTTP
	// round-trip. Create fans out one PUT per backup; asking the Raft leader
	// on each ACK serialized the fleet onto one node and turned a leader
	// election into 503s for every in-flight fan-out. A lagging local FSM
	// fail-closes (no placement ⇒ reject); the originator retries via outbox.
	if s.cfg.EnableCluster {
		placement, ok, err := s.liveSecretPlacement(sandboxID)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrClusterSecretPlacementUnavailable, err)
		}
		if !ok || placement.IsOrphaned() {
			return fmt.Errorf("%w: sandbox %q has no live placement", ErrInvalidClusterSecretBlob, sandboxID)
		}
		authorizedOriginator := strings.TrimSpace(placement.OwnerNodeID)
		if originatorNodeID = strings.TrimSpace(originatorNodeID); authorizedOriginator == "" || originatorNodeID != authorizedOriginator {
			return fmt.Errorf("%w: node %q does not own sandbox %q", ErrClusterSecretOriginatorDenied, originatorNodeID, sandboxID)
		}
		recordedRecipients := secrets.NormalizeRecipients(placement.SecretRecipients)
		// Incarnation fencing: a resealed/recreated placement must not accept
		// sealed blobs from a prior lifetime (empty blob incarnation included).
		placeInc := strings.TrimSpace(placement.IncarnationID)
		blobInc := strings.TrimSpace(blob.IncarnationID)
		if placeInc == "" || blobInc == "" || placeInc != blobInc {
			return fmt.Errorf("%w: incarnation_id does not match live placement", ErrInvalidClusterSecretBlob)
		}
		recipientsPublished := len(recordedRecipients) > 0 && sameStringSlice(recordedRecipients, wireRecipients)
		switch {
		case placement.IsReserved():
			if !recipientsPublished || placement.SecretSealGeneration != 0 || blob.SealGeneration != 1 {
				return fmt.Errorf("%w: initial secret does not match reserved placement", ErrInvalidClusterSecretBlob)
			}
		case recipientsPublished:
			if placement.SecretSealGeneration <= 0 || blob.SealGeneration != placement.SecretSealGeneration {
				return fmt.Errorf("%w: secret generation does not match live placement", ErrInvalidClusterSecretBlob)
			}
		default:
			// Two-phase reseal: the current owner may stage exactly N+1 on the
			// replacement recipients before Raft publishes that set. The old
			// generation remains usable until a replacement ACKs and the CAS lands.
			if blob.SealGeneration != placement.SecretSealGeneration+1 {
				return fmt.Errorf("%w: staged reseal must be the next placement generation", ErrInvalidClusterSecretBlob)
			}
		}
	}
	if s.store != nil {
		tombGen, err := s.store.ClusterSecretTombGenerationForIncarnation(ctx, sandboxID, blob.IncarnationID)
		if err != nil {
			return err
		}
		if tombGen > 0 {
			if blob.SealGeneration <= tombGen {
				return fmt.Errorf("%w: sandbox %q secret was deleted (tombstone gen=%d)", ErrInvalidClusterSecretBlob, sandboxID, tombGen)
			}
			// Newer seal clears tomb atomically inside PutClusterSecret.
		}
		maxGen, _, err := s.store.ClusterSecretSealGeneration(ctx, sandboxID, blob.IncarnationID)
		if err != nil {
			return err
		}
		if maxGen > 0 && blob.SealGeneration < maxGen {
			return fmt.Errorf("%w: stale seal_generation %d < local %d", ErrInvalidClusterSecretBlob, blob.SealGeneration, maxGen)
		}
	}
	return nil
}

// liveSecretPlacement is the peer-PUT fence: a local/distributable FSM
// snapshot. Nil (Agent read failure) is unavailable, not absence; a missing
// ID is absence. AuthoritativePlacementsByIDs is reserved for destructive
// reconcilers that must not treat a lagging follower as "deleted".
func (s *Service) liveSecretPlacement(sandboxID string) (cluster.Placement, bool, error) {
	c := s.Cluster()
	if c == nil {
		return cluster.Placement{}, false, ErrClusterSecretPlacementUnavailable
	}
	placements := c.PlacementsByIDs([]string{sandboxID})
	if placements == nil {
		return cluster.Placement{}, false, ErrClusterSecretPlacementUnavailable
	}
	placement, ok := placements[sandboxID]
	return placement, ok, nil
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
// present, otherwise [self]. It is only used by local-only create paths; HA
// reserved creates use SealAndDistributeReserved's leader-confirmed binding.
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

// SelectReplacementRecipients picks owner + up to maxBackups alive
// worker/mixed members using the same HRW policy as create-time reserve.
// Empty when cluster identity or live candidates are unavailable.
func (s *Service) SelectReplacementRecipients(sandboxID string, maxBackups int) []string {
	c := s.Cluster()
	if c == nil {
		return nil
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil
	}
	ownerID := c.SelfNodeID()
	if p, ok := c.PlacementOf(sandboxID); ok {
		if id := strings.TrimSpace(p.OwnerNodeID); id != "" {
			ownerID = id
		}
	}
	return s.selectReplacementRecipients(sandboxID, ownerID, maxBackups)
}

func (s *Service) selectReplacementRecipients(sandboxID, ownerID string, maxBackups int) []string {
	c := s.Cluster()
	if c == nil {
		return nil
	}
	members := c.LocalMembers()
	if len(members) == 0 {
		members = c.Members()
	}
	candidates := make([]cluster.Member, 0, len(members))
	for _, m := range members {
		if !m.Alive || strings.TrimSpace(m.NodeID) == "" {
			continue
		}
		if !cluster.CanOwnSandboxRole(m.Role) {
			continue
		}
		candidates = append(candidates, m)
	}
	return cluster.SelectSecretRecipients(sandboxID, candidates, ownerID, maxBackups)
}

func (s *Service) anySecretTargetDead(targets []string, alive map[string]struct{}, selfID string) bool {
	frozenPeers := 0
	deadPeers := 0
	for _, id := range targets {
		id = strings.TrimSpace(id)
		if id == "" || id == selfID {
			continue
		}
		frozenPeers++
		if _, ok := alive[id]; !ok {
			deadPeers++
		}
	}
	// Restore the configured replication factor as soon as any intended backup
	// is lost. Waiting for a strict majority means one dead node in the default
	// two-backup set is never replaced and its put-outbox retries forever.
	// Also repair recipient sets narrowed by an older ownership replay. There
	// may be no dead target in [self], so dead-only detection would leave an HA
	// sandbox permanently at one ciphertext copy.
	return (frozenPeers > 0 && deadPeers > 0) || frozenPeers < s.SecretRecipientBackupCount()
}

// secretIncarnationForSeal returns the current cluster placement or local
// audit lifecycle incarnation. Standalone lifecycles use the retained ACL row
// so a destroyed-and-recreated deterministic sandbox ID cannot inherit an old
// worker capability or mix two tenants' evidence.
func (s *Service) secretIncarnationForSeal(sandboxID string) string {
	incarnationID, _ := s.auditIdentityFor(sandboxID)
	return incarnationID
}

// auditIdentityFor resolves the lifecycle id and tenant owner an audit event
// is stamped with. Placement (in-memory) first; then the pre-persist nonce;
// then one SQLite read that returns both — the same single round-trip the
// start path already paid for the incarnation alone.
func (s *Service) auditIdentityFor(sandboxID string) (incarnationID, ownerRef string) {
	if s == nil {
		return "", ""
	}
	if c := s.Cluster(); c != nil {
		if p, ok := c.PlacementOf(sandboxID); ok {
			if inc := strings.TrimSpace(p.IncarnationID); inc != "" {
				return inc, strings.TrimSpace(p.OwnerRef)
			}
		}
	}
	s.auditIncarnationMu.RLock()
	pending := strings.TrimSpace(s.pendingAuditIncarnation[sandboxID])
	s.auditIncarnationMu.RUnlock()
	if pending != "" {
		return pending, ""
	}
	if s.store != nil {
		inc, owner, err := s.store.CurrentSandboxAuditIdentity(context.Background(), sandboxID)
		if err == nil {
			return strings.TrimSpace(inc), strings.TrimSpace(owner)
		}
	}
	return "", ""
}

// prepareAuditIncarnation makes a lifecycle nonce available before the WASM
// runtime asks its capability issuer. The sandbox row and ACL are persisted
// only after runtime creation succeeds; this short-lived map bridges that
// ordering without introducing another database table.
func (s *Service) prepareAuditIncarnation(ctx context.Context, sandboxID, toolboxToken string) (string, error) {
	if s == nil || strings.TrimSpace(sandboxID) == "" {
		return "", errors.New("prepare audit incarnation: sandbox id required")
	}
	if bound := strings.TrimSpace(secrets.IncarnationIDFromContext(ctx)); bound != "" {
		s.auditIncarnationMu.Lock()
		if s.pendingAuditIncarnation == nil {
			s.pendingAuditIncarnation = make(map[string]string)
		}
		existing := strings.TrimSpace(s.pendingAuditIncarnation[sandboxID])
		if existing != "" && existing != bound {
			s.auditIncarnationMu.Unlock()
			return "", errors.New("prepare audit incarnation: sandbox create already in progress")
		}
		s.pendingAuditIncarnation[sandboxID] = bound
		s.auditIncarnationMu.Unlock()
		return bound, nil
	}
	if c := s.Cluster(); c != nil {
		if p, ok := c.PlacementOf(sandboxID); ok {
			if incarnationID := strings.TrimSpace(p.IncarnationID); incarnationID != "" {
				return incarnationID, nil
			}
		}
	}
	s.auditIncarnationMu.RLock()
	pending := strings.TrimSpace(s.pendingAuditIncarnation[sandboxID])
	s.auditIncarnationMu.RUnlock()
	if pending != "" {
		if derived := auditlog.LocalIncarnationID(sandboxID, toolboxToken); derived != "" && derived != pending {
			return "", errors.New("prepare audit incarnation: sandbox create already in progress")
		}
		return pending, nil
	}
	if derived := auditlog.LocalIncarnationID(sandboxID, toolboxToken); derived != "" {
		s.auditIncarnationMu.Lock()
		if s.pendingAuditIncarnation == nil {
			s.pendingAuditIncarnation = make(map[string]string)
		}
		conflict := false
		if existing := strings.TrimSpace(s.pendingAuditIncarnation[sandboxID]); existing != "" {
			if existing != derived {
				conflict = true
			} else {
				derived = existing
			}
		} else {
			s.pendingAuditIncarnation[sandboxID] = derived
		}
		s.auditIncarnationMu.Unlock()
		if conflict {
			return "", errors.New("prepare audit incarnation: sandbox create already in progress")
		}
		return derived, nil
	}
	// Reuse the current lifecycle only while its sandbox row is still live.
	// A retained ACL without a row belongs to a deleted lifecycle and must not
	// seed a replacement that happens to reuse the same deterministic ID.
	if s.store != nil {
		if _, getErr := s.store.Get(context.Background(), sandboxID); getErr == nil {
			if existing, incErr := s.store.CurrentSandboxAuditIncarnation(context.Background(), sandboxID); incErr != nil {
				return "", incErr
			} else if existing = strings.TrimSpace(existing); existing != "" {
				return existing, nil
			}
		} else if !errors.Is(getErr, store.ErrNotFound) {
			return "", getErr
		}
	}
	incarnationID, err := cluster.MintIncarnationID()
	if err != nil {
		return "", fmt.Errorf("mint sandbox audit incarnation: %w", err)
	}
	s.auditIncarnationMu.Lock()
	if s.pendingAuditIncarnation == nil {
		s.pendingAuditIncarnation = make(map[string]string)
	}
	if existing := strings.TrimSpace(s.pendingAuditIncarnation[sandboxID]); existing != "" {
		incarnationID = existing
	} else {
		s.pendingAuditIncarnation[sandboxID] = incarnationID
	}
	s.auditIncarnationMu.Unlock()
	return incarnationID, nil
}

func (s *Service) clearPendingAuditIncarnation(sandboxID, incarnationID string) {
	if s == nil {
		return
	}
	s.auditIncarnationMu.Lock()
	if s.pendingAuditIncarnation[sandboxID] == incarnationID {
		delete(s.pendingAuditIncarnation, sandboxID)
	}
	s.auditIncarnationMu.Unlock()
}

// WantsSecretRecipientFanout reports whether reserve/seal should use a
// multi-recipient set for this create request.
func (s *Service) WantsSecretRecipientFanout(req models.CreateSandboxRequest) bool {
	if s == nil {
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

// RedactClusterSecretsConfigured applies the current secret redaction contract.
func (s *Service) RedactClusterSecretsConfigured(req models.CreateSandboxRequest) models.CreateSandboxRequest {
	return RedactClusterSecrets(req)
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
//
// A single row is a page of one: there is exactly one implementation.
func (s *Service) computeFailoverReady(ctx context.Context, sb *models.Sandbox) *bool {
	if sb == nil {
		return nil
	}
	s.failoverReadyBatch(ctx, []*models.Sandbox{sb})
	return sb.FailoverReady
}

// failoverReadyInputs is everything a page shares: built once per page, read
// per row. Nothing in the per-row step touches the store or the member list.
type failoverReadyInputs struct {
	selfID string
	// alive is the live member set including self. Built once: at 2,000
	// members a 100-row page used to rebuild it 100 times.
	alive map[string]struct{}
	// placements is the control-plane batch for the page's ids; nil means
	// the batch was unavailable and readiness fails closed.
	placements map[string]cluster.Placement
	// incarnation resolves each row's lifecycle (placement first, then the
	// row's own column).
	incarnation map[string]string
	// seals holds this node's sealed-row summaries by ref from one batched
	// read; nil means that read failed and readiness fails closed.
	seals map[string]store.ClusterSecretSealSummary
}

// failoverReadyBatch attaches failover_ready to a page with one membership
// snapshot, one PlacementsByIDs call, and one batched store read for the
// rows that need it (recreate policy). Per-row work is in-memory only, so a
// 100-row page costs one SQLite round trip on the single connection instead
// of a hundred competing with creates.
func (s *Service) failoverReadyBatch(ctx context.Context, sandboxes []*models.Sandbox) {
	if s == nil || len(sandboxes) == 0 {
		return
	}
	var rows []*models.Sandbox
	ids := make([]string, 0, len(sandboxes))
	for _, sb := range sandboxes {
		if sb == nil {
			continue
		}
		if sb.Failover == nil || !sb.Failover.ShouldRecreate() {
			sb.FailoverReady = nil
			continue
		}
		rows = append(rows, sb)
		if sb.ID != "" {
			ids = append(ids, sb.ID)
		}
	}
	if len(rows) == 0 {
		return
	}
	in := failoverReadyInputs{incarnation: make(map[string]string, len(rows))}
	var members []cluster.Member
	members, in.placements = s.failoverReadySnapshots(ids)
	if c := s.Cluster(); c != nil {
		in.selfID = c.SelfNodeID()
	}
	in.alive = make(map[string]struct{}, len(members)+1)
	for _, m := range members {
		if m.Alive && m.NodeID != "" {
			in.alive[m.NodeID] = struct{}{}
		}
	}
	if in.selfID != "" {
		in.alive[in.selfID] = struct{}{}
	}
	refs := make([]string, 0, len(rows))
	for _, sb := range rows {
		incarnationID := strings.TrimSpace(sb.AuditIncarnationID)
		if p, ok := in.placements[sb.ID]; ok && strings.TrimSpace(p.IncarnationID) != "" {
			incarnationID = strings.TrimSpace(p.IncarnationID)
		}
		if incarnationID == "" {
			// Rare: a row without its own lifecycle column and no placement.
			incarnationID = s.secretIncarnationForSeal(sb.ID)
		}
		in.incarnation[sb.ID] = incarnationID
		if sb.ID != "" && incarnationID != "" {
			refs = append(refs, secrets.FormatRef(sb.ID, incarnationID, secrets.RefVersion))
		}
	}
	if s.store != nil && len(refs) > 0 {
		failoverReadyStoreReads.Add(1)
		seals, err := s.store.ClusterSecretSealSummaries(ctx, refs)
		if err != nil {
			// Fail closed, and say so: the old per-row reader treated a store
			// error as "no local row, no recipients" and reported ready=true.
			if s.logger != nil {
				s.logger.Warn("failover readiness: sealed-row batch read failed; reporting not ready", "rows", len(refs), "err", err)
			}
			in.seals = nil
		} else {
			in.seals = seals
		}
	} else {
		in.seals = map[string]store.ClusterSecretSealSummary{}
	}
	for _, sb := range rows {
		sb.FailoverReady = s.computeFailoverReadyRow(sb, &in)
	}
}

// failoverReadySnapshots loads membership once and placement rows only for the
// requested sandbox IDs (PlacementsByIDs). Prefer LocalMembers (gossip) so
// agent workers do not HTTP-fan-out for every row; fall back to Members() when
// the gossip view is empty.
func (s *Service) failoverReadySnapshots(ids []string) (members []cluster.Member, placements map[string]cluster.Placement) {
	placements = map[string]cluster.Placement{}
	c := s.Cluster()
	if c == nil {
		return nil, placements
	}
	members = c.LocalMembers()
	if len(members) == 0 {
		members = c.Members()
	}
	if len(ids) == 0 {
		return members, placements
	}
	placements = c.PlacementsByIDs(ids)
	return members, placements
}

// computeFailoverReadyRow is the per-row step over prebuilt page inputs. It
// reads maps and the in-memory ACK state only.
func (s *Service) computeFailoverReadyRow(sb *models.Sandbox, in *failoverReadyInputs) *bool {
	if sb == nil || sb.Failover == nil || !sb.Failover.ShouldRecreate() {
		return nil
	}
	ready := false
	if (in.placements == nil && s.Cluster() != nil) || in.seals == nil {
		// The control-plane batch or the local sealed-row read was
		// unavailable. Fail readiness closed without a per-row fallback.
		return &ready
	}
	incarnationID := in.incarnation[sb.ID]
	ref := ""
	if sb.ID != "" && incarnationID != "" {
		ref = secrets.FormatRef(sb.ID, incarnationID, secrets.RefVersion)
	}
	seal, sealed := in.seals[ref]
	var recipients []string
	placement, placed := in.placements[sb.ID]
	if placed && len(placement.SecretRecipients) > 0 {
		recipients = placement.SecretRecipients
	} else if sealed {
		recipients = seal.Recipients
	}
	pruneDeadSecretHolders(sb.ID, incarnationID, in.alive)
	localGen, localHolds := int64(0), false
	if sealed && seal.SealGeneration > 0 {
		localGen, localHolds = seal.SealGeneration, true
	}
	selfID := in.selfID
	if localGen > 0 && secretHolderGeneration(sb.ID, incarnationID) != localGen {
		seed := []string{}
		if localHolds && selfID != "" {
			seed = []string{selfID}
		}
		replaceSecretHoldersForGeneration(sb.ID, incarnationID, localGen, seed...)
	}
	if localGen > 0 {
		setSecretHolderTargets(sb.ID, incarnationID, localGen, recipients)
	}
	holders := secretHolderNodeIDs(sb.ID, incarnationID)
	if len(holders) == 0 && len(recipients) > 0 && localHolds && selfID != "" {
		resetSecretHoldersForGeneration(sb.ID, incarnationID, localGen, selfID)
		holders = secretHolderNodeIDs(sb.ID, incarnationID)
	}

	liveHolders := 0
	for _, id := range holders {
		if _, ok := in.alive[id]; !ok {
			continue
		}
		if id == selfID && !localHolds {
			continue
		}
		liveHolders++
	}
	hasSecret := sealed || (placed && (strings.TrimSpace(placement.SecretRef) != "" || len(recipients) > 0))
	switch {
	case !hasSecret:
		ready = true
	case !s.cfg.EnableCluster && len(recipients) <= 1 && liveHolders >= 1:
		ready = true
	case len(recipients) > 1 && liveHolders >= 2:
		ready = true
	}
	return &ready
}

// failoverReadyStoreReads counts store round trips made for failover
// readiness (tests assert one per page).
var failoverReadyStoreReads atomic.Int64

func (s *Service) localSealedSecretGeneration(ctx context.Context, sandboxID, incarnationID string) (gen int64, holds bool) {
	if s == nil || s.store == nil || strings.TrimSpace(sandboxID) == "" || strings.TrimSpace(incarnationID) == "" {
		return 0, false
	}
	gen, holds, err := s.store.ClusterSecretSealGeneration(ctx, sandboxID, incarnationID)
	if err != nil || !holds || gen <= 0 {
		return 0, false
	}
	return gen, true
}

// HasLocalSealedSecretGeneration reports whether this node holds a sealed row
// with seal_generation >= minGeneration (peer HEAD probe target).
func (s *Service) HasLocalSealedSecretGeneration(ctx context.Context, sandboxID, incarnationID string, minGeneration int64) (bool, error) {
	if s == nil || s.store == nil {
		return false, nil
	}
	if minGeneration <= 0 {
		return false, errors.New("minimum seal generation must be positive")
	}
	if strings.TrimSpace(incarnationID) == "" {
		return false, errors.New("secret incarnation id is required")
	}
	gen, holds, err := s.store.ClusterSecretSealGeneration(ctx, sandboxID, incarnationID)
	if err != nil {
		return false, err
	}
	return holds && gen >= minGeneration, nil
}

func (s *Service) secretRecipientsForSandboxCached(ctx context.Context, sandboxID, incarnationID string, placements map[string]cluster.Placement) []string {
	if placements != nil {
		if p, ok := placements[sandboxID]; ok && len(p.SecretRecipients) > 0 {
			return p.SecretRecipients
		}
	} else {
		if c := s.Cluster(); c != nil {
			if p, ok := c.PlacementOf(sandboxID); ok && len(p.SecretRecipients) > 0 {
				return p.SecretRecipients
			}
		}
	}
	if s.store == nil {
		return nil
	}
	rec, err := s.store.GetClusterSecretForSandboxIncarnation(ctx, sandboxID, incarnationID)
	if err != nil || rec == nil {
		return nil
	}
	return rec.Recipients
}

func (s *Service) attachFailoverReady(ctx context.Context, sb *models.Sandbox) {
	if sb == nil {
		return
	}
	sb.FailoverReady = s.computeFailoverReady(ctx, sb)
}

func (s *Service) attachFailoverReadyAll(ctx context.Context, sandboxes []*models.Sandbox) {
	s.failoverReadyBatch(ctx, sandboxes)
}
