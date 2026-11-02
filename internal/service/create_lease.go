package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// One create of a sandbox ID runs on this node at a time.
//
// A create that names its ID (an Idempotency-Key create, the cluster's
// reserved create, a failover recreate) can meet another create of the same
// ID: an SDK retry after a proxy 502 or a client timeout while the first
// create still pulls its image, two ingress nodes routing one key's retries
// to the same owner, the owner watcher racing a local create. Every per-ID
// side effect of a create is keyed by the ID alone and knows of one creator:
//
//   - the capacity reservation (Admitter.Admit overwrites it, Release
//     deletes it);
//   - the external mounts (MountAll replaces the ID's mount set, UnmountAll
//     tears it down and removes rootDir/<id>);
//   - the runtime's per-ID state: container and pause names, the ready
//     socket, the Firecracker TAP slot and run directory;
//   - a first-use platform volume and the public route sandbox-<id>;
//   - in a cluster, the sealed secrets and the reservation itself, which a
//     failed overlap create retracts (DestroySandbox, CancelReservation).
//
// A second create that ran alongside the first failed on the name collision
// and rolled all of that back under the first, which went on running with
// no reservation and no mounts (and, in a cluster, could be destroyed).
//
// So the second create waits. createLeases holds, per ID, the create running
// it. A create that finds the lease taken waits for it to be given back, then
// takes it and looks again, so it sees exactly what a retry arriving one
// moment later would: the first create's sandbox, which the caller replays,
// or, after a failure the first create rolled back, nothing, and the caller
// creates afresh (a retry after a failure must be able to succeed). The
// waiter never adopts the first create's error: that error belonged to an
// attempt the client already gave up on.
//
// A keyed create whose request differs from the running one's is refused at
// once (ErrIdempotencyKeyReused): it would be refused after the wait anyway.
// The wait is bounded by the caller's context and by createLeaseWait, the
// longest a create and its rollback can run; past it the waiter answers
// ErrCreateInProgress (503 with Retry-After) and has touched nothing.
//
// The lease is the outermost hold of a create: CreateSandboxWithID takes it
// before it looks for the row and gives it back after the create's rollback
// has run, and a caller that adds steps after the create (the cluster
// overlap's seal and promote, a facade's own state row) takes it first so
// those steps are inside it too. The inner takes are re-entrant through the
// context.

// ErrCreateInProgress is answered to a create that waited out createLeaseWait
// behind another create of the same sandbox ID on this node. Nothing was
// created or changed; the same request retried later replays or creates.
var ErrCreateInProgress = errors.New("a create of this sandbox is still running on this node; retry shortly")

// errCreateLeaseKeyMismatch is acquire's refusal of a keyed create whose
// request differs from the running create's; BeginSandboxCreate turns it
// into the client's ErrIdempotencyKeyReused, which names the key.
var errCreateLeaseKeyMismatch = errors.New("create lease held by a different request")

const (
	// defaultCreateLeaseWait stands in for the create timeout when
	// SB_CREATE_TIMEOUT_SEC disables it, so a waiter is still bounded.
	defaultCreateLeaseWait = 10 * time.Minute
	// createLeaseWaitSlack covers what a lease holder runs past the create
	// itself: the cluster seal and promote (overlapCommitTimeout each) and a
	// failed overlap's retract (30s).
	createLeaseWaitSlack = time.Minute
)

type createLeaseCtxKey struct{}

// createLeases is the per-ID create lease table.
type createLeases struct {
	mu     sync.Mutex
	leases map[string]*createLease
}

type createLease struct {
	digest string        // the holder's request digest; "" for an unkeyed create
	done   chan struct{} // closed when the holder gives the lease back
}

// acquire takes id's lease for a create made with digests, waiting while
// another create holds it. It refuses at once a keyed create whose request
// differs from the holder's (both must be keyed to compare), and gives up
// with ErrCreateInProgress after wait or with ctx's error. The returned
// release runs once.
func (l *createLeases) acquire(ctx context.Context, id string, digests []string, wait time.Duration) (func(), error) {
	var expired <-chan time.Time
	for {
		l.mu.Lock()
		held := l.leases[id]
		if held == nil {
			lease := &createLease{done: make(chan struct{})}
			if len(digests) > 0 {
				lease.digest = digests[0]
			}
			if l.leases == nil {
				l.leases = map[string]*createLease{}
			}
			l.leases[id] = lease
			l.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					l.mu.Lock()
					delete(l.leases, id)
					l.mu.Unlock()
					close(lease.done)
				})
			}, nil
		}
		mismatch := held.digest != "" && len(digests) > 0 && !createDigestsMatch(held.digest, digests)
		l.mu.Unlock()
		if mismatch {
			return nil, errCreateLeaseKeyMismatch
		}
		if expired == nil {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			expired = timer.C
		}
		select {
		case <-held.done:
			// Look again: another waiter may have taken it first.
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-expired:
			return nil, ErrCreateInProgress
		}
	}
}

// createLeaseWait bounds a wait for another create of the same ID: the create
// timeout (the longest the holder's create can run), its rollback budget, and
// the slack for the cluster steps around it.
func (s *Service) createLeaseWait() time.Duration {
	if s.testCreateLeaseWait > 0 {
		return s.testCreateLeaseWait
	}
	wait := s.cfg.CreateSandboxTimeout()
	if wait <= 0 {
		wait = defaultCreateLeaseWait
	}
	return wait + createRollbackTimeout + createLeaseWaitSlack
}

// holdsCreateLease reports whether ctx is inside id's create lease.
func holdsCreateLease(ctx context.Context, id string) bool {
	held, _ := ctx.Value(createLeaseCtxKey{}).(string)
	return held != "" && held == id
}

// beginCreateLease takes id's create lease (see the top of this file) and
// returns the context to create with: it carries the lease, so an inner take
// of the same ID is a no-op, and a keyed create's digests, which the row
// write stores. It does not read the stored digest; a caller that replays a
// stored sandbox checks it (checkStoredCreateDigest).
func (s *Service) beginCreateLease(ctx context.Context, id string, digests []string) (context.Context, func(), error) {
	noop := func() {}
	id = strings.TrimSpace(id)
	if id == "" || holdsCreateLease(ctx, id) {
		return ctx, noop, nil
	}
	if len(digests) == 0 || strings.TrimSpace(digests[0]) == "" {
		digests = nil
	}
	release, err := s.createLeases.acquire(ctx, id, digests, s.createLeaseWait())
	if errors.Is(err, errCreateLeaseKeyMismatch) {
		return ctx, noop, keyReusedError(ctx)
	}
	if err != nil {
		return ctx, noop, err
	}
	return context.WithValue(withCreateRequestDigests(ctx, digests), createLeaseCtxKey{}, id), release, nil
}

// BeginSandboxCreate takes id's create lease for a caller that runs steps of
// its own around the create (the cluster overlap's seal and promote, a
// facade's state row), so a second create of id waits for all of them, not
// only for CreateSandboxWithID inside. Within one create, the outer take
// holds the lease and CreateSandboxWithID's inner take joins it.
//
// It refuses a keyed create whose request differs from the one running
// (ErrIdempotencyKeyReused) or from the one id's sandbox was made with, and
// returns ErrCreateInProgress or ctx's error when the wait gives up. A create
// without digests (no key, or no server key) is not checked. The returned ctx
// is the one to create with; release gives the lease back and must run after
// every step that can roll the create back.
func (s *Service) BeginSandboxCreate(ctx context.Context, id string, digests []string) (context.Context, func(), error) {
	if holdsCreateLease(ctx, strings.TrimSpace(id)) {
		// The outer take checked the stored digest under this same lease.
		return ctx, func() {}, nil
	}
	ctx, release, err := s.beginCreateLease(ctx, id, digests)
	if err != nil {
		return ctx, release, err
	}
	if err := s.checkStoredCreateDigest(ctx, id); err != nil {
		release()
		return ctx, func() {}, err
	}
	return ctx, release, nil
}

// admitCreate reserves capacity for a create of sandboxID and returns the
// release its rollback calls. The reservation is the create's only if it made
// it: an ID that already holds one (its live sandbox, or a create of the ID
// that did not go through the lease) keeps it, and the returned release is a
// no-op, so a create that then fails on the taken ID frees nothing it does
// not own. Under the create lease that case is a leaked reservation or a bug
// elsewhere, so it is logged.
func (s *Service) admitCreate(sandboxID string, req models.CreateSandboxRequest) (func(), error) {
	if s.admitter == nil {
		return func() {}, nil
	}
	owned, err := s.admitter.AdmitOwned(sandboxID, capacityRequestFromCreate(req))
	if err != nil {
		return nil, err
	}
	if !owned {
		if s.logger != nil {
			s.logger.Warn("create: sandbox id already holds a capacity reservation; leaving it to its holder",
				"sandbox_id", sandboxID)
		}
		return func() {}, nil
	}
	return func() { s.admitter.Release(sandboxID) }, nil
}

// rollbackCreatePublicRoutes undoes the public routes a failed create
// installed. When the row insert found the ID taken, the route sandbox-<id>
// belongs to the stored sandbox: this create's sync pointed it at its own
// container (or the delete just removed it), so it is put back from the
// stored row instead of being left deleted.
func (s *Service) rollbackCreatePublicRoutes(ctx context.Context, sandbox *models.Sandbox, idTaken bool) {
	_ = s.deleteSandboxPublicRoutes(ctx, sandbox)
	if !idTaken || s.store == nil {
		return
	}
	existing, err := s.store.Get(ctx, sandbox.ID)
	if err != nil || existing == nil || !sandboxAllowsPublicTraffic(existing) {
		return
	}
	if err := s.syncSandboxPublicRoute(ctx, existing); err != nil && s.logger != nil {
		s.logger.Warn("create: restoring the public route of the sandbox holding this id failed; reconcile repairs it",
			"sandbox_id", sandbox.ID, "error", err)
	}
}
