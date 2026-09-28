package cluster

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// OwnedRecoveryRequest asks the control plane for the recovery work assigned
// to the CALLING node. The owner is never taken from the body: the handler
// uses the mTLS-authenticated peer identity, so a node can only ever ask for
// its own placements.
type OwnedRecoveryRequest struct {
	Limit     int    `json:"limit,omitempty"`
	PageToken string `json:"page_token,omitempty"`
}

// OwnedRecoveryResponse carries full placements — spec and secret handle
// included — for the caller's own failover-recreate sandboxes. It is the
// worker-side equivalent of the FSM read a server-role owner watcher does
// locally; without it a dedicated worker has no way to learn that a placement
// was reassigned to it.
type OwnedRecoveryResponse struct {
	Placements    []Placement `json:"placements"`
	NextPageToken string      `json:"next_page_token,omitempty"`
	// Authoritative distinguishes "this node owns no recovery work" from
	// "the control plane could not answer". The watcher must not treat the
	// second as the first.
	Authoritative bool `json:"authoritative,omitempty"`
}

// ReassignStuckRequest asks the leader to move a placement this node has
// failed to recreate. Target selection stays on the FSM side: it needs drain
// state, pending reservations and capacity leases that an Agent does not hold.
type ReassignStuckRequest struct {
	SandboxID string `json:"sandbox_id"`
	// IncarnationID fences the request against a placement that has already
	// moved on since this node last read it.
	IncarnationID string `json:"incarnation_id,omitempty"`
}

// ErrStuckReassignNotOwner rejects a reassignment request from a node that is
// not the placement's current owner (or names a superseded incarnation). A
// stale request from a previous owner must not bounce a live sandbox off the
// node that has just taken it over.
var ErrStuckReassignNotOwner = errors.New("cluster: reassign requester is not the current placement owner")

// ownedRecoveryPageLimit bounds one worker poll. Failover bursts are small
// (the dead owner's share of the fleet), and the cursor carries the rest to
// the next tick rather than making one node's recovery a fleet-sized read.
const ownedRecoveryPageLimit = 256

// ownedRecoveryScanBudget bounds how many owner-index rows ONE request may
// inspect while looking for eligible recovery work. The index carries every
// placement the node owns, but only failover-recreate rows with a spec are
// eligible, so a dense worker can hold thousands of ineligible rows before
// the first eligible one. Filling the page server-side keeps the worker from
// paying a round trip per ineligible run; the budget keeps the leader from
// paying an unbounded scan for one poll.
const ownedRecoveryScanBudget = 4 * ownedRecoveryPageLimit

// maxOwnedRecoveryPagesPerTick bounds one tick's paging. The cursor is kept
// across ticks (see Agent.ownedRecoveryCursor), so this caps the work per
// tick without ever abandoning the rest of the walk.
const maxOwnedRecoveryPagesPerTick = 16

// AttachRecreator wires the service-layer recreate hook used by the worker
// owner watcher. It mirrors Cluster.AttachRecreator so pkg/daemon attaches the
// same hook whatever role the node runs — a dedicated worker previously had no
// such method, so the daemon's interface probe silently skipped it and the
// only automatic recreation loop in the product belonged to *Cluster.
func (a *Agent) AttachRecreator(r SandboxRecreator) {
	if a == nil {
		return
	}
	a.recreatorMu.Lock()
	a.recreator = r
	a.recreatorMu.Unlock()
}

func (a *Agent) currentRecreator() SandboxRecreator {
	if a == nil {
		return nil
	}
	a.recreatorMu.RLock()
	defer a.recreatorMu.RUnlock()
	return a.recreator
}

// startOwnerWatcher spawns the dedicated-worker recovery loop. It polls the
// control plane for placements the FSM has assigned to THIS node and asks the
// service layer to materialize them — the work a server-role node does from
// its local FSM in Cluster.recreateOwnedSandboxes.
//
// The worker does not join Raft to get this: the control plane answers an
// owner-scoped, paged, mTLS-authenticated query, and the owner is the
// authenticated peer identity rather than anything the caller supplies.
func (a *Agent) startOwnerWatcher() {
	a.recreateFailures = &recreateFailureTracker{counts: make(map[string]int), permanent: make(map[string]struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	a.ownerWatcherStop = cancel
	go func() {
		t := time.NewTicker(ownerWatcherInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.recreateOwnedSandboxes(ctx)
			}
		}
	}()
}

func (a *Agent) stopOwnerWatcher() {
	if a != nil && a.ownerWatcherStop != nil {
		a.ownerWatcherStop()
	}
}

func (a *Agent) recreateOwnedSandboxes(ctx context.Context) {
	r := a.currentRecreator()
	if r == nil {
		return
	}
	deps := ownerRecreateDeps{
		recreator: r,
		failures:  a.recreateFailures,
		logger:    a.logger,
		escalate:  a.requestReassignStuckPlacement,
	}
	// Resume where the last tick stopped. An empty filtered page is NOT the
	// end of the walk: OwnedRecoveryPlacements pages the owner index and then
	// drops rows without failover-recreate or a spec, so a page can be empty
	// and still have work behind it. Treating that as completion restarts the
	// walk from the beginning every tick, and a dense worker whose eligible
	// rows sort after its ineligible ones is never recovered at all.
	pageToken := a.ownedRecoveryCursor
	for pages := 0; pages < maxOwnedRecoveryPagesPerTick; pages++ {
		page, ok := a.fetchOwnedRecoveryPage(ctx, pageToken)
		if !ok {
			// Not authoritative. A worker must not conclude "I own nothing"
			// from an unreachable control plane; the next tick retries from
			// the same cursor.
			return
		}
		for _, p := range page.Placements {
			if ctx.Err() != nil {
				a.ownedRecoveryCursor = pageToken
				return
			}
			id := strings.TrimSpace(p.SandboxID)
			if id == "" {
				continue
			}
			recreateOwnedPlacement(ctx, deps, id, p)
		}
		// A cursor that does not progress cannot be walked further; restart
		// from the beginning next tick rather than spinning on it.
		if page.NextPageToken == "" || page.NextPageToken == pageToken {
			a.ownedRecoveryCursor = ""
			return
		}
		pageToken = page.NextPageToken
	}
	// Out of page budget for this tick, with the walk unfinished.
	a.ownedRecoveryCursor = pageToken
}

func (a *Agent) fetchOwnedRecoveryPage(ctx context.Context, pageToken string) (OwnedRecoveryResponse, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, controlPlanePlacementRequestTimeout)
	defer cancel()
	var resp OwnedRecoveryResponse
	body := OwnedRecoveryRequest{Limit: ownedRecoveryPageLimit, PageToken: pageToken}
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalOwnedRecoveryPath, PublicInternalOwnedRecoveryPath, body, &resp); err != nil {
		a.logger.Warn("cluster agent: owned recovery poll failed; retrying next tick", "err", err)
		return OwnedRecoveryResponse{}, false
	}
	return resp, resp.Authoritative
}

// requestReassignStuckPlacement asks the leader to run its own stuck-placement
// reassignment for a sandbox this worker keeps failing to recreate. The worker
// deliberately does not choose the target: that needs drain state, pending
// reservations and capacity leases the FSM owns.
func (a *Agent) requestReassignStuckPlacement(ctx context.Context, id string, p Placement) {
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	body := ReassignStuckRequest{SandboxID: id, IncarnationID: strings.TrimSpace(p.IncarnationID)}
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalReassignStuckPath, PublicInternalReassignStuckPath, body, nil); err != nil {
		a.logger.Warn("cluster agent: reassign request for stuck placement failed; will retry",
			"sandbox_id", id, "err", err)
		return
	}
	if a.recreateFailures != nil {
		a.recreateFailures.clear(id)
	}
	a.logger.Warn("cluster agent: asked the control plane to reassign a stuck placement",
		"sandbox_id", id, "from", a.nodeID)
}

// OwnedRecoveryPlacements answers an owner-scoped recovery query for ownerID.
// Only placements that node owns AND that opted into failover recreate are
// returned, with the spec and secret handle the owner needs to rebuild them.
//
// Callers must pass the mTLS-authenticated peer identity as ownerID; nothing
// here derives the owner from a request body.
func (c *Cluster) OwnedRecoveryPlacements(ownerID string, limit int, pageToken string) OwnedRecoveryResponse {
	ownerID = strings.TrimSpace(ownerID)
	if c == nil || c.fsm == nil || ownerID == "" {
		return OwnedRecoveryResponse{}
	}
	if limit <= 0 || limit > ownedRecoveryPageLimit {
		limit = ownedRecoveryPageLimit
	}
	// The owner index is the bounded read: a worker asking for its own rows
	// must never pay a scan of the global placement table.
	out := OwnedRecoveryResponse{Authoritative: true}
	cursor := pageToken
	// Keep walking the owner index until the page is full, the owner's rows
	// are exhausted, or the scan budget is spent. Returning an empty page with
	// a live cursor is legitimate here — most of a dense worker's rows are
	// ineligible — so the filling happens on this side, where one index walk
	// replaces a round trip per ineligible run.
	for scanned := 0; scanned < ownedRecoveryScanBudget; {
		want := limit - len(out.Placements)
		if want <= 0 {
			break
		}
		page := c.fsm.placementPage(PlacementPageRequest{
			Limit:       want,
			PageToken:   cursor,
			OwnerNodeID: ownerID,
		})
		scanned += len(page.Placements)
		for _, hot := range page.Placements {
			full, ok := c.fsm.get(hot.SandboxID)
			if !ok {
				continue
			}
			// Re-check the owner against the full record: the page came from
			// the index, and a reassignment could have landed between the two
			// reads.
			if strings.TrimSpace(full.OwnerNodeID) != ownerID {
				continue
			}
			if !placementWantsFailoverRecreate(full) || full.Spec == nil {
				continue
			}
			out.Placements = append(out.Placements, full)
		}
		if page.NextPageToken == "" || page.NextPageToken == cursor {
			cursor = page.NextPageToken
			break
		}
		cursor = page.NextPageToken
	}
	out.NextPageToken = cursor
	return out
}

// ReassignStuckPlacement runs the leader's stuck-placement reassignment on
// behalf of a worker that cannot recreate a sandbox it owns. requesterID is
// the mTLS-authenticated caller; only the current owner may ask.
func (c *Cluster) ReassignStuckPlacement(ctx context.Context, requesterID, sandboxID, incarnationID string) error {
	requesterID = strings.TrimSpace(requesterID)
	sandboxID = strings.TrimSpace(sandboxID)
	if c == nil || c.fsm == nil {
		return ErrUnknownSandbox
	}
	if requesterID == "" || sandboxID == "" {
		return ErrUnknownSandbox
	}
	p, ok := c.fsm.get(sandboxID)
	if !ok {
		return ErrUnknownSandbox
	}
	if strings.TrimSpace(p.OwnerNodeID) != requesterID {
		// Not this node's placement to move. Stale requests from a previous
		// owner must not be able to bounce a live sandbox off its new home.
		return ErrStuckReassignNotOwner
	}
	if incarnationID != "" && strings.TrimSpace(p.IncarnationID) != strings.TrimSpace(incarnationID) {
		return ErrStuckReassignNotOwner
	}
	// Report the outcome. A worker that is told "reassigned" clears the
	// failure counter driving its escalation, so answering success for a
	// move that did not happen turns a stuck sandbox into an endless local
	// retry loop with no escalation left.
	return c.tryReassignStuckPlacement(ctx, sandboxID, p)
}
