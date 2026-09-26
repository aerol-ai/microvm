package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// workerRecreator records what the worker owner watcher asked the service to
// rebuild.
type workerRecreator struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (r *workerRecreator) RecreateSandbox(_ context.Context, id string, _ models.CreateSandboxRequest, _ PlacementSecrets, _ map[int]ExposedPortRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, id)
	return r.err
}

func (r *workerRecreator) recreated() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func failoverRecreatePlacement(id, owner string) Placement {
	spec := models.CreateSandboxRequest{
		Image:    "alpine",
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	return Placement{
		SandboxID:     id,
		OwnerNodeID:   owner,
		IncarnationID: "inc-" + id,
		State:         PlacementStatePlaced,
		Spec:          &spec,
	}
}

// A dedicated worker runs an Agent, which had no AttachRecreator at all — so
// pkg/daemon's interface probe skipped it and the only automatic recreation
// loop in the product belonged to *Cluster. A reassignment to a worker was a
// failover that silently never completed.
func TestAgentImplementsRecreatorAttachment(t *testing.T) {
	var _ interface {
		AttachRecreator(SandboxRecreator)
	} = (*Agent)(nil)
	var _ interface {
		AttachRecreator(SandboxRecreator)
	} = (*Cluster)(nil)
}

// End-to-end worker recovery: the control plane says this node owns a
// failover-recreate placement, and the worker materializes it without holding
// any FSM or joining Raft.
func TestAgentOwnerWatcherRecreatesOwnedPlacements(t *testing.T) {
	const owned = "sb-owned-by-worker"
	var gotRequests []OwnedRecoveryRequest
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalOwnedRecoveryPath {
			http.NotFound(w, r)
			return
		}
		var req OwnedRecoveryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode owned recovery request: %v", err)
		}
		gotRequests = append(gotRequests, req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OwnedRecoveryResponse{
			Placements:    []Placement{failoverRecreatePlacement(owned, "worker-self")},
			Authoritative: true,
		})
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	rec := &workerRecreator{}
	agent.recreateFailures = &recreateFailureTracker{counts: map[string]int{}, permanent: map[string]struct{}{}}
	agent.AttachRecreator(rec)
	agent.recreateOwnedSandboxes(context.Background())

	if got := rec.recreated(); len(got) != 1 || got[0] != owned {
		t.Fatalf("worker recreated %v, want [%s]", got, owned)
	}
	if len(gotRequests) != 1 || gotRequests[0].Limit != ownedRecoveryPageLimit {
		t.Fatalf("owned recovery requests = %+v, want one bounded page", gotRequests)
	}
}

// An unreachable control plane must not read as "this node owns nothing":
// that would silently stop recovery for the duration of the blip.
func TestAgentOwnerWatcherSkipsWhenControlPlaneUnavailable(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	rec := &workerRecreator{}
	agent.recreateFailures = &recreateFailureTracker{counts: map[string]int{}, permanent: map[string]struct{}{}}
	agent.AttachRecreator(rec)
	agent.recreateOwnedSandboxes(context.Background())

	if got := rec.recreated(); len(got) != 0 {
		t.Fatalf("recreated %v from an unavailable control plane", got)
	}
}

// Repeated local failures must escalate to the leader instead of retrying the
// same node forever — the behavior maxRecreateFailuresBeforeReassign exists
// for, which a worker could not reach because it cannot apply Raft itself.
func TestAgentOwnerWatcherEscalatesStuckPlacement(t *testing.T) {
	const stuck = "sb-stuck-on-worker"
	reassigns := 0
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case PublicInternalOwnedRecoveryPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OwnedRecoveryResponse{
				Placements:    []Placement{failoverRecreatePlacement(stuck, "worker-self")},
				Authoritative: true,
			})
		case PublicInternalReassignStuckPath:
			var req ReassignStuckRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode reassign request: %v", err)
			}
			if req.SandboxID != stuck || req.IncarnationID != "inc-"+stuck {
				t.Errorf("reassign request = %+v, want the stuck sandbox and its incarnation", req)
			}
			reassigns++
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	rec := &workerRecreator{err: errors.New("image pull failed")}
	agent.recreateFailures = &recreateFailureTracker{counts: map[string]int{}, permanent: map[string]struct{}{}}
	agent.AttachRecreator(rec)
	for range maxRecreateFailuresBeforeReassign {
		agent.recreateOwnedSandboxes(context.Background())
	}
	if reassigns != 1 {
		t.Fatalf("reassign requests = %d after %d failures, want 1", reassigns, maxRecreateFailuresBeforeReassign)
	}
}

// Recipient-denied is permanent for this node: walking the fleet cannot help,
// and the worker must stop rather than churn the placement.
func TestAgentOwnerWatcherStopsOnRecipientDenied(t *testing.T) {
	const denied = "sb-denied"
	reassigns := 0
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case PublicInternalOwnedRecoveryPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OwnedRecoveryResponse{
				Placements:    []Placement{failoverRecreatePlacement(denied, "worker-self")},
				Authoritative: true,
			})
		case PublicInternalReassignStuckPath:
			reassigns++
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})

	rec := &workerRecreator{err: fmt.Errorf("open: %w", secrets.ErrRecipientDenied)}
	agent.recreateFailures = &recreateFailureTracker{counts: map[string]int{}, permanent: map[string]struct{}{}}
	agent.AttachRecreator(rec)
	for range maxRecreateFailuresBeforeReassign + 2 {
		agent.recreateOwnedSandboxes(context.Background())
	}
	if reassigns != 0 {
		t.Fatalf("recipient-denied placement was reassigned %d times; it is permanent for this node", reassigns)
	}
	if got := rec.recreated(); len(got) != 1 {
		t.Fatalf("recipient-denied placement retried %d times, want exactly 1 attempt", len(got))
	}
}

// The control plane answers the owner-scoped query from the authenticated
// caller's identity only, and only for failover-recreate placements with a
// replicated spec.
func TestOwnedRecoveryPlacementsIsOwnerScoped(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-owner", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	mine := failoverRecreatePlacement("sb-mine", "wrk-a")
	theirs := failoverRecreatePlacement("sb-theirs", "wrk-b")
	nonHA := failoverRecreatePlacement("sb-non-ha", "wrk-a")
	nonHA.Spec = &models.CreateSandboxRequest{Image: "alpine"}

	c.fsm.mu.Lock()
	for _, p := range []Placement{mine, theirs, nonHA} {
		c.fsm.placements[p.SandboxID] = p
		c.fsm.claimOwnerLocked(p.SandboxID, p)
	}
	c.fsm.mu.Unlock()

	resp := c.OwnedRecoveryPlacements("wrk-a", 0, "")
	if !resp.Authoritative {
		t.Fatal("owner-scoped answer must be authoritative")
	}
	if len(resp.Placements) != 1 || resp.Placements[0].SandboxID != "sb-mine" {
		t.Fatalf("owned recovery = %+v, want only wrk-a's failover-recreate placement", resp.Placements)
	}
	if resp.Placements[0].Spec == nil {
		t.Fatal("owner must receive the spec; without it the sandbox cannot be rebuilt")
	}
	if got := c.OwnedRecoveryPlacements("", 0, ""); got.Authoritative || len(got.Placements) != 0 {
		t.Fatalf("empty owner returned %+v; the owner is the authenticated peer, never a blank", got)
	}
}

// A stale request from a node that no longer owns the placement must not be
// able to bounce it off its new home.
func TestReassignStuckPlacementRejectsNonOwner(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-reassign", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	p := failoverRecreatePlacement("sb-moved", "wrk-new")
	c.fsm.mu.Lock()
	c.fsm.placements[p.SandboxID] = p
	c.fsm.claimOwnerLocked(p.SandboxID, p)
	c.fsm.mu.Unlock()

	if err := c.ReassignStuckPlacement(context.Background(), "wrk-old", "sb-moved", ""); !errors.Is(err, ErrStuckReassignNotOwner) {
		t.Fatalf("previous owner's reassign = %v, want ErrStuckReassignNotOwner", err)
	}
	if err := c.ReassignStuckPlacement(context.Background(), "wrk-new", "sb-moved", "inc-stale"); !errors.Is(err, ErrStuckReassignNotOwner) {
		t.Fatalf("stale incarnation reassign = %v, want ErrStuckReassignNotOwner", err)
	}
	if err := c.ReassignStuckPlacement(context.Background(), "wrk-new", "sb-absent", ""); !errors.Is(err, ErrUnknownSandbox) {
		t.Fatalf("unknown sandbox reassign = %v, want ErrUnknownSandbox", err)
	}
}

// seedOwnedRecoveryRows fills an FSM with n ineligible rows for owner, then one
// failover-recreate row that sorts after all of them.
func seedOwnedRecoveryRows(c *Cluster, owner string, ineligible int, haID string) {
	for i := range ineligible {
		p := failoverRecreatePlacement(fmt.Sprintf("a-%05d", i), owner)
		// No failover policy and no spec: owned, but not recovery work.
		p.Spec = nil
		c.fsm.placements[p.SandboxID] = p
		c.fsm.claimOwnerLocked(p.SandboxID, p)
	}
	ha := failoverRecreatePlacement(haID, owner)
	c.fsm.placements[ha.SandboxID] = ha
	c.fsm.claimOwnerLocked(ha.SandboxID, ha)
}

// OwnedRecoveryPlacements pages the owner index and THEN drops rows that are
// not recovery work, so a page can legitimately come back empty with more
// work behind it. A dense worker whose eligible rows sort after a page's
// worth of ineligible ones must still be recovered.
func TestOwnedRecoveryFillsPagePastIneligibleRows(t *testing.T) {
	c := &Cluster{fsm: newPlacementFSM()}
	seedOwnedRecoveryRows(c, "worker-self", ownedRecoveryPageLimit, "z-must-recover")

	page := c.OwnedRecoveryPlacements("worker-self", ownedRecoveryPageLimit, "")
	if len(page.Placements) != 1 {
		t.Fatalf("first page returned %d recovery rows, want 1; %d ineligible rows sorted ahead of it", len(page.Placements), ownedRecoveryPageLimit)
	}
	if page.Placements[0].SandboxID != "z-must-recover" {
		t.Fatalf("first page returned %q, want the failover-recreate row", page.Placements[0].SandboxID)
	}
}

// Past the per-request scan budget the response is legitimately empty with a
// live cursor. The worker must follow that cursor instead of restarting the
// walk, or the rows behind it are never recovered.
func TestOwnedRecoveryWatcherFollowsEmptyPageCursor(t *testing.T) {
	c := &Cluster{fsm: newPlacementFSM()}
	seedOwnedRecoveryRows(c, "worker-self", ownedRecoveryScanBudget+ownedRecoveryPageLimit, "z-must-recover")

	first := c.OwnedRecoveryPlacements("worker-self", ownedRecoveryPageLimit, "")
	if len(first.Placements) != 0 || first.NextPageToken == "" {
		t.Fatalf("bad fixture: first page has %d rows and cursor %q; it must be the empty-page-with-cursor case",
			len(first.Placements), first.NextPageToken)
	}

	var tokens []string
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req OwnedRecoveryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		tokens = append(tokens, req.PageToken)
		_ = json.NewEncoder(w).Encode(c.OwnedRecoveryPlacements("worker-self", req.Limit, req.PageToken))
	}))
	rec := &workerRecreator{}
	agent.AttachRecreator(rec)

	// One tick is page-budgeted; the cursor carries the rest to the next one.
	for range 4 {
		agent.recreateOwnedSandboxes(context.Background())
	}

	if !slices.Contains(rec.recreated(), "z-must-recover") {
		t.Fatalf("recovered %v after four ticks; the sandbox behind the empty pages was never recreated", rec.recreated())
	}
	if len(tokens) > 1 && tokens[1] == "" {
		t.Fatal("the second request restarted the walk from the beginning instead of following the cursor")
	}
}

// The cursor is kept across ticks, but a completed walk must start over:
// otherwise a placement assigned later — after the cursor passed its key —
// would never be seen.
func TestOwnedRecoveryWatcherRestartsWalkAfterCompletion(t *testing.T) {
	c := &Cluster{fsm: newPlacementFSM()}
	seedOwnedRecoveryRows(c, "worker-self", 4, "z-first")

	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req OwnedRecoveryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		_ = json.NewEncoder(w).Encode(c.OwnedRecoveryPlacements("worker-self", req.Limit, req.PageToken))
	}))
	rec := &workerRecreator{}
	agent.AttachRecreator(rec)
	agent.recreateOwnedSandboxes(context.Background())

	if agent.ownedRecoveryCursor != "" {
		t.Fatalf("cursor = %q after a completed walk; the next tick would skip everything before it", agent.ownedRecoveryCursor)
	}

	// A placement assigned after the first sweep must be picked up.
	late := failoverRecreatePlacement("a-late", "worker-self")
	c.fsm.placements[late.SandboxID] = late
	c.fsm.claimOwnerLocked(late.SandboxID, late)
	agent.recreateOwnedSandboxes(context.Background())

	if !slices.Contains(rec.recreated(), "a-late") {
		t.Fatalf("recovered %v; a placement assigned after the walk completed was never picked up", rec.recreated())
	}
}

// placeFailoverPlacement commits a failover-recreate placement owned by
// ownerID through the real raft log, so reassignment CASes see committed state.
func placeFailoverPlacement(t *testing.T, c *Cluster, id, ownerID string) Placement {
	t.Helper()
	p := failoverRecreatePlacement(id, ownerID)
	raw, err := encodeCommand(command{
		Op: opPlace, SandboxID: p.SandboxID, OwnerNodeID: ownerID,
		OwnerAPIURL: "http://" + ownerID, IncarnationID: p.IncarnationID, Spec: p.Spec,
	})
	if err != nil {
		t.Fatalf("encodeCommand: %v", err)
	}
	if err := c.raft.raft.Apply(raw, 2*time.Second).Error(); err != nil {
		t.Fatalf("apply opPlace: %v", err)
	}
	return p
}

// The worker RPC runs on a control-plane server, so excluding "self" excludes
// the wrong node. The node to avoid is the one the placement is stuck on —
// otherwise the failing worker, which usually has the most free capacity
// precisely because its sandboxes are not running, is handed the sandbox
// straight back and the success reply clears the failure counter that asked
// for the move.
func TestReassignStuckPlacementExcludesTheFailingWorker(t *testing.T) {
	c, cleanup := newTestClusterWithRole(t, "srv-reassign-exclude", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	idx := newGossipMemberIndex()
	idx.replace([]Member{
		recreateCandidate("stuck-worker", config.NodeRoleWorker, 100),
		recreateCandidate("healthy-worker", config.NodeRoleWorker, 10),
	})
	c.gossip.setMemberIndex(idx)

	p := placeFailoverPlacement(t, c, "sb-stuck-exclude", "stuck-worker")
	if err := c.ReassignStuckPlacement(context.Background(), "stuck-worker", p.SandboxID, p.IncarnationID); err != nil {
		t.Fatalf("ReassignStuckPlacement: %v", err)
	}

	after, ok := c.fsm.get(p.SandboxID)
	if !ok {
		t.Fatal("placement disappeared")
	}
	if after.OwnerNodeID == "stuck-worker" {
		t.Fatal("the placement was reassigned to the worker it was stuck on; recovery keeps retrying the node it was meant to abandon")
	}
	if after.OwnerNodeID != "healthy-worker" {
		t.Fatalf("new owner = %q, want healthy-worker", after.OwnerNodeID)
	}
}

// With no alternative the placement stays where it is — but the caller must
// be told, or it clears the failure counter driving its escalation.
func TestReassignStuckPlacementReportsWhenNoAlternateExists(t *testing.T) {
	c, cleanup := newTestClusterWithRole(t, "srv-reassign-none", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	idx := newGossipMemberIndex()
	idx.replace([]Member{recreateCandidate("lonely-worker", config.NodeRoleWorker, 100)})
	c.gossip.setMemberIndex(idx)

	p := placeFailoverPlacement(t, c, "sb-no-alternate", "lonely-worker")
	err := c.ReassignStuckPlacement(context.Background(), "lonely-worker", p.SandboxID, p.IncarnationID)
	if !errors.Is(err, ErrNoReassignTarget) {
		t.Fatalf("reassign with no alternate = %v, want ErrNoReassignTarget", err)
	}

	after, _ := c.fsm.get(p.SandboxID)
	if after.OwnerNodeID != "lonely-worker" {
		t.Fatalf("owner = %q; a placement with no alternate must stay put rather than be orphaned", after.OwnerNodeID)
	}
}

// opReassign preserves the incarnation, so the incarnation CAS alone cannot
// fence a placement that has already been moved. A late escalation must not
// bounce a sandbox off the node that has just taken it over.
func TestReassignStuckPlacementFencesOwnerThroughTheMutation(t *testing.T) {
	c, cleanup := newTestClusterWithRole(t, "srv-reassign-fence", config.NodeRoleServer, true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	idx := newGossipMemberIndex()
	idx.replace([]Member{
		recreateCandidate("stuck-worker", config.NodeRoleWorker, 100),
		recreateCandidate("healthy-worker", config.NodeRoleWorker, 10),
	})
	c.gossip.setMemberIndex(idx)

	p := placeFailoverPlacement(t, c, "sb-already-moved", "stuck-worker")
	// The placement moves on — same incarnation, new owner — before the
	// escalation's own command reaches the FSM.
	stale := p
	moved, _ := c.fsm.get(p.SandboxID)
	moved.OwnerNodeID = "healthy-worker"
	c.fsm.mu.Lock()
	c.fsm.releaseOwnerLocked(p.SandboxID, p)
	c.fsm.placements[p.SandboxID] = moved
	c.fsm.claimOwnerLocked(p.SandboxID, moved)
	c.fsm.mu.Unlock()

	err := c.tryReassignStuckPlacement(context.Background(), stale.SandboxID, stale)
	if !errors.Is(err, ErrStuckReassignNotOwner) {
		t.Fatalf("reassign against a superseded owner = %v, want ErrStuckReassignNotOwner", err)
	}
	after, _ := c.fsm.get(p.SandboxID)
	if after.OwnerNodeID != "healthy-worker" {
		t.Fatalf("owner = %q; the stale escalation bounced the sandbox off its new home", after.OwnerNodeID)
	}
}

// A cancelled tick keeps its place instead of restarting the walk, and an
// unauthoritative answer changes nothing at all: a worker must never conclude
// "I own nothing" from a control plane it could not reach.
func TestOwnedRecoveryWatcherKeepsItsPlaceOnInterruption(t *testing.T) {
	c := &Cluster{fsm: newPlacementFSM()}
	seedOwnedRecoveryRows(c, "worker-self", ownedRecoveryScanBudget+ownedRecoveryPageLimit, "z-must-recover")

	authoritative := true
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req OwnedRecoveryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		resp := c.OwnedRecoveryPlacements("worker-self", req.Limit, req.PageToken)
		resp.Authoritative = authoritative
		_ = json.NewEncoder(w).Encode(resp)
	}))
	agent.AttachRecreator(&workerRecreator{})

	// One tick advances the cursor into the walk.
	agent.recreateOwnedSandboxes(context.Background())
	mid := agent.ownedRecoveryCursor

	// An unreachable / unauthoritative control plane must not move it.
	authoritative = false
	agent.recreateOwnedSandboxes(context.Background())
	if agent.ownedRecoveryCursor != mid {
		t.Fatalf("cursor moved from %q to %q on a non-authoritative answer", mid, agent.ownedRecoveryCursor)
	}

	// A cancelled context stops the tick where it is.
	authoritative = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	agent.recreateOwnedSandboxes(ctx)
}

// An owner query with no owner, or against a node with no FSM, answers
// nothing rather than somebody else's recovery work.
func TestOwnedRecoveryPlacementsRefusesBlankOwner(t *testing.T) {
	var none *Cluster
	if got := none.OwnedRecoveryPlacements("worker", 10, ""); got.Authoritative || len(got.Placements) != 0 {
		t.Fatalf("nil cluster answered %+v", got)
	}
	c := &Cluster{fsm: newPlacementFSM()}
	if got := c.OwnedRecoveryPlacements("  ", 10, ""); got.Authoritative || len(got.Placements) != 0 {
		t.Fatalf("blank owner answered %+v", got)
	}
	// An over-large limit is clamped rather than honored.
	seedOwnedRecoveryRows(c, "worker-self", 2, "z-ha")
	if got := c.OwnedRecoveryPlacements("worker-self", ownedRecoveryPageLimit*10, ""); len(got.Placements) != 1 {
		t.Fatalf("clamped page returned %d rows", len(got.Placements))
	}
}
