package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
