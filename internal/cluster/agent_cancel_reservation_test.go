package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// agentCancelControlPlane answers an agent's cancel as a server tier whose
// follower has not applied the reservation yet: the plain lookup (any
// member, its own FSM) says 404, while the leader's authoritative read has
// the row in leader.
func agentCancelControlPlane(t *testing.T, capture *agentControlPlaneCapture, leader map[string]Placement, leaderErr int) *Agent {
	t.Helper()
	return newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, PublicInternalPlacementPath):
			http.Error(w, "no placement record", http.StatusNotFound)
			return true
		case r.Method == http.MethodPost && r.URL.Path == PublicInternalPlacementsByIDsPath:
			if r.URL.Query().Get("authoritative") != "true" {
				t.Fatalf("a cancel read the placement without asking the leader: %s", r.URL.RequestURI())
			}
			if leaderErr != 0 {
				http.Error(w, "leader trouble", leaderErr)
				return true
			}
			var req placementsByIDsRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			out := map[string]Placement{}
			for _, id := range req.IDs {
				if p, ok := leader[id]; ok {
					out[id] = p
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
			return true
		}
		return false
	}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
}

// TestAgentCancelReservationReachesLeaderWhenFollowerLags is the live
// finding on a role-separated cluster: the ingress reserves a name through
// the server tier and forwards the create to a worker (an agent), the
// worker's create fails at once (400 "image is required"), and its retract
// cancels before the follower it happened to ask has applied the
// reservation. The cancel used to read that follower, see "no such
// reservation", and propose nothing, so the name stayed held until the
// reservation expired and the corrected retry got 409 for two minutes.
func TestAgentCancelReservationReachesLeaderWhenFollowerLags(t *testing.T) {
	capture := &agentControlPlaneCapture{}
	agent := agentCancelControlPlane(t, capture, map[string]Placement{
		"sb-lag": {SandboxID: "sb-lag", OwnerNodeID: "worker-self", State: PlacementStateReserved, IncarnationID: "inc-lag"},
	}, 0)
	if err := agent.CancelReservation(context.Background(), " sb-lag "); err != nil {
		t.Fatalf("CancelReservation: %v", err)
	}
	cmds := capture.commandsSnapshot()
	if len(cmds) != 1 || cmds[0].Op != opCancelReserve || cmds[0].SandboxID != "sb-lag" || cmds[0].ExpectedIncarnationID != "inc-lag" {
		t.Fatalf("applied %+v, want one opCancelReserve for sb-lag fenced by inc-lag", cmds)
	}
}

func TestAgentCancelReservationLeaderVerdicts(t *testing.T) {
	ctx := context.Background()
	leader := map[string]Placement{
		"sb-placed": {SandboxID: "sb-placed", OwnerNodeID: "worker-self", State: PlacementStatePlaced, IncarnationID: "inc-placed"},
		"sb-no-inc": {SandboxID: "sb-no-inc", OwnerNodeID: "worker-self", State: PlacementStateReserved},
	}
	tests := []struct {
		name      string
		id        string
		leaderErr int
		wantErr   error
		wantAnErr bool
	}{
		// The leader does not have it either: nothing to cancel.
		{name: "gone everywhere", id: "sb-gone"},
		// Already promoted: a cancel never touches a sandbox.
		{name: "promoted", id: "sb-placed"},
		{name: "no incarnation to fence on", id: "sb-no-inc", wantErr: ErrIncarnationConflict},
		// The leader cannot be asked: surfaced, so the retract path logs a
		// cancel failure instead of silently leaking the name.
		{name: "leader unreachable", id: "sb-any", leaderErr: http.StatusInternalServerError, wantAnErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			capture := &agentControlPlaneCapture{}
			agent := agentCancelControlPlane(t, capture, leader, tc.leaderErr)
			err := agent.CancelReservation(ctx, tc.id)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			case tc.wantAnErr:
				if err == nil {
					t.Fatal("a failed leader read was swallowed")
				}
			case err != nil:
				t.Fatalf("err = %v, want nil", err)
			}
			if cmds := capture.commandsSnapshot(); len(cmds) != 0 {
				t.Fatalf("applied %+v, want nothing", cmds)
			}
		})
	}
}
