package cluster

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// TestAgentControlPlaneMovesOnFromAServerItCannotReach is the zone-loss
// case (Phase 3 drill): a server whose zone dropped off the network stays in
// the gossip list for a few seconds, and every call that tried it first
// failed. A call whose connection could not even open never reached it, so
// the next server takes it, writes included.
func TestAgentControlPlaneMovesOnFromAServerItCannotReach(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := "https://" + closed.Addr().String()
	_ = closed.Close()

	var served atomic.Int64
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}), Member{NodeID: "server-2", APIURL: gone, InternalURL: gone, Alive: true, Role: config.NodeRoleServer})
	if n := len(agent.controlPlaneMembers()); n != 2 {
		t.Fatalf("control-plane members = %d, want 2", n)
	}

	// The order is shuffled per call; 40 calls try the gone server first
	// about 20 times.
	const calls = 40
	for i := range calls {
		var out struct {
			OK bool `json:"ok"`
		}
		if err := agent.doControlPlaneJSON(context.Background(), http.MethodPost, PublicInternalApplyPath, PublicInternalApplyPath, map[string]int{"i": i}, &out); err != nil || !out.OK {
			t.Fatalf("call %d: err=%v ok=%v, want the reachable server's answer", i, err, out.OK)
		}
	}
	if got := served.Load(); got != calls {
		t.Fatalf("the reachable server answered %d calls, want %d", got, calls)
	}
}

// TestAgentControlPlaneDoesNotRetryACallThatArrived: a server that took the
// request and failed it may have applied it, so the call ends there.
func TestAgentControlPlaneDoesNotRetryACallThatArrived(t *testing.T) {
	var first atomic.Int64
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.Add(1)
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	err := agent.doControlPlaneJSON(context.Background(), http.MethodPost, PublicInternalApplyPath, PublicInternalApplyPath, map[string]int{"i": 1}, nil)
	if err == nil || neverReachedPeer(err) {
		t.Fatalf("err = %v, want a final error from a server that took the call", err)
	}
	if got := first.Load(); got != 1 {
		t.Fatalf("server saw the call %d times, want 1", got)
	}
}
