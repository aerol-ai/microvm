package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// TestAPITokenWritesGate is the rolling-upgrade gate for ops 31/32: a
// cluster with any Raft server below fv 3 answers ErrClusterVersion instead
// of committing an op that server would skip; once every server is on 3,
// writes apply. A failed server counts at its last-known version.
func TestAPITokenWritesGate(t *testing.T) {
	c, cleanup := newTestCluster(t, "tok-gate-a", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	rec := newTokenRecord(t, "ci", "payments", controlplane.RoleRunner)
	resp, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Token: rec})
	if err != nil || resp.Token.ID != rec.ID || resp.Token.Version == 0 {
		t.Fatalf("one-server cluster on this build: %+v %v", resp, err)
	}
	if got, found, fresh := c.LookupToken(rec.ID); !found || !fresh || got.Name != "ci" {
		t.Fatalf("a server reads its own FSM: %+v %v %v", got, found, fresh)
	}
	if err := c.raft.raft.AddNonvoter("tok-gate-b", "127.0.0.1:1", 0, 0).Error(); err != nil {
		t.Fatal(err)
	}
	second := newTokenRecord(t, "ci-2", "payments", controlplane.RoleRunner)
	if _, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Token: second}); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("a server unknown to gossip counts as an old build: %v", err)
	}
	index := c.gossip.currentMemberIndex()
	// fv 2 is the audit-caller release: it applies profiles, not tokens.
	index.upsert(Member{NodeID: "tok-gate-b", Alive: false, FSMOpsVersion: auditCallerFSMOpsVersion})
	if _, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Token: second}); !errors.Is(err, ErrClusterVersion) || !strings.Contains(err.Error(), "API tokens need 3") {
		t.Fatalf("a failed server on the previous release: %v", err)
	}
	// The egress-profile gate is unchanged by the bump: fv 2 still passes it.
	if err := c.egressProfileWritesAllowed(); err != nil {
		t.Fatalf("profiles need only fv 1: %v", err)
	}
	if _, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Delete: true, ID: rec.ID}); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("revoke is gated too: %v", err)
	}
	index.upsert(Member{NodeID: "tok-gate-b", Alive: false, FSMOpsVersion: fsmOpsVersion})
	if _, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Token: second}); err != nil {
		t.Fatalf("all upgraded: %v", err)
	}
	dup := newTokenRecord(t, "ci-2", "payments", controlplane.RoleViewer)
	if _, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Token: dup}); !errors.Is(err, ErrAPITokenNameTaken) {
		t.Fatalf("name taken through the leader: %v", err)
	}
	list, err := c.ListAPITokens(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %d %v", len(list), err)
	}
	if _, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Delete: true, ID: rec.ID}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, found, _ := c.LookupToken(rec.ID); found {
		t.Fatal("revocation is immediate on the server that applied it")
	}
	if changes, changed := c.APITokenChanges(0); !changed || len(changes.Changes) != 2 {
		t.Fatalf("changes = %+v", changes)
	}
	if page := c.APITokenPage("", 0); len(page.Tokens) != 1 {
		t.Fatalf("page = %+v", page)
	}

	// The leader's sweep deletes tokens 30 days past expiry, through Raft.
	n, err := c.SweepExpiredAPITokens(ctx, second.ExpiresAt.Add(time.Second))
	if err != nil || n != 1 {
		t.Fatalf("sweep = %d %v", n, err)
	}
	if list, _ := c.ListAPITokens(ctx); len(list) != 0 {
		t.Fatalf("after the sweep: %d tokens", len(list))
	}
}

// TestFollowerAPITokenWriteForward: a follower forwards one hop to the
// leader with its PAT, FSM verdicts come back as the same sentinels, and
// every transport failure is an error (never an empty success).
func TestFollowerAPITokenWriteForward(t *testing.T) {
	follower, leaderID := newEgressInmemFollower(t)
	var reply atomic.Value
	var status atomic.Int32
	var auth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		if r.URL.Path != PublicInternalAPITokenWritePath {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, reply.Load().(string))
	}))
	defer srv.Close()
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: leaderID, InternalURL: srv.URL, Alive: true})
	c := &Cluster{nodeID: "eg-raft-follower", raft: &raftNode{raft: follower}, internalClient: srv.Client(),
		patToken: "pat", gossip: &gossipNode{memberIndex: index}}
	ctx := context.Background()
	rec := newTokenRecord(t, "ci", "payments", controlplane.RoleRunner)
	stored := rec
	stored.Version = 42
	ok, _ := json.Marshal(APITokenWriteResponse{Token: stored})
	status.Store(http.StatusOK)
	reply.Store(string(ok))
	resp, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Token: rec})
	if err != nil || resp.Token.Version != 42 || auth.Load() != "Bearer pat" {
		t.Fatalf("forwarded = %+v %v (auth %v)", resp, err, auth.Load())
	}
	for _, tc := range []struct {
		code string
		want error
	}{
		{apiTokenCodeNameTaken, ErrAPITokenNameTaken},
		{apiTokenCodeIDTaken, ErrAPITokenIDTaken},
		{apiTokenCodeClusterVersion, ErrClusterVersion},
	} {
		b, _ := json.Marshal(APITokenWriteResponse{Code: tc.code, Message: "m"})
		reply.Store(string(b))
		if _, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Token: rec}); !errors.Is(err, tc.want) {
			t.Fatalf("code %s: %v", tc.code, err)
		}
	}
	b, _ := json.Marshal(APITokenWriteResponse{Code: "mystery", Message: "m"})
	reply.Store(string(b))
	if _, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Token: rec}); err == nil || !strings.Contains(err.Error(), "mystery") {
		t.Fatalf("unknown code: %v", err)
	}
	status.Store(http.StatusServiceUnavailable)
	reply.Store("not leader")
	if _, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Delete: true, ID: rec.ID}); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("leader moved: %v", err)
	}
	status.Store(http.StatusOK)
	reply.Store("{garbled")
	if _, err := c.WriteAPIToken(ctx, APITokenWriteRequest{Token: rec}); err == nil || !strings.Contains(err.Error(), "decode API token write") {
		t.Fatalf("garbled: %v", err)
	}
	if _, err := c.SweepExpiredAPITokens(ctx, time.Now()); err != nil {
		t.Fatalf("a follower's sweep is a no-op: %v", err)
	}
}

// TestAPITokenWriteOutcome: every FSM verdict survives the hop as a body
// and turns back into the same sentinel; anything else is no code.
func TestAPITokenWriteOutcome(t *testing.T) {
	for _, sentinel := range []error{ErrAPITokenNameTaken, ErrAPITokenIDTaken, ErrClusterVersion} {
		out := APITokenWriteOutcome(fmt.Errorf("wrapped: %w", sentinel))
		if out.Code == "" || !errors.Is(out.err(), sentinel) {
			t.Fatalf("%v: %+v", sentinel, out)
		}
	}
	if out := APITokenWriteOutcome(errors.New("raft timeout")); out.Code != "" || out.err() != nil {
		t.Fatalf("an unknown error carries no code: %+v", out)
	}
}

func TestAPITokensWithoutPlacementState(t *testing.T) {
	ctx := context.Background()
	for _, c := range []*Cluster{nil, {}, {raft: &raftNode{}}} {
		if _, err := c.WriteAPIToken(ctx, APITokenWriteRequest{}); err == nil {
			t.Fatal("a write without raft must fail")
		}
		if n, err := c.SweepExpiredAPITokens(ctx, time.Now()); n != 0 || err != nil {
			t.Fatal("no sweep without raft")
		}
	}
	for _, c := range []*Cluster{nil, {}} {
		if _, err := c.ListAPITokens(ctx); err == nil {
			t.Fatal("a list without an FSM must fail")
		}
		if _, found, fresh := c.LookupToken("tok_aaaaaaaaaaaa"); found || fresh {
			t.Fatal("no FSM: never fresh")
		}
		if resp, changed := c.APITokenChanges(0); !changed || !resp.Resnapshot {
			t.Fatal("no FSM: resnapshot")
		}
		if page := c.APITokenPage("", 0); len(page.Tokens) != 0 {
			t.Fatal("no FSM: empty page")
		}
	}
	var a *Agent
	if _, err := a.WriteAPIToken(ctx, APITokenWriteRequest{}); err == nil {
		t.Fatal("nil agent write")
	}
	if _, err := a.ListAPITokens(ctx); err == nil {
		t.Fatal("nil agent list")
	}
	if _, err := a.FetchTokenChanges(ctx, 0); err == nil {
		t.Fatal("nil agent poll")
	}
	// A lone follower that never heard from a leader can't forward.
	_, lone := raft.NewInmemTransport("tok-lone")
	orphan := &Cluster{nodeID: "tok-lone", raft: &raftNode{raft: newEgressInmemRaft(t, "tok-lone", lone, nil, 30*time.Second)}}
	if _, err := orphan.WriteAPIToken(ctx, APITokenWriteRequest{}); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("no leader: %v", err)
	}
}

// TestAgentAPITokenFeed drives the worker side over mTLS-shaped HTTP: the
// write goes to the server tier, a list walks pages, the mirror's poll
// turns a 304 into ErrTokensUnchanged, and a real TokenMirror syncs from it.
func TestAgentAPITokenFeed(t *testing.T) {
	l := newTokenLog(t)
	a := newTokenRecord(t, "a", "payments", controlplane.RoleRunner)
	b := newTokenRecord(t, "b", controlplane.FleetTeam, controlplane.RoleViewer)
	l.put(a)
	l.put(b)
	server := &Cluster{fsm: l.fsm}
	var lastWrite atomic.Value
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case PublicInternalAPITokenChangesPath:
			var since uint64
			fmt.Sscan(r.URL.Query().Get("since"), &since)
			resp, changed := server.APITokenChanges(since)
			if !changed {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_ = json.NewEncoder(w).Encode(resp)
		case PublicInternalAPITokenPagePath:
			var limit int
			fmt.Sscan(r.URL.Query().Get("limit"), &limit)
			_ = json.NewEncoder(w).Encode(server.APITokenPage(r.URL.Query().Get("after"), limit))
		case PublicInternalAPITokenWritePath:
			var req APITokenWriteRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			lastWrite.Store(req)
			if req.Token.Name == "taken" {
				_ = json.NewEncoder(w).Encode(APITokenWriteOutcome(ErrAPITokenNameTaken))
				return
			}
			_ = json.NewEncoder(w).Encode(APITokenWriteResponse{Token: req.Token})
		default:
			http.NotFound(w, r)
		}
	}))
	ctx := context.Background()
	if _, err := agent.FetchTokenChanges(ctx, l.idx); !errors.Is(err, identity.ErrTokensUnchanged) {
		t.Fatalf("a current cursor: %v", err)
	}
	body, err := agent.FetchTokenChanges(ctx, 0)
	if err != nil || !strings.Contains(string(body), a.ID) {
		t.Fatalf("delta = %s %v", body, err)
	}
	list, err := agent.ListAPITokens(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %v %v", list, err)
	}
	if body, err := agent.FetchTokenPage(ctx, "", 1); err != nil || !strings.Contains(string(body), `"next"`) {
		t.Fatalf("limited page = %s %v", body, err)
	}
	c := newTokenRecord(t, "c", "payments", controlplane.RoleRunner)
	if resp, err := agent.WriteAPIToken(ctx, APITokenWriteRequest{Token: c}); err != nil || resp.Token.ID != c.ID {
		t.Fatalf("write = %+v %v", resp, err)
	}
	if got := lastWrite.Load().(APITokenWriteRequest); got.Token.ID != c.ID || len(got.Token.SecretHash) != 32 {
		t.Fatalf("the server tier got %+v", got)
	}
	taken := newTokenRecord(t, "taken", "payments", controlplane.RoleRunner)
	if _, err := agent.WriteAPIToken(ctx, APITokenWriteRequest{Token: taken}); !errors.Is(err, ErrAPITokenNameTaken) {
		t.Fatalf("name taken across the agent hop: %v", err)
	}

	m := identity.NewTokenMirror(agent, identity.MirrorConfig{PageLimit: 1})
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, found, fresh := m.LookupToken(b.ID); !found || !fresh || m.Len() != 2 {
		t.Fatalf("mirror over the agent: found=%v fresh=%v len=%d", found, fresh, m.Len())
	}
	l.del(a.ID)
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := m.LookupToken(a.ID); found {
		t.Fatal("a revoke reaches the worker on the next poll")
	}
}

func TestAgentAPITokenServerErrors(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PublicInternalAPITokenPagePath && r.URL.Query().Get("after") == "" {
			_, _ = io.WriteString(w, "{garbled")
			return
		}
		http.Error(w, "disk full", http.StatusInternalServerError)
	}))
	ctx := context.Background()
	if _, err := agent.WriteAPIToken(ctx, APITokenWriteRequest{}); err == nil || !strings.Contains(err.Error(), "API token write") {
		t.Fatalf("write: %v", err)
	}
	if _, err := agent.FetchTokenChanges(ctx, 0); err == nil {
		t.Fatal("poll: want the server error")
	}
	if _, err := agent.ListAPITokens(ctx); err == nil {
		t.Fatal("list: want a decode error")
	}
	noMembers := &Agent{nodeID: "w", gossip: &gossipNode{memberIndex: newGossipMemberIndex()}}
	if _, err := noMembers.FetchTokenPage(ctx, "x", 0); err == nil {
		t.Fatal("no server tier: want an error")
	}
	if _, err := noMembers.ListAPITokens(ctx); err == nil {
		t.Fatal("no server tier: list fails")
	}
}
