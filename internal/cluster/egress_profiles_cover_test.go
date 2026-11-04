package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/pkg/models"
)

// newEgressInmemRaft starts one in-memory raft server (no sockets). servers
// is the bootstrap configuration; nil leaves it unbootstrapped, which is a
// follower that never learns a leader.
func newEgressInmemRaft(t *testing.T, id string, trans *raft.InmemTransport, servers []raft.Server, heartbeat time.Duration) *raft.Raft {
	t.Helper()
	conf := raft.DefaultConfig()
	conf.LocalID = raft.ServerID(id)
	conf.HeartbeatTimeout = heartbeat
	conf.ElectionTimeout = heartbeat
	conf.LeaderLeaseTimeout = heartbeat
	conf.CommitTimeout = 5 * time.Millisecond
	conf.LogOutput = io.Discard
	logs, snaps := raft.NewInmemStore(), raft.NewInmemSnapshotStore()
	if servers != nil {
		if err := raft.BootstrapCluster(conf, logs, logs, snaps, trans, raft.Configuration{Servers: servers}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := raft.NewRaft(conf, newPlacementFSM(), logs, logs, snaps, trans)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Shutdown().Error() })
	return r
}

// newEgressInmemFollower returns a raft follower that knows its leader's ID.
// The follower is a nonvoter with a long heartbeat timeout, so it never
// campaigns or forgets the leader mid-test, and the leader is the only voter,
// so its leadership never lapses.
func newEgressInmemFollower(t *testing.T) (*raft.Raft, string) {
	t.Helper()
	const leaderID, followerID = "eg-raft-leader", "eg-raft-follower"
	_, lt := raft.NewInmemTransport(leaderID)
	_, ft := raft.NewInmemTransport(followerID)
	lt.Connect(followerID, ft)
	ft.Connect(leaderID, lt)
	servers := []raft.Server{
		{ID: leaderID, Address: leaderID, Suffrage: raft.Voter},
		{ID: followerID, Address: followerID, Suffrage: raft.Nonvoter},
	}
	newEgressInmemRaft(t, leaderID, lt, servers, 100*time.Millisecond)
	follower := newEgressInmemRaft(t, followerID, ft, servers, 30*time.Second)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, id := follower.LeaderWithID(); string(id) == leaderID {
			return follower, leaderID
		}
		if time.Now().After(deadline) {
			t.Fatal("the in-memory follower never learned its leader")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestFollowerEgressProfileWriteForwardErrors: every way the one-hop forward
// to the leader can fail comes back as an error the API maps, never as an
// empty success, and a leader's 503 stays ErrNotLeader so the caller retries.
func TestFollowerEgressProfileWriteForwardErrors(t *testing.T) {
	follower, leaderID := newEgressInmemFollower(t)
	var status atomic.Int32
	var body atomic.Value
	var auth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		if r.URL.Path != PublicInternalEgressProfileWritePath {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer srv.Close()
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()

	newFollower := func(internalURL string) *Cluster {
		index := newGossipMemberIndex()
		if internalURL != "" {
			index.upsert(Member{NodeID: leaderID, InternalURL: internalURL, Alive: true})
		}
		return &Cluster{nodeID: "eg-raft-follower", raft: &raftNode{raft: follower}, internalClient: srv.Client(),
			patToken: "pat", gossip: &gossipNode{memberIndex: index}}
	}
	ctx := context.Background()
	req := EgressProfileWriteRequest{Profile: EgressProfileRecord{Owner: "acct", Name: "python", AllowOut: []string{"pypi.org"}, HostnameCount: 1}}

	ok, _ := json.Marshal(EgressProfileWriteResponse{Profile: EgressProfileRecord{Owner: "acct", Name: "python", Generation: 4}, Changed: true})
	status.Store(http.StatusOK)
	body.Store(string(ok))
	resp, err := newFollower(srv.URL).WriteEgressProfile(ctx, req)
	if err != nil || resp.Profile.Generation != 4 || auth.Load() != "Bearer pat" {
		t.Fatalf("forwarded write = %+v %v (auth %q)", resp, err, auth.Load())
	}

	for _, tc := range []struct {
		name     string
		internal string
		status   int
		body     string
		want     error
		contains string
	}{
		{name: "leader not in gossip", want: ErrPeerInternalURLRequired},
		{name: "unparsable leader url", internal: "http://bad host", contains: "build egress profile write"},
		{name: "leader unreachable", internal: closedURL, contains: "egress profile write"},
		{name: "leader stepped down", internal: srv.URL, status: http.StatusServiceUnavailable, body: "not leader", want: ErrNotLeader},
		{name: "leader refused", internal: srv.URL, status: http.StatusInternalServerError, body: " boom \n", contains: "status 500: boom"},
		{name: "garbled reply", internal: srv.URL, status: http.StatusOK, body: "{not json", contains: "decode egress profile write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status.Store(int32(tc.status))
			body.Store(tc.body)
			_, err := newFollower(tc.internal).WriteEgressProfile(ctx, req)
			if err == nil {
				t.Fatal("want an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.contains != "" && !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.contains)
			}
		})
	}

	noClient := newFollower(srv.URL)
	noClient.internalClient = nil
	if _, err := noClient.WriteEgressProfile(ctx, req); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("no internal client: %v", err)
	}

	// A follower that has never heard from a leader can't forward anywhere.
	_, lone := raft.NewInmemTransport("eg-raft-lone")
	orphan := &Cluster{nodeID: "eg-raft-lone", raft: &raftNode{raft: newEgressInmemRaft(t, "eg-raft-lone", lone, nil, 30*time.Second)}}
	if _, err := orphan.WriteEgressProfile(ctx, req); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("no leader: %v", err)
	}
}

// TestEgressProfilesWithoutPlacementState: a node or agent that holds no
// placement state refuses profile reads and writes instead of answering from
// nothing.
func TestEgressProfilesWithoutPlacementState(t *testing.T) {
	ctx := context.Background()
	for _, c := range []*Cluster{nil, {}, {raft: &raftNode{}}} {
		if _, err := c.WriteEgressProfile(ctx, EgressProfileWriteRequest{}); err == nil {
			t.Fatal("a write without raft must fail")
		}
	}
	for _, c := range []*Cluster{nil, {}} {
		if _, err := c.ReadEgressProfiles(ctx, EgressProfileReadRequest{}); err == nil {
			t.Fatal("a read without an FSM must fail")
		}
	}
	var a *Agent
	if _, err := a.WriteEgressProfile(ctx, EgressProfileWriteRequest{}); err == nil {
		t.Fatal("a nil agent write must fail")
	}
	if _, err := a.ReadEgressProfiles(ctx, EgressProfileReadRequest{}); err == nil {
		t.Fatal("a nil agent read must fail")
	}
}

// TestClusterReadEgressProfilesPage: a read with no names pages the owner's
// profiles by name from this server's FSM.
func TestClusterReadEgressProfilesPage(t *testing.T) {
	l := newProfileLog(t)
	l.put("acct", "python", 1, "pypi.org")
	l.put("acct", "go", 1, "proxy.golang.org")
	l.put("other", "node", 1, "registry.npmjs.org")
	c := &Cluster{fsm: l.fsm}
	resp, err := c.ReadEgressProfiles(context.Background(), EgressProfileReadRequest{Owner: "acct", Limit: 1})
	if err != nil || !resp.Authoritative || len(resp.Profiles) != 1 || resp.Profiles[0].Name != "go" {
		t.Fatalf("first page = %+v %v", resp, err)
	}
	resp, _ = c.ReadEgressProfiles(context.Background(), EgressProfileReadRequest{Owner: "acct", After: "go"})
	if len(resp.Profiles) != 1 || resp.Profiles[0].Name != "python" {
		t.Fatalf("next page = %+v", resp)
	}
}

// TestAgentEgressProfileWriteServerError: a server-tier failure is the
// write's error, and the agent's real clock drives the point-read cache.
func TestAgentEgressProfileWriteServerError(t *testing.T) {
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PublicInternalEgressProfileReadPath {
			_ = json.NewEncoder(w).Encode(EgressProfileReadResponse{Authoritative: true, Profiles: []EgressProfileRecord{{Owner: "acct", Name: "python"}}})
			return
		}
		http.Error(w, "disk full", http.StatusInternalServerError)
	}))
	ctx := context.Background()
	if _, err := agent.WriteEgressProfile(ctx, EgressProfileWriteRequest{Profile: EgressProfileRecord{Owner: "acct", Name: "python"}}); err == nil || !strings.Contains(err.Error(), "write egress profile") {
		t.Fatalf("server error: %v", err)
	}
	resp, err := agent.ReadEgressProfiles(ctx, EgressProfileReadRequest{Owner: "acct", Names: []string{"python"}})
	if err != nil || len(resp.Profiles) != 1 {
		t.Fatalf("read = %+v %v", resp, err)
	}
	if e, ok := agent.profiles.entries[EgressProfileKey{"acct", "python"}]; !ok || time.Since(e.at) > time.Minute {
		t.Fatalf("cache entry = %+v %v", e, ok)
	}
}

// TestFSMEgressProfileCapSkipsUnplacedRefs: a reference to a sandbox with no
// hot row (only reachable if the index and the rows ever disagree) neither
// panics nor counts toward the cap.
func TestFSMEgressProfileCapSkipsUnplacedRefs(t *testing.T) {
	l := newProfileLog(t)
	l.put("acct", "python", 1, "pypi.org")
	l.place("sb-1", "acct", &models.CreateSandboxRequest{EgressProfiles: []string{"python"}})
	key := EgressProfileKey{"acct", "python"}
	l.fsm.mu.Lock()
	l.fsm.egressProfileRefs[key]["sb-ghost"] = struct{}{}
	over := l.fsm.egressProfileCapOverLocked(key, 1)
	l.fsm.mu.Unlock()
	if len(over) != 0 {
		t.Fatalf("over = %v", over)
	}
}

// TestFSMEgressProfileSnapshotOrder: the snapshot lists profiles by owner,
// then name, so every replica persists byte-identical snapshots.
func TestFSMEgressProfileSnapshotOrder(t *testing.T) {
	l := newProfileLog(t)
	l.put("zeta", "a", 1, "a.example.com")
	l.put("acct", "b", 1, "b.example.com")
	l.put("acct", "a", 1, "c.example.com")
	l.put("mid", "z", 1, "d.example.com")
	l.fsm.mu.RLock()
	got := l.fsm.egressProfilesSnapshotLocked()
	l.fsm.mu.RUnlock()
	var keys []string
	for _, r := range got {
		keys = append(keys, r.Owner+"/"+r.Name)
	}
	if strings.Join(keys, ",") != "acct/a,acct/b,mid/z,zeta/a" {
		t.Fatalf("snapshot order = %v", keys)
	}
}
