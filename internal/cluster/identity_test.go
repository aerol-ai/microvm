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

	"github.com/aerol-ai/microvm/internal/cloudidentity"
)

// TestIdentityGateMixedVersions: no node accepts an identity create while
// any live member advertises a build older than identityFSMOpsVersion; an
// older worker would drop the option.
func TestIdentityGateMixedVersions(t *testing.T) {
	index := newGossipMemberIndex()
	index.replace([]Member{{NodeID: "self", Alive: true, FSMOpsVersion: fsmOpsVersion}})
	g := &gossipNode{memberIndex: index, bootstrapPeers: []string{"10.0.0.2:7946"}}
	c, a := &Cluster{gossip: g}, &Agent{gossip: g}
	for _, step := range []struct {
		name   string
		member Member
		want   bool
	}{
		{"an upgraded server", Member{NodeID: "srv-b", Alive: true, FSMOpsVersion: identityFSMOpsVersion}, true},
		{"a worker on the release before identity", Member{NodeID: "wrk-c", Alive: true, Role: "worker", FSMOpsVersion: identityFSMOpsVersion - 1}, false},
		{"it upgrades", Member{NodeID: "wrk-c", Alive: true, Role: "worker", FSMOpsVersion: identityFSMOpsVersion}, true},
		{"a dead old member does not hold it", Member{NodeID: "old", Alive: false, FSMOpsVersion: 1}, true},
	} {
		index.upsert(step.member)
		if got := c.IdentityAllowed(); got != step.want {
			t.Fatalf("%s: Cluster gate = %v", step.name, got)
		}
		if got := a.IdentityAllowed(); got != step.want {
			t.Fatalf("%s: Agent gate = %v", step.name, got)
		}
	}
	var nc *Cluster
	var na *Agent
	if nc.IdentityAllowed() || na.IdentityAllowed() {
		t.Fatal("a nil client opened the gate")
	}
}

// TestIdentityWritesGate: a real one-server cluster takes identity writes;
// an unknown (old) Raft server closes the gate with ErrClusterVersion.
func TestIdentityWritesGate(t *testing.T) {
	c, cleanup := newTestCluster(t, "id-gate-a", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	now := time.Now()
	resp, err := c.WriteIdentity(ctx, IdentityWriteRequest{Keys: &IdentityKeysWrite{Keys: []cloudidentity.KeyRecord{identityKeyRec(t, 0, now)}}})
	if err != nil || resp.Keys == nil || resp.Keys.Generation != 1 || !resp.Changed {
		t.Fatalf("first key = %+v %v", resp, err)
	}
	if _, err := c.WriteIdentity(ctx, IdentityWriteRequest{Keys: &IdentityKeysWrite{Keys: []cloudidentity.KeyRecord{identityKeyRec(t, 1, now)}}}); !errors.Is(err, ErrIdentityKeysConflict) {
		t.Fatalf("a second first key = %v", err)
	}
	role, err := c.WriteIdentity(ctx, IdentityWriteRequest{Role: &IdentityRoleRecord{Owner: "team:p", Tag: "deploy", MinRole: "runner"}})
	if err != nil || role.Role == nil || !role.Changed || role.Role.CreatedUnixNano == 0 {
		t.Fatalf("role put = %+v %v", role, err)
	}
	if _, err := c.WriteIdentity(ctx, IdentityWriteRequest{Role: &IdentityRoleRecord{Owner: "team:p", Tag: "deploy", MinRole: "viewer"}}); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("bad min role = %v", err)
	}
	read, err := c.ReadIdentity(ctx, IdentityReadRequest{Keys: true, Owner: "team:p", Tags: []string{"deploy", "missing"}})
	if err != nil || !read.Authoritative || read.Keys == nil || read.Keys.Generation != 1 || len(read.Roles) != 1 {
		t.Fatalf("read = %+v %v", read, err)
	}
	if page, _ := c.ReadIdentity(ctx, IdentityReadRequest{Owner: "team:p", RolePage: true}); len(page.Roles) != 1 || page.Keys != nil {
		t.Fatalf("page = %+v", page)
	}
	if _, err := c.WriteIdentity(ctx, IdentityWriteRequest{Role: &IdentityRoleRecord{Owner: "team:p", Tag: "deploy"}, DeleteRole: true}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.WriteIdentity(ctx, IdentityWriteRequest{}); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("empty write = %v", err)
	}
	if err := c.raft.raft.AddNonvoter("id-gate-b", "127.0.0.1:1", 0, 0).Error(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteIdentity(ctx, IdentityWriteRequest{Role: &IdentityRoleRecord{Owner: "team:p", Tag: "deploy", MinRole: "runner"}}); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("an old server in the configuration = %v", err)
	}
	c.gossip.currentMemberIndex().upsert(Member{NodeID: "id-gate-b", Alive: false, FSMOpsVersion: identityFSMOpsVersion - 1})
	if _, err := c.WriteIdentity(ctx, IdentityWriteRequest{Role: &IdentityRoleRecord{Owner: "team:p", Tag: "deploy", MinRole: "runner"}}); !errors.Is(err, ErrClusterVersion) {
		t.Fatalf("a failed server on the release before = %v", err)
	}
}

// TestFollowerIdentityWriteForwardsToLeader: a follower forwards one hop
// and the leader's FSM refusal comes back as the same sentinel.
func TestFollowerIdentityWriteForwardsToLeader(t *testing.T) {
	follower, leaderID := newEgressInmemFollower(t)
	var reply atomic.Value
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalIdentityWritePath {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		got.Store(string(body))
		_, _ = io.WriteString(w, reply.Load().(string))
	}))
	defer srv.Close()
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: leaderID, InternalURL: srv.URL, Alive: true})
	c := &Cluster{nodeID: "eg-raft-follower", raft: &raftNode{raft: follower}, internalClient: srv.Client(),
		patToken: "pat", gossip: &gossipNode{memberIndex: index}}
	ok, _ := json.Marshal(IdentityWriteResponse{Role: &IdentityRoleRecord{Owner: "o", Tag: "t", MinRole: "runner"}, Changed: true})
	reply.Store(string(ok))
	ctx := context.Background()
	req := IdentityWriteRequest{Role: &IdentityRoleRecord{Owner: "o", Tag: "t", MinRole: "runner"}}
	resp, err := c.WriteIdentity(ctx, req)
	if err != nil || resp.Role == nil || !resp.Changed || !strings.Contains(got.Load().(string), `"tag":"t"`) {
		t.Fatalf("forwarded = %+v %v (sent %v)", resp, err, got.Load())
	}
	for _, sentinel := range []error{ErrIdentityKeysConflict, ErrIdentityInvalid, ErrClusterVersion} {
		out, _ := json.Marshal(IdentityWriteOutcome(sentinel))
		reply.Store(string(out))
		if _, err := c.WriteIdentity(ctx, req); !errors.Is(err, sentinel) {
			t.Fatalf("%v came back as %v", sentinel, err)
		}
	}
	reply.Store(`{"code":"brand_new","message":"m"}`)
	if _, err := c.WriteIdentity(ctx, req); err == nil {
		t.Fatal("an unknown code must be an error")
	}
	reply.Store(`{not json`)
	if _, err := c.WriteIdentity(ctx, req); err == nil {
		t.Fatal("a garbled reply must be an error")
	}
	if out := IdentityWriteOutcome(errors.New("plain")); out.Code != "" {
		t.Fatalf("a plain error has no code: %+v", out)
	}
}

func TestIdentityWithoutPlacementState(t *testing.T) {
	ctx := context.Background()
	for _, c := range []*Cluster{nil, {}, {raft: &raftNode{}}} {
		if _, err := c.WriteIdentity(ctx, IdentityWriteRequest{}); err == nil {
			t.Fatal("a write without raft must fail")
		}
	}
	for _, c := range []*Cluster{nil, {}} {
		if _, err := c.ReadIdentity(ctx, IdentityReadRequest{}); err == nil {
			t.Fatal("a read without an FSM must fail")
		}
	}
	var a *Agent
	if _, err := a.WriteIdentity(ctx, IdentityWriteRequest{}); err == nil {
		t.Fatal("a nil agent write must fail")
	}
	if _, err := a.ReadIdentity(ctx, IdentityReadRequest{}); err == nil {
		t.Fatal("a nil agent read must fail")
	}
}

// TestAgentIdentity: a worker writes and reads through the server tier; its
// point role reads come from a cache refreshed every identityRoleCacheTTL,
// served stale for up to identityRoleCacheMaxStale while the server tier is
// away, and refused past that so the create check fails closed.
func TestAgentIdentity(t *testing.T) {
	var calls atomic.Int32
	var down, notAuthoritative atomic.Bool
	var writeReply atomic.Value
	writeReply.Store(`{"changed":true,"role":{"owner":"team:p","tag":"deploy","min_role":"runner"}}`)
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case PublicInternalIdentityWritePath:
			_, _ = io.WriteString(w, writeReply.Load().(string))
		case PublicInternalIdentityReadPath:
			calls.Add(1)
			if down.Load() {
				http.Error(w, "no", http.StatusInternalServerError)
				return
			}
			var req IdentityReadRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			resp := IdentityReadResponse{Authoritative: !notAuthoritative.Load()}
			for _, tag := range req.Tags {
				if tag == "deploy" {
					resp.Roles = append(resp.Roles, IdentityRoleRecord{Owner: req.Owner, Tag: tag, MinRole: "runner"})
				}
			}
			if req.Keys {
				resp.Keys = &cloudidentity.KeySet{Generation: 7}
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	now := time.Unix(1_000_000, 0)
	agent.identityRoles.now = func() time.Time { return now }
	ctx := context.Background()
	read := func(tags ...string) (IdentityReadResponse, error) {
		return agent.ReadIdentity(ctx, IdentityReadRequest{Owner: "team:p", Tags: tags})
	}
	if resp, err := read("deploy", "missing"); err != nil || len(resp.Roles) != 1 || calls.Load() != 1 {
		t.Fatalf("first read = %+v %v calls=%d", resp, err, calls.Load())
	}
	if resp, _ := read("deploy", "missing"); len(resp.Roles) != 1 || calls.Load() != 1 {
		t.Fatalf("a fresh read must come from the cache: calls=%d", calls.Load())
	}
	now = now.Add(identityRoleCacheTTL)
	if _, err := read("deploy"); err != nil || calls.Load() != 2 {
		t.Fatalf("a stale entry must be refetched: %v calls=%d", err, calls.Load())
	}
	down.Store(true)
	now = now.Add(identityRoleCacheTTL)
	if resp, err := read("deploy"); err != nil || len(resp.Roles) != 1 {
		t.Fatalf("within the stale window: %+v %v", resp, err)
	}
	now = now.Add(identityRoleCacheMaxStale)
	if _, err := read("deploy"); err == nil {
		t.Fatal("past the stale window a read must fail")
	}
	down.Store(false)
	notAuthoritative.Store(true)
	if _, err := agent.ReadIdentity(ctx, IdentityReadRequest{Keys: true}); err == nil {
		t.Fatal("a non-authoritative answer must be refused")
	}
	notAuthoritative.Store(false)
	keys, err := agent.ReadIdentity(ctx, IdentityReadRequest{Keys: true})
	if err != nil || keys.Keys == nil || keys.Keys.Generation != 7 {
		t.Fatalf("key read = %+v %v", keys, err)
	}
	// A write through this worker forgets its cached copy of the tag.
	before := calls.Load()
	if resp, err := agent.WriteIdentity(ctx, IdentityWriteRequest{Role: &IdentityRoleRecord{Owner: "team:p", Tag: "deploy", MinRole: "admin"}}); err != nil || !resp.Changed {
		t.Fatalf("write = %+v %v", resp, err)
	}
	if _, err := read("deploy"); err != nil || calls.Load() != before+1 {
		t.Fatalf("a written tag must be refetched: %v", err)
	}
	out, _ := json.Marshal(IdentityWriteOutcome(ErrIdentityKeysConflict))
	writeReply.Store(string(out))
	if _, err := agent.WriteIdentity(ctx, IdentityWriteRequest{Keys: &IdentityKeysWrite{}}); !errors.Is(err, ErrIdentityKeysConflict) {
		t.Fatalf("conflict came back as %v", err)
	}
	writeReply.Store(`{bad`)
	if _, err := agent.WriteIdentity(ctx, IdentityWriteRequest{Keys: &IdentityKeysWrite{}}); err == nil {
		t.Fatal("a garbled write reply must be an error")
	}
	// The real clock drives the cache when no test clock is set.
	var fresh identityRoleCache
	if fresh.clock().IsZero() {
		t.Fatal("no clock")
	}
}

// TestIdentityRoleCacheIsBounded: made-up tags cannot grow a worker's role
// cache past identityRoleCacheMax. Entries past the stale window go first;
// when every entry is still live a new tag is answered but not kept.
func TestIdentityRoleCacheIsBounded(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := &identityRoleCache{now: func() time.Time { return now }}
	fetches := 0
	fetch := func(_ context.Context, req IdentityReadRequest) (IdentityReadResponse, error) {
		fetches++
		resp := IdentityReadResponse{Authoritative: true}
		for _, tag := range req.Tags {
			if tag == "deploy" {
				resp.Roles = append(resp.Roles, IdentityRoleRecord{Owner: req.Owner, Tag: tag})
			}
		}
		return resp, nil
	}
	ctx := context.Background()
	read := func(tags ...string) IdentityReadResponse {
		t.Helper()
		resp, err := c.read(ctx, IdentityReadRequest{Owner: "team:p", Tags: tags}, fetch)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	for i := 0; i < identityRoleCacheMax; i++ {
		read(fmt.Sprintf("made-up-%d", i))
	}
	if len(c.entries) != identityRoleCacheMax {
		t.Fatalf("entries = %d, want the cap", len(c.entries))
	}
	// Full of live entries: answered, not kept, and fetched again.
	before := fetches
	if resp := read("deploy"); len(resp.Roles) != 1 {
		t.Fatalf("a tag past the cap was not answered: %+v", resp)
	}
	read("deploy")
	if len(c.entries) != identityRoleCacheMax || fetches != before+2 {
		t.Fatalf("entries = %d fetches = %d, want the cap and two fetches", len(c.entries), fetches-before)
	}
	// Once the old entries are past the stale window they make room.
	now = now.Add(identityRoleCacheMaxStale)
	read("deploy")
	if len(c.entries) != 1 {
		t.Fatalf("entries = %d after the sweep, want only the new one", len(c.entries))
	}
	before = fetches
	if resp := read("deploy"); len(resp.Roles) != 1 || fetches != before {
		t.Fatalf("the kept entry was not served from the cache: %+v fetches %d", resp, fetches-before)
	}
}
