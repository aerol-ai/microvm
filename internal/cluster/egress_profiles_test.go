package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestAgentEgressProfileWriteKeepsSentinels: a worker's profile write goes
// to the server tier, and the FSM's refusals come back as the same
// sentinels, whatever hops they crossed.
func TestAgentEgressProfileWriteKeepsSentinels(t *testing.T) {
	var reply EgressProfileWriteResponse
	var got EgressProfileWriteRequest
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalEgressProfileWritePath {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(reply)
	}))
	ctx := context.Background()
	req := EgressProfileWriteRequest{Profile: EgressProfileRecord{Owner: "acct", Name: "python", AllowOut: []string{"pypi.org"}, HostnameCount: 1}}
	reply = EgressProfileWriteResponse{Profile: EgressProfileRecord{Owner: "acct", Name: "python", Generation: 3}, Changed: true}
	resp, err := agent.WriteEgressProfile(ctx, req)
	if err != nil || resp.Profile.Generation != 3 || got.Profile.Name != "python" {
		t.Fatalf("write = %+v %v (sent %+v)", resp, err, got)
	}
	for _, tc := range []struct {
		err  error
		want error
	}{
		{ErrEgressProfileInUse, ErrEgressProfileInUse},
		{ErrEgressProfileCapExceeded, ErrEgressProfileCapExceeded},
		{ErrClusterVersion, ErrClusterVersion},
	} {
		reply = EgressProfileWriteOutcome(tc.err)
		if _, err := agent.WriteEgressProfile(ctx, req); !errors.Is(err, tc.want) {
			t.Fatalf("%v came back as %v", tc.want, err)
		}
	}
	reply = EgressProfileWriteResponse{Code: "something_new", Message: "m"}
	if _, err := agent.WriteEgressProfile(ctx, req); err == nil {
		t.Fatal("an unknown outcome code must be an error")
	}
	if out := EgressProfileWriteOutcome(errors.New("plain")); out.Code != "" {
		t.Fatalf("a plain error has no outcome code: %+v", out)
	}
}

// TestAgentEgressProfileCache: point reads are served from the cache for
// egressProfileCacheTTL, refetched after, served stale for up to
// egressProfileCacheMaxStale while the server tier is away, and refused
// past that so the caller fails closed.
func TestAgentEgressProfileCache(t *testing.T) {
	var calls atomic.Int32
	var down atomic.Bool
	authoritative := atomic.Bool{}
	authoritative.Store(true)
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalEgressProfileReadPath {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		if down.Load() {
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		var req EgressProfileReadRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := EgressProfileReadResponse{Authoritative: authoritative.Load()}
		for _, n := range req.Names {
			if n == "python" {
				resp.Profiles = append(resp.Profiles, EgressProfileRecord{Owner: req.Owner, Name: n, Generation: 1})
			}
		}
		if len(req.Names) == 0 {
			resp.Profiles = []EgressProfileRecord{{Owner: req.Owner, Name: "listed"}}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	now := time.Unix(1_000_000, 0)
	agent.profiles.now = func() time.Time { return now }
	ctx := context.Background()
	read := func(names ...string) (EgressProfileReadResponse, error) {
		return agent.ReadEgressProfiles(ctx, EgressProfileReadRequest{Owner: "acct", Names: names})
	}
	if resp, err := read("python", "missing"); err != nil || len(resp.Profiles) != 1 || calls.Load() != 1 {
		t.Fatalf("first read = %+v %v calls=%d", resp, err, calls.Load())
	}
	if resp, _ := read("python", "missing"); len(resp.Profiles) != 1 || calls.Load() != 1 {
		t.Fatalf("a fresh read must come from the cache (absent names too): calls=%d", calls.Load())
	}
	now = now.Add(egressProfileCacheTTL)
	if _, err := read("python"); err != nil || calls.Load() != 2 {
		t.Fatalf("a stale entry must be refetched: %v calls=%d", err, calls.Load())
	}
	down.Store(true)
	now = now.Add(egressProfileCacheTTL)
	if resp, err := read("python"); err != nil || len(resp.Profiles) != 1 {
		t.Fatalf("within the stale window the last answer serves: %+v %v", resp, err)
	}
	now = now.Add(egressProfileCacheMaxStale)
	if _, err := read("python"); err == nil {
		t.Fatal("past the stale window a read must fail")
	}
	down.Store(false)
	authoritative.Store(false)
	now = now.Add(egressProfileCacheMaxStale)
	if _, err := read("python"); err == nil {
		t.Fatal("a non-authoritative answer must not be cached as truth")
	}
	authoritative.Store(true)
	if resp, err := agent.ReadEgressProfiles(ctx, EgressProfileReadRequest{Owner: "acct"}); err != nil || len(resp.Profiles) != 1 || resp.Profiles[0].Name != "listed" {
		t.Fatalf("list read = %+v %v", resp, err)
	}
	// A write through this worker forgets its cached copy.
	agent.profiles.forget(EgressProfileKey{"acct", "python"})
	before := calls.Load()
	if _, err := read("python"); err != nil || calls.Load() != before+1 {
		t.Fatalf("a forgotten entry must be refetched: %v", err)
	}
}

// TestFollowerEgressProfileWriteForwardsToLeader: a follower forwards a
// profile write one hop, over mTLS, and gets the leader's record back.
func TestFollowerEgressProfileWriteForwardsToLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires opening real raft/memberlist sockets")
	}
	leader, cleanupLeader := newTestCluster(t, "eg-leader", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PublicInternalEgressProfileWritePath, func(w http.ResponseWriter, r *http.Request) {
		var req EgressProfileWriteRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp, err := leader.WriteEgressProfile(r.Context(), req)
		if err != nil {
			if out := EgressProfileWriteOutcome(err); out.Code != "" {
				_ = json.NewEncoder(w).Encode(out)
				return
			}
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	leader.AttachInternalHandler(mux)
	follower, cleanupFollower := newTestCluster(t, "eg-follower", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, "eg-follower", 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	put := EgressProfileWriteRequest{Profile: EgressProfileRecord{Name: "python", AllowOut: []string{"pypi.org"}, HostnameCount: 1}}
	resp, err := follower.WriteEgressProfile(ctx, put)
	if err != nil || resp.Profile.Generation != 1 || !resp.Changed {
		t.Fatalf("forwarded write = %+v %v", resp, err)
	}
	// Reference it from a placement's spec; a forwarded delete is then
	// refused with the sentinel the leader's FSM raised.
	if err := leader.RecordPlacement(ctx, "sb-eg", &models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{"python"}}, PlacementSecrets{}); err != nil {
		t.Fatal(err)
	}
	if _, err := follower.WriteEgressProfile(ctx, EgressProfileWriteRequest{Delete: true, Profile: EgressProfileRecord{Name: "python"}}); !errors.Is(err, ErrEgressProfileInUse) {
		t.Fatalf("forwarded delete of a referenced profile: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		read, _ := follower.ReadEgressProfiles(ctx, EgressProfileReadRequest{Names: []string{"python"}})
		if len(read.Profiles) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the follower's FSM never saw the profile")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
