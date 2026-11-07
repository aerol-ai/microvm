package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

type fakeGuardAPI struct {
	members []cluster.Member
	// voters is raft_voters; nil sends the voters the members' flags name,
	// as a daemon with the field does.
	voters []string
	// legacy leaves raft_voters out, as a daemon from before the field.
	legacy      bool
	membersErr  error
	transfer    upgradewire.LeaderTransferResponse
	transferErr error
	transfers   int
}

func (f *fakeGuardAPI) Members(context.Context) (memberList, error) {
	if f.membersErr != nil || f.legacy {
		return memberList{Members: f.members}, f.membersErr
	}
	voters := f.voters
	if voters == nil {
		voters = []string{}
		for _, m := range f.members {
			if m.Voter {
				voters = append(voters, m.NodeID)
			}
		}
	}
	return memberList{Members: f.members, RaftVoters: voters}, nil
}

func (f *fakeGuardAPI) TransferLeadership(context.Context) (upgradewire.LeaderTransferResponse, error) {
	f.transfers++
	return f.transfer, f.transferErr
}

func srv(id string, alive, leader bool) cluster.Member {
	return cluster.Member{NodeID: id, Alive: alive, Voter: true, Leader: leader}
}

func TestGuardServerStop(t *testing.T) {
	worker := cluster.Member{NodeID: "w1", Alive: true}
	cases := []struct {
		name          string
		self          string
		api           fakeGuardAPI
		allow         bool
		wantErr       string
		wantTransfers int
		wantOut       string
	}{
		{name: "three servers up, follower: goes on", self: "s2",
			api: fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", true, false), worker}}},
		{name: "a worker never checks quorum", self: "w1",
			api: fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", false, false), srv("s3", false, false), worker}}},
		{name: "one of three down: stopping a second loses quorum", self: "s2",
			api:     fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", false, false)}},
			wantErr: "leaves 1 of 3 voting servers up, and Raft needs 2; these servers are down: s3"},
		{name: "one of three down with --allow-downtime: warns and goes on", self: "s2", allow: true,
			api:     fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", false, false)}},
			wantOut: "going on because --allow-downtime"},
		{name: "one voter only warns (install.sh re-run on a one-server cluster)", self: "s1",
			api:     fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), worker}},
			wantOut: "s1 is the only voting server"},
		{name: "two voters, one down: refuses", self: "s1",
			api:     fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", false, false)}},
			wantErr: "leaves 0 of 2 voting servers up"},
		{name: "one voter with --allow-downtime: no hand-off to try", self: "s1", allow: true,
			api: fakeGuardAPI{members: []cluster.Member{srv("s1", true, true)}}},
		{name: "the leader hands off first", self: "s1",
			api:           fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", true, false)}, transfer: upgradewire.LeaderTransferResponse{Leader: "s3", Term: 7}},
			wantTransfers: 1, wantOut: "handed leadership to s3 (term 7)"},
		{name: "a failed hand-off refuses", self: "s1",
			api:           fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", true, false)}, transferErr: errors.New("boom")},
			wantTransfers: 1, wantErr: "handing leadership to another server failed"},
		{name: "a failed hand-off with --allow-downtime warns", self: "s1", allow: true,
			api:           fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", true, false)}, transferErr: errors.New("boom")},
			wantTransfers: 1, wantOut: "could not hand off leadership"},
		{name: "still leading after the hand-off refuses", self: "s1",
			api:           fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", true, false)}, transfer: upgradewire.LeaderTransferResponse{Leader: "s1"}},
			wantTransfers: 1, wantErr: "still leads after the hand-off"},
		{name: "still leading with --allow-downtime goes on", self: "s1", allow: true,
			api:           fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", true, false)}, transfer: upgradewire.LeaderTransferResponse{Leader: "s1"}},
			wantTransfers: 1},
		{name: "members unreadable refuses", self: "s1",
			api:     fakeGuardAPI{membersErr: errors.New("connection refused")},
			wantErr: "quorum cannot be checked"},
		{name: "members unreadable with --allow-downtime warns", self: "s1", allow: true,
			api:     fakeGuardAPI{membersErr: errors.New("connection refused")},
			wantOut: "could not check quorum"},
		{name: "this node not listed refuses", self: "s9",
			api:     fakeGuardAPI{members: []cluster.Member{srv("s1", true, true)}},
			wantErr: `node "s9" is not in the local member list`},
		{name: "this node not listed with --allow-downtime goes on", self: "s9", allow: true,
			api: fakeGuardAPI{members: []cluster.Member{srv("s1", true, true)}}},
		// J2: gossip forgot two dead voters of five. The member list shows
		// 3 of 3 up; the Raft configuration still has 5, so stopping one
		// leaves 2 of 5 and is refused.
		{name: "voters gossip forgot still count", self: "s2",
			api: fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", true, false), worker},
				voters: []string{"s1", "s2", "s3", "s4", "s5"}},
			wantErr: "leaves 2 of 5 voting servers up, and Raft needs 3; these servers are down: s4, s5"},
		{name: "voters gossip forgot, with --allow-downtime: warns", self: "s2", allow: true,
			api: fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", true, false)},
				voters: []string{"s1", "s2", "s3", "s4", "s5"}},
			wantOut: "leaves 2 of 5 voting servers up"},
		{name: "five voters, one forgotten: a stop keeps quorum", self: "s3",
			api: fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", true, false), srv("s4", true, false)},
				voters: []string{"s1", "s2", "s3", "s4", "s5"}}},
		{name: "the Raft configuration decides who votes, not a stale flag", self: "s2",
			api: fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), {NodeID: "s2", Alive: true}, srv("s3", false, false)},
				voters: []string{"s1", "s2", "s3"}},
			wantErr: "leaves 1 of 3 voting servers up"},
		{name: "a node the Raft configuration does not list as a voter goes on", self: "s3",
			api: fakeGuardAPI{members: []cluster.Member{srv("s1", true, true), srv("s2", false, false), srv("s3", true, false)},
				voters: []string{"s1", "s2"}}},
		{name: "this node missing from gossip but voting still counts", self: "s2",
			api:     fakeGuardAPI{members: []cluster.Member{srv("s1", true, true)}, voters: []string{"s1", "s2", "s3"}},
			wantErr: "leaves 1 of 3 voting servers up, and Raft needs 2; these servers are down: s3"},
		{name: "an older daemon without raft_voters: gossip count with a warning", self: "s2",
			api:     fakeGuardAPI{legacy: true, members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", true, false)}},
			wantOut: "does not list the Raft voters"},
		{name: "an older daemon without raft_voters still refuses what it can see", self: "s2",
			api:     fakeGuardAPI{legacy: true, members: []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", false, false)}},
			wantErr: "leaves 1 of 3 voting servers up"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			api := tc.api
			err := guardServerStop(context.Background(), stopGuardEnv{cluster: true, nodeID: tc.self}, &api, tc.allow, &out)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("err = %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if api.transfers != tc.wantTransfers {
				t.Fatalf("transfers = %d, want %d", api.transfers, tc.wantTransfers)
			}
			if tc.wantOut != "" && !strings.Contains(out.String(), tc.wantOut) {
				t.Fatalf("out = %q, want %q", out.String(), tc.wantOut)
			}
		})
	}
}

func TestReadStopGuardEnv(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "sandboxd.env")
	os.WriteFile(envFile, []byte("SB_PAT_TOKEN=pat-1\nSB_API_PORT=9999\nSB_API_HOST=0.0.0.0\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "cluster.env"), []byte("SB_ENABLE_CLUSTER=true\nSB_NODE_ID=s2\nSB_API_HOST=10.0.0.5\n"), 0o600)
	e := readStopGuardEnv(envFile)
	if !e.cluster || e.nodeID != "s2" || e.pat != "pat-1" || e.apiURL != "http://10.0.0.5:9999" {
		t.Fatalf("env = %+v", e)
	}
	// No files: off cluster mode, default local API.
	e = readStopGuardEnv(filepath.Join(t.TempDir(), "sandboxd.env"))
	if e.cluster || e.apiURL != "http://127.0.0.1:21212" {
		t.Fatalf("defaults = %+v", e)
	}
	// The hook is a no-op off cluster mode: it never builds a client.
	old := newStopGuardAPI
	newStopGuardAPI = func(stopGuardEnv) stopGuardAPI { t.Fatal("client built off cluster mode"); return nil }
	defer func() { newStopGuardAPI = old }()
	if err := serverStopGuard(nodeupgrade.Paths{EnvFile: filepath.Join(t.TempDir(), "sandboxd.env")}, &bytes.Buffer{})(context.Background(), false); err != nil {
		t.Fatal(err)
	}
}

// The hook on a cluster node uses the local API client, which sends the
// node's PAT and reads the members and hand-off routes.
func TestServerStopGuardAgainstTheLocalAPI(t *testing.T) {
	var gotAuth []string
	voters := []string{"s1", "s2", "s3"}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/cluster/members":
			json.NewEncoder(w).Encode(map[string]any{"members": []cluster.Member{srv("s1", true, true), srv("s2", true, false), srv("s3", true, false)},
				"raft_voters": voters})
		case r.Method == http.MethodPost && r.URL.Path == upgradewire.ClusterLeaderTransferPath:
			var req upgradewire.LeaderTransferRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(upgradewire.LeaderTransferResponse{Leader: "s2", Term: 3})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	old := newStopGuardAPI
	newStopGuardAPI = func(e stopGuardEnv) stopGuardAPI {
		return &localAPI{base: ts.URL, pat: e.pat, http: ts.Client()}
	}
	defer func() { newStopGuardAPI = old }()
	dir := t.TempDir()
	envFile := filepath.Join(dir, "sandboxd.env")
	os.WriteFile(envFile, []byte("SB_PAT_TOKEN=pat-9\nSB_ENABLE_CLUSTER=true\nSB_NODE_ID=s1\n"), 0o600)
	var out bytes.Buffer
	if err := serverStopGuard(nodeupgrade.Paths{EnvFile: envFile}, &out)(context.Background(), false); err != nil {
		t.Fatalf("guard: %v", err)
	}
	if !strings.Contains(out.String(), "handed leadership to s2") || len(gotAuth) != 2 || gotAuth[0] != "Bearer pat-9" {
		t.Fatalf("out=%q auth=%v", out.String(), gotAuth)
	}
	// Two voters gossip no longer lists: the daemon's raft_voters still
	// names them, and the guard refuses (J2).
	voters = []string{"s1", "s2", "s3", "s4", "s5"}
	out.Reset()
	err := serverStopGuard(nodeupgrade.Paths{EnvFile: envFile}, &out)(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "leaves 2 of 5 voting servers up") {
		t.Fatalf("guard with forgotten voters = %v", err)
	}

	// Error answers surface with their status; an empty member list is
	// an error, not "no voters".
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/cluster/members" {
			w.Write([]byte(`{}`))
			return
		}
		http.Error(w, "nope", http.StatusConflict)
	}))
	defer bad.Close()
	a := &localAPI{base: bad.URL, http: bad.Client()}
	if _, err := a.Members(context.Background()); err == nil || !strings.Contains(err.Error(), "listed no members") {
		t.Fatalf("empty members err = %v", err)
	}
	if _, err := a.TransferLeadership(context.Background()); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("transfer err = %v", err)
	}
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not json")) }))
	defer garbage.Close()
	if _, err := (&localAPI{base: garbage.URL, http: garbage.Client()}).Members(context.Background()); err == nil {
		t.Fatal("garbage members decoded")
	}
	if _, err := (&localAPI{base: "http://127.0.0.1:1", http: &http.Client{}}).Members(context.Background()); err == nil {
		t.Fatal("closed port answered")
	}
	if _, err := (&localAPI{base: "http://bad\x7f", http: &http.Client{}}).Members(context.Background()); err == nil {
		t.Fatal("bad url accepted")
	}
	if err := (&localAPI{base: ts.URL, http: ts.Client()}).do(context.Background(), http.MethodPost, "/x", make(chan int), nil); err == nil {
		t.Fatal("unmarshalable body accepted")
	}
}
