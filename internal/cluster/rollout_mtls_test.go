package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// A two-server rollout over the real internal mTLS channel: the leader's
// stage and apply calls reach the follower's node step, the follower fences
// them against the committed record after a Raft read index, copies the
// uploaded files from the leader's file route, and a call from a node that
// does not lead is refused. Leadership then moves with the hand-off call.

// upgradeTestMux is the slice of pkg/api/v1 the node step needs.
func upgradeTestMux(c *Cluster) http.Handler {
	mux := http.NewServeMux()
	writeErr := func(w http.ResponseWriter, err error) {
		var se *UpgradeStepError
		status, body := http.StatusInternalServerError, upgradewire.ErrorResponse{Error: "internal", Reason: err.Error()}
		if errors.As(err, &se) {
			status, body = se.Status, upgradewire.ErrorResponse{Error: se.Code, Reason: se.Reason}
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	mux.HandleFunc("POST /v1/cluster/nodes/{id}/upgrade", func(w http.ResponseWriter, r *http.Request) {
		peer, _ := AuthenticatedPeerNodeID(r)
		var req UpgradeStepRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := c.UpgradeStep(r.Context(), peer, req)
		if err != nil {
			writeErr(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("GET /v1/cluster/nodes/{id}/upgrade", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(c.UpgradeStatus(r.Context(), r.URL.Query().Get("op")))
	})
	mux.HandleFunc("GET "+PublicInternalUpgradeFilesPath+"{sha}", func(w http.ResponseWriter, r *http.Request) {
		peer, _ := AuthenticatedPeerNodeID(r)
		c.ServeUpgradeFile(w, r, peer, r.PathValue("sha"))
	})
	return mux
}

// wireUpgradeTestNode points a test cluster's upgrade node at a temp dir and
// a fake systemd, and records what it launches.
func wireUpgradeTestNode(t *testing.T, c *Cluster) *[]nodeupgrade.Request {
	t.Helper()
	c.upgrade.cfg.RemoteUpgrade = true
	dir := t.TempDir()
	p := nodeupgrade.Paths{StateDir: filepath.Join(dir, "upgrade"), DBPath: filepath.Join(dir, "state.db"), Sandboxd: filepath.Join(dir, "sandboxd"), Toolboxd: filepath.Join(dir, "toolboxd")}
	c.upgrade.paths = func() (nodeupgrade.Paths, error) { return p, nil }
	c.upgrade.host = &fakeUpgradeHost{fetch: map[string][]byte{}, missing: map[string]bool{}, active: map[string]bool{}}
	launched := &[]nodeupgrade.Request{}
	c.upgrade.launch = func(_ context.Context, _ nodeupgrade.Host, _ string, req nodeupgrade.Request) (string, error) {
		*launched = append(*launched, req)
		return req.Op, nil
	}
	c.AttachInternalHandler(upgradeTestMux(c))
	return launched
}

func TestRolloutOverInternalMTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}
	leader, cleanupL := newTestCluster(t, "ldr", true, nil)
	defer cleanupL()
	waitForLeader(t, leader, 10*time.Second)
	follower, cleanupF := newTestCluster(t, "fol", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupF()
	waitForVoter(t, leader, "fol", 10*time.Second)
	leader.rolloutStop()
	follower.rolloutStop()
	wireUpgradeTestNode(t, leader)
	folLaunched := wireUpgradeTestNode(t, follower)
	ctx := context.Background()

	sd, tb := []byte("sandboxd B"), []byte("toolboxd B")
	files := map[string]string{"sandboxd": sumOf(sd), "toolboxd": sumOf(tb)}
	for _, b := range [][]byte{sd, tb} {
		if _, _, err := leader.PutUpgradeFile(ctx, sumOf(b), bytes.NewReader(b)); err != nil {
			t.Fatal(err)
		}
	}
	out, created, err := leader.ApplyRollout(ctx, "pat:op", upgradewire.ApplyRequest{
		Version: "itest-b", Files: files, Source: upgradewire.SourceUpload, AllowUnversioned: true, Hold: true,
	})
	if err != nil || !created || len(out.Nodes) != 2 {
		t.Fatalf("apply = %+v %v %v", out, created, err)
	}
	leader.driver.inline = true
	leader.driver.tick(ctx)
	r, _ := leader.fsm.rolloutView()
	if r.Nodes["fol"].State != upgradewire.NodeStaged || r.Nodes["ldr"].State != upgradewire.NodeStaged {
		t.Fatalf("after staging: %s", describeNodes(r))
	}
	// The follower copied the upload from the leader's file route.
	fp, _ := follower.upgrade.paths()
	if !(nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(fp.StateDir)}).Has(files["sandboxd"]) {
		t.Fatal("the follower did not copy the uploaded file from the leader")
	}
	if n := upgradeServedBytes.Value(); n < int64(len(sd)+len(tb)) {
		t.Fatalf("served bytes = %d", n)
	}
	leader.driver.tick(ctx) // all staged -> running
	leader.driver.tick(ctx) // the follower goes first; the leader last
	if len(*folLaunched) != 1 || (*folLaunched)[0].Version != "itest-b" || (*folLaunched)[0].From == "" {
		t.Fatalf("follower launches = %+v", *folLaunched)
	}
	r, _ = leader.fsm.rolloutView()
	if r.Nodes["fol"].State != upgradewire.NodeUpgrading || r.Nodes["ldr"].State != upgradewire.NodeStaged || !leader.fsm.drainedNodesSnapshot()["fol"] {
		t.Fatalf("after the first step: %s", describeNodes(r))
	}
	// The leader reads the follower's state over the channel.
	folMember, _ := leader.LookupMember("fol")
	st, err := clusterNodeClient{c: leader}.Status(ctx, folMember, r.Nodes["fol"].Op)
	if err != nil || st.NodeID != "fol" || st.AppliedIndex == 0 {
		t.Fatalf("status = %+v %v", st, err)
	}
	// A node that does not lead is refused by the fence, after a read
	// index, with the not_leader code.
	ldrMember, _ := follower.LookupMember("ldr")
	_, err = clusterNodeClient{c: follower}.Step(ctx, ldrMember, UpgradeStepRequest{
		RolloutID: r.ID, Step: UpgradeStepStage, Direction: upgradewire.DirectionUpgrade, Version: "itest-b", Files: files, Term: follower.raft.raft.CurrentTerm(),
	})
	if stepCode(err) != upgradeCodeNotLeader {
		t.Fatalf("a step from a follower = %v", err)
	}
	if _, err := follower.UpgradeFenceFor(ctx, r.ID, "ldr"); err != nil {
		t.Fatalf("fence on a follower = %v", err)
	}
	// Hand-off: the follower leads afterwards.
	if err := (clusterNodeClient{c: leader}).TransferLeadership(ctx, folMember); err != nil {
		t.Fatalf("transfer = %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !follower.IsLeader() {
		if time.Now().After(deadline) {
			t.Fatal("the follower never led")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The old leader now refuses to serve a non-server? It is a follower:
	// it serves everyone.
	if leader.leaderRefusesCopy("someone") {
		t.Fatal("a follower refused a copy")
	}
	if !strings.Contains(rolloutOpID(r), r.ID) {
		t.Fatal("op id")
	}
}
