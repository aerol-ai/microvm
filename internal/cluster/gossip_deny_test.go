package cluster

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/memberlist"
)

// Deny enforcement at gossip and on the internal listener (gossip_deny.go).

func TestGossipAliveDelegateRefusesDeniedNodes(t *testing.T) {
	denied := map[string]bool{"wkr-gone": true, "self": true}
	d := &gossipAliveDelegate{selfID: "self", denied: func(id string) bool { return denied[id] }}
	before := expvarMapValue(denyHits, denyHitGossip)
	if err := d.NotifyAlive(&memberlist.Node{Name: "wkr-gone"}); !errors.Is(err, ErrPeerDeleted) {
		t.Fatalf("denied peer = %v", err)
	}
	if got := expvarMapValue(denyHits, denyHitGossip) - before; got != 1 {
		t.Fatalf("gossip deny hits = %d, want 1", got)
	}
	// Self is never refused: its own alive message passes through here.
	for _, n := range []*memberlist.Node{{Name: "self"}, {Name: "wkr-ok"}, nil} {
		if err := d.NotifyAlive(n); err != nil {
			t.Fatalf("NotifyAlive(%v) = %v", n, err)
		}
	}
	var nilDelegate *gossipAliveDelegate
	if err := nilDelegate.NotifyAlive(&memberlist.Node{Name: "wkr-gone"}); err != nil {
		t.Fatal(err)
	}
	if err := (&gossipAliveDelegate{}).NotifyAlive(&memberlist.Node{Name: "wkr-gone"}); err != nil {
		t.Fatal("a delegate without a deny source refused a node")
	}
}

func TestMemberIndexDropsDeniedMembers(t *testing.T) {
	denied := map[string]bool{}
	i := newGossipMemberIndex()
	i.selfID, i.denied = "self", func(id string) bool { return denied[id] }
	i.upsert(Member{NodeID: "wkr-1", Alive: true, Role: config.NodeRoleWorker})
	i.upsert(Member{NodeID: "self", Alive: true, Role: config.NodeRoleServer, InternalURL: "https://self"})
	denied["wkr-1"], denied["self"] = true, true
	// The next update for a denied member drops it; self stays.
	i.upsert(Member{NodeID: "wkr-1", Alive: true, Role: config.NodeRoleWorker})
	if _, ok := i.get("wkr-1"); ok {
		t.Fatal("a denied member stayed in the index")
	}
	if _, ok := i.get("self"); !ok {
		t.Fatal("self was dropped")
	}
	if _, seen := i.seen["wkr-1"]; seen {
		t.Fatal("a denied member kept its seen time")
	}
	i.replace([]Member{{NodeID: "wkr-1", Alive: true}, {NodeID: "wkr-2", Alive: true}, {NodeID: "self", Alive: true}})
	if got := memberIDs(i.snapshot()); strings.Join(got, ",") != "self,wkr-2" {
		t.Fatalf("after replace = %v", got)
	}
	if floor, alive := i.featureFloor(); alive != 2 || floor != 0 {
		t.Fatalf("feature floor = %d over %d alive, want the denied node uncounted", floor, alive)
	}
}

func TestDenyHitRecorderThrottlesItsLog(t *testing.T) {
	var buf bytes.Buffer
	now := time.Unix(1000, 0)
	r := &denyHitRecorder{logger: slog.New(slog.NewTextHandler(&buf, nil)), now: func() time.Time { return now }}
	before := expvarMapValue(denyHits, denyHitPeer)
	r.hit(denyHitPeer, "wkr-1")
	r.hit(denyHitPeer, "wkr-1")
	r.hit(denyHitPlacement, "wkr-1") // another place logs on its own
	now = now.Add(denyHitLogEvery)
	r.hit(denyHitPeer, "wkr-1")
	if got := strings.Count(buf.String(), "refused a deleted node"); got != 3 {
		t.Fatalf("log lines = %d, want 3:\n%s", got, buf.String())
	}
	if got := expvarMapValue(denyHits, denyHitPeer) - before; got != 3 {
		t.Fatalf("peer hits = %d, want every refusal counted", got)
	}
	var nilRecorder *denyHitRecorder
	nilRecorder.hit(denyHitPeer, "wkr-1") // counts, logs nothing, no panic
	(&denyHitRecorder{}).hit(denyHitPeer, "wkr-1")
}

// A deleted node that still holds a cluster cert is refused on the internal
// listener with its own 403, before the membership check ever runs.
func TestInternalServerRefusesDeniedPeer(t *testing.T) {
	pool, tlsCert, err := generateTestCertForNode("worker-1")
	if err != nil {
		t.Fatal(err)
	}
	ct := &ClusterTLS{nodeCert: tlsCert, caPool: pool}
	srv, err := startInternalServer("127.0.0.1:0", ct, func(context.Context, []byte) error { return nil }, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.SetPeerAuthorizer(func(string) bool { return true })
	denied := false
	srv.SetPeerDenyCheck(func(id string) bool { return denied && id == "worker-1" })
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: ct.clientConfig()}}
	post := func() (int, string) {
		req, _ := http.NewRequest(http.MethodPost, "https://"+srv.Addr()+InternalAPIPath, strings.NewReader("{}"))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, _ := post(); code != http.StatusNoContent {
		t.Fatalf("live peer = %d", code)
	}
	denied = true
	code, body := post()
	if code != http.StatusForbidden || !strings.Contains(body, "was deleted") {
		t.Fatalf("deleted peer = %d %q", code, body)
	}
	// A deleted node is told it was deleted: never the "not in membership"
	// wording a restarting node reads as "retry".
	if errors.Is(statusError{status: code, message: body}, ErrMembershipPending) {
		t.Fatal("the deleted-node refusal reads as membership pending")
	}
	srv.SetPeerDenyCheck(nil)
	if code, _ := post(); code != http.StatusNoContent {
		t.Fatalf("after removing the check = %d", code)
	}
	var nilSrv *internalServer
	nilSrv.SetPeerDenyCheck(nil)
}

// Two real gossip nodes: a node the seed has denied never joins its view,
// even with the gossip key.
func TestGossipRefusesDeniedNodeAtJoin(t *testing.T) {
	if testing.Short() {
		t.Skip("starts two memberlist nodes")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var mu sync.Mutex
	denied := map[string]bool{"wkr-gone": true}
	seed, err := setupGossip(gossipSetupConfig{
		NodeID: "seed", BindAddr: "127.0.0.1:0", APIURL: "http://seed", Role: config.NodeRoleServer,
		Denied: func(id string) bool {
			mu.Lock()
			defer mu.Unlock()
			return denied[id]
		},
		DenyHits: &denyHitRecorder{logger: logger},
	}, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Close()
	addr := seed.ml.LocalNode().Address()
	join := func(id string) *gossipNode {
		g, err := setupGossip(gossipSetupConfig{NodeID: id, BindAddr: "127.0.0.1:0", APIURL: "http://" + id, Role: config.NodeRoleWorker, BootstrapPeers: []string{addr}}, nil, logger)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	ok := join("wkr-ok")
	defer ok.Close()
	gone := join("wkr-gone")
	defer gone.Close()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		seed.refreshMemberIndex()
		if _, found := seed.lookupMember("wkr-ok"); found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, found := seed.lookupMember("wkr-ok"); !found {
		t.Fatal("an allowed node never joined")
	}
	for _, n := range seed.memberlistNodes() {
		if n.Name == "wkr-gone" {
			t.Fatal("memberlist admitted the denied node")
		}
	}
	if _, found := seed.memberlistMember("wkr-gone"); found {
		t.Fatal("the unfiltered lookup found the denied node")
	}
	if m, found := seed.memberlistMember("wkr-ok"); !found || m.Role != config.NodeRoleWorker {
		t.Fatalf("memberlistMember(wkr-ok) = %+v %v", m, found)
	}
	// Deleted while a member: the view drops it at once, but memberlist
	// keeps it until it stops answering probes, and the node-delete path
	// still finds it there.
	mu.Lock()
	denied["wkr-ok"] = true
	mu.Unlock()
	seed.refreshMemberIndex()
	if _, found := seed.lookupMember("wkr-ok"); found {
		t.Fatal("a node denied while a member stayed in the view")
	}
	if m, found := seed.memberlistMember("wkr-ok"); !found || m.NodeID != "wkr-ok" {
		t.Fatalf("memberlistMember after deny = %+v %v", m, found)
	}
}
