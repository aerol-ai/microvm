package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/hashicorp/memberlist"
)

func TestNoopZeroCoverageMethods(t *testing.T) {
	n := NewNoop("self", "http://self", "")
	ctx := context.Background()
	n.AttachInternalHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	got, err := n.AuthoritativePlacementsByIDs(ctx, []string{"sb-1"})
	if err != nil || len(got) != 0 {
		t.Fatalf("AuthoritativePlacementsByIDs = %v %v", got, err)
	}
	if err := n.BeginDeletePlacementExact(ctx, "sb-1", "self", "inc-1"); err != nil {
		t.Fatalf("BeginDeletePlacementExact = %v", err)
	}

	d := &gossipDelegate{}
	d.NotifyMsg([]byte("x"))
	d.MergeRemoteState([]byte("y"), false)

	(&voterAutoJoinDelegate{}).NotifyUpdate(nil)
	if expiry := placementDeleteExpiryUnix(); expiry <= 0 {
		t.Fatalf("placementDeleteExpiryUnix = %d", expiry)
	}
}

func TestGossipAndVoterDelegateNoopMethods(t *testing.T) {
	d := &gossipDelegate{}
	d.NotifyMsg([]byte("x"))
	d.MergeRemoteState([]byte("x"), false)
	if got := d.GetBroadcasts(0, 0); got != nil {
		t.Fatalf("GetBroadcasts=%v", got)
	}
	if got := d.LocalState(false); got != nil {
		t.Fatalf("LocalState=%v", got)
	}

	v := &voterAutoJoinDelegate{}
	v.NotifyUpdate(nil)
}

func TestGossipHelpersAdditionalBranches(t *testing.T) {
	var nilNode *gossipNode
	if got := nilNode.memberlistNodes(); got != nil {
		t.Fatalf("nil gossip node members=%v", got)
	}

	encodedServer, err := json.Marshal(nodeMeta{NodeID: "server-1", Role: config.NodeRoleServer, APIURL: "http://cp", InternalURL: "https://cp"})
	if err != nil {
		t.Fatal(err)
	}
	encodedWorker, err := json.Marshal(nodeMeta{NodeID: "worker-1", Role: config.NodeRoleWorker, APIURL: "http://w"})
	if err != nil {
		t.Fatal(err)
	}

	if hasLiveControlPlaneMember(nil, "") {
		t.Fatal("nil members should not report control-plane")
	}
	if hasLiveControlPlaneMember([]*memberlist.Node{{Name: "w", State: memberlist.StateAlive, Meta: encodedWorker}}, "") {
		t.Fatal("worker-only members should not report control-plane")
	}
	if !hasLiveControlPlaneMember([]*memberlist.Node{{Name: "s", State: memberlist.StateAlive, Meta: encodedServer}}, "") {
		t.Fatal("server with endpoint should report control-plane")
	}
	if hasLiveControlPlaneMember([]*memberlist.Node{{Name: "self", State: memberlist.StateAlive, Meta: encodedServer}}, "server-1") {
		t.Fatal("self control-plane member should be ignored")
	}

	joined := 0
	gn := &gossipNode{
		bootstrapPeers: []string{"127.0.0.1:7946"},
		joinBootstrapPeers: func(peers []string) (int, error) {
			joined++
			return len(peers), nil
		},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		delegate: &gossipDelegate{nodeID: "self"},
	}

	gn.maybeRejoinBootstrapPeers([]*memberlist.Node{{Name: "self", State: memberlist.StateAlive, Meta: encodedWorker}})
	if joined != 1 {
		t.Fatalf("expected one bootstrap rejoin, got %d", joined)
	}
	gn.maybeRejoinBootstrapPeers([]*memberlist.Node{{Name: "other", State: memberlist.StateAlive, Meta: encodedServer}})
	if joined != 1 {
		t.Fatalf("expected no extra rejoin when control-plane member alive, got %d", joined)
	}
}

func TestGossipDelegateNodeMetaFallbacks(t *testing.T) {
	d := newGossipDelegate("node-a", "", "http://127.0.0.1:8080", "", "10.0.0.1:7001", "", config.NodeRoleServer, "", nil)
	if meta := d.NodeMeta(0); meta != nil {
		t.Fatalf("NodeMeta(0)=%q", string(meta))
	}
	if meta := d.NodeMeta(2); string(meta) != "{}" {
		t.Fatalf("NodeMeta tiny limit=%q", string(meta))
	}
	if meta := d.NodeMeta(memberlist.MetaMaxSize); len(meta) == 0 {
		t.Fatal("NodeMeta default limit should not be empty")
	}
}

func TestGossipIndexNilAndLeaseLossBranches(t *testing.T) {
	var nilIdx *gossipMemberIndex
	nilIdx.upsert(Member{NodeID: "x"})
	nilIdx.replace([]Member{{NodeID: "x"}})
	if got := nilIdx.snapshot(); got != nil {
		t.Fatalf("nil snapshot=%v", got)
	}
	nilIdx.recordLeaseLossesLocked(nil)
	nilIdx.recordMetricsLocked(0)

	idx := newGossipMemberIndex()
	idx.upsert(Member{}) // empty id
	idx.seen = nil
	idx.upsert(Member{NodeID: "w", Alive: true, Role: config.NodeRoleWorker, Capacity: step3FatCapacity()})
	idx.replace([]Member{
		{NodeID: "", Alive: true},
		{NodeID: "w", Alive: false, Role: config.NodeRoleWorker},
	})
	idx.seen = nil
	idx.replace([]Member{{NodeID: "w2", Alive: true, Role: config.NodeRoleWorker}})
}

func TestMaybeRejoinBootstrapPeersJoinError(t *testing.T) {
	meta, _ := json.Marshal(nodeMeta{NodeID: "self", Role: config.NodeRoleWorker, APIURL: "http://self"})
	gn := &gossipNode{
		bootstrapPeers: []string{"127.0.0.1:1"},
		joinBootstrapPeers: func(peers []string) (int, error) {
			return 0, errors.New("join failed")
		},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		delegate: &gossipDelegate{nodeID: "self"},
	}
	gn.maybeRejoinBootstrapPeers([]*memberlist.Node{{Name: "self", State: memberlist.StateAlive, Meta: meta}})
}

func TestMaybeRejoinBootstrapPeersJoinSuccess(t *testing.T) {
	gn := &gossipNode{
		bootstrapPeers: []string{"127.0.0.1:1"},
		joinBootstrapPeers: func(peers []string) (int, error) {
			return 2, nil
		},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		delegate: &gossipDelegate{nodeID: "self"},
	}
	// Empty nodes → no live control plane → rejoin succeeds.
	gn.maybeRejoinBootstrapPeers(nil)
}

func TestGossipNotifyUpdateLoggerAndSetupErrors(t *testing.T) {
	next := &voterAutoJoinDelegate{c: &Cluster{nodeID: "self"}}
	d := &indexedEventDelegate{
		index:  newGossipMemberIndex(),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		next:   next,
	}
	meta, _ := json.Marshal(nodeMeta{NodeID: "peer", Role: config.NodeRoleServer, APIURL: "http://p"})
	d.NotifyUpdate(&memberlist.Node{Name: "peer", State: memberlist.StateAlive, Meta: meta})
	if m := memberFromMemberlistNode(nil); m.NodeID != "" {
		t.Fatalf("nil node=%+v", m)
	}

	if _, err := setupGossip(gossipSetupConfig{NodeID: "n", BindAddr: "bad"}, nil, nil); err == nil {
		t.Fatal("bad bind addr")
	}
	if _, err := setupGossip(gossipSetupConfig{NodeID: "n", BindAddr: "127.0.0.1:0", AdvertiseAddr: "bad"}, nil, nil); err == nil {
		t.Fatal("bad advertise addr")
	}
	if _, err := setupGossip(gossipSetupConfig{NodeID: "n", BindAddr: "127.0.0.1:0", SecretKey: []byte("short")}, nil, nil); err == nil {
		t.Fatal("bad secret key length")
	}
	if _, _, err := splitHostPort("127.0.0.1:notport"); err == nil {
		t.Fatal("invalid port")
	}
}
