package cluster

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"expvar"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/version"
)

// More Raft-free coverage of the join service: the token gauge, FSM pruning,
// gossip-backed helpers and the peer POST.

func TestJoinTokenGauge(t *testing.T) {
	f := newPlacementFSM()
	now := time.Now()
	stamp := now.UnixNano()
	_, srv := testJoinToken(t, JoinRoleServer, stamp, time.Hour, false)
	_, never := testJoinToken(t, JoinRoleWorker, stamp, 0, true)
	_, used := testJoinToken(t, JoinRoleWorker, stamp, 0, false)
	_, old := testJoinToken(t, JoinRoleIngress, now.Add(-2*time.Hour).UnixNano(), time.Hour, false)
	for i, rec := range []JoinTokenRecord{srv, never, used, old} {
		applyDenyLogAt(t, f, uint64(i+1), putTokenCmd(rec, stamp))
	}
	applyDenyLogAt(t, f, 9, admitCmd(used.ID, "w", JoinRoleWorker, testKey("w"), stamp))
	prev := joinTokenSource.Load()
	joinTokenSource.Store(f)
	defer joinTokenSource.Store(prev)
	get := func(role, kind string) string {
		return joinTokenGauge.Get(role).(*expvar.Map).Get(kind).String()
	}
	if get(JoinRoleServer, "expiring") != "1" || get(JoinRoleWorker, "never") != "1" || get(JoinRoleIngress, "expiring") != "0" || get(JoinRoleWorker, "expiring") != "0" {
		t.Fatalf("gauge server/expiring=%s worker/never=%s ingress/expiring=%s", get(JoinRoleServer, "expiring"), get(JoinRoleWorker, "never"), get(JoinRoleIngress, "expiring"))
	}
	if countJoinTokens(nil, JoinRoleWorker, "never", now) != 0 {
		t.Fatal("nil FSM counted tokens")
	}
}

func TestJoinTokenPruneAndLiteralFSM(t *testing.T) {
	// A literal FSM grows its maps on the first join op.
	lit := &placementFSM{}
	_, rec := testJoinToken(t, JoinRoleWorker, 1, time.Hour, false)
	if _, ok := applyDenyLogAt(t, lit, 1, putTokenCmd(rec, 1)).(JoinTokenRecord); !ok {
		t.Fatal("literal FSM refused a token")
	}
	lit2 := &placementFSM{}
	if _, ok := applyDenyLogAt(t, lit2, 1, command{Op: opAdoptNodes, StampUnixNano: 1, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{{NodeID: "a", Role: JoinRoleWorker, KeyHash: testKey("a")}}}}).(JoinAdoptResult); !ok {
		t.Fatal("literal FSM refused adopt")
	}
	// A token expired for longer than the list retention is dropped by the
	// next join write, at that write's stamp.
	f := newPlacementFSM()
	applyDenyLogAt(t, f, 1, putTokenCmd(rec, 1))
	later := rec.ExpiresUnixNano + int64(joinTokenListRetention) + 1
	_, fresh := testJoinToken(t, JoinRoleWorker, later, time.Hour, false)
	applyDenyLogAt(t, f, 2, putTokenCmd(fresh, later))
	if _, ok := f.joinToken(rec.ID); ok {
		t.Fatal("long-expired token kept")
	}
	if _, ok := f.joinToken(fresh.ID); !ok {
		t.Fatal("fresh token dropped")
	}
	r := JoinTokenRecord{UsedBy: []JoinTokenUse{{NodeID: "a", KeyHash: "k"}}}
	if !r.usedBy("a", "k") || r.usedBy("a", "other") || r.usedBy("b", "k") {
		t.Fatal("usedBy")
	}
}

// gossipCluster is a Cluster literal with a member view.
func gossipCluster(t *testing.T, members ...Member) *Cluster {
	t.Helper()
	c := &Cluster{fsm: newPlacementFSM(), nodeID: "self", logger: slog.New(slog.NewTextHandler(io.Discard, nil)), denyHits: &denyHitRecorder{}}
	c.gossip = &gossipNode{memberIndex: newGossipMemberIndex()}
	for _, m := range members {
		c.gossip.memberIndex.upsert(m)
	}
	return c
}

func TestJoinGossipBackedHelpers(t *testing.T) {
	c := gossipCluster(t,
		Member{NodeID: "srv-a", Alive: true, Role: config.NodeRoleServer, InternalURL: "https://10.0.0.2:7002", Version: "v1.2.3"},
		Member{NodeID: "wkr-a", Alive: true, Role: config.NodeRoleWorker, InternalURL: "https://10.0.0.3:7002", Version: "v1.2.2"},
		Member{NodeID: "srv-dead", Alive: false, Role: config.NodeRoleServer, InternalURL: "https://10.0.0.4:7002", Version: "v0.1.0"},
	)
	c.internalURL = "https://10.0.0.1:7002"
	c.joinAdvertisePort = 17003
	got := c.joinURLs()
	if len(got) != 2 || got[0] != "https://10.0.0.1:17003" || got[1] != "https://10.0.0.2:17003" {
		t.Fatalf("join URLs = %v (workers and dead servers are not join URLs)", got)
	}
	for v, want := range map[string]bool{"v1.2.3": true, "v1.2.2": true, "v0.1.0": false, version.Version: true, "v9": false} {
		if c.joinVersionAllowed(v) != want {
			t.Fatalf("joinVersionAllowed(%s) != %v", v, want)
		}
	}
	// A live member's ID is taken unless it is that key retrying.
	applyDenyLogAt(t, c.fsm, 1, command{Op: opAdoptNodes, StampUnixNano: 1, JoinAdopt: &JoinAdoptCommand{Nodes: []AdmittedNode{{NodeID: "wkr-a", Role: JoinRoleWorker, KeyHash: testKey("wkr-a")}}}})
	if err := c.liveMemberHoldsID("wkr-a", testKey("wkr-a")); err != nil {
		t.Fatalf("retry of the admitted key refused: %v", err)
	}
	if err := c.liveMemberHoldsID("wkr-a", testKey("thief")); !errors.Is(err, ErrNodeIDInUse) {
		t.Fatalf("live ID with another key = %v", err)
	}
	if err := c.liveMemberHoldsID("srv-dead", testKey("x")); err != nil {
		t.Fatalf("dead member's ID = %v", err)
	}
	if peers := c.bootstrapPeers(); peers == nil {
		t.Fatal("bootstrap peers nil")
	}
	// Members without raft: collectMemberKeys reports each as unreachable.
	c.tls = nil
	nodes, unreachable := c.collectMemberKeys(context.Background())
	if len(nodes) != 0 || len(unreachable) != 2 {
		t.Fatalf("collect = %v %v", nodes, unreachable)
	}
	// No other live server answers: postToServerPeers says so.
	if err := c.postToServerPeers(context.Background(), "/x", struct{}{}, nil); err == nil {
		t.Fatal("post with no internal client succeeded")
	}
	var nilMirror *agentDenyMirror
	if nilMirror.revokedKey("k", 1) || (&agentDenyMirror{}).revokedKey("", 1) {
		t.Fatal("revokedKey on nil mirror or empty key")
	}
	if ExtractPeerRole(&x509.Certificate{DNSNames: []string{"role:boss", "node:x"}}) != "" {
		t.Fatal("an unknown role SAN was accepted")
	}
}

func TestJoinWritesWithoutRaft(t *testing.T) {
	c := &Cluster{cfg: config.Config{}}
	ctx := context.Background()
	if _, err := c.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleWorker}); err == nil {
		t.Fatal("create without Raft succeeded")
	}
	if err := c.RevokeJoinToken(ctx, "abcdef"); err == nil {
		t.Fatal("revoke without Raft succeeded")
	}
	info := joinTokenInfo(JoinTokenRecord{ID: "abcdef", ExpiresUnixNano: 1}, 2)
	if !info.Expired || info.ExpiresAt == nil || info.UsedBy == nil {
		t.Fatalf("token info = %+v", info)
	}
}

func TestPostPeerJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(PeerNodeIDHeader) != "me" || r.Header.Get("Authorization") != "Bearer pat" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/ok":
			_ = json.NewEncoder(w).Encode(CAKeyResponse{CAKey: "KEY"})
		case "/no-signer":
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": ErrNoCASigner.Error()})
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	var out CAKeyResponse
	if err := postPeerJSON(ctx, srv.Client(), srv.URL+"/ok", "me", "pat", struct{}{}, &out); err != nil || out.CAKey != "KEY" {
		t.Fatalf("ok = %+v %v", out, err)
	}
	if err := postPeerJSON(ctx, srv.Client(), srv.URL+"/no-signer", "me", "pat", struct{}{}, &out); !errors.Is(err, ErrNoCASigner) || !isPeerRetryable(err) {
		t.Fatalf("no signer = %v", err)
	}
	var se statusError
	if err := postPeerJSON(ctx, srv.Client(), srv.URL+"/other", "me", "pat", struct{}{}, &out); !errors.As(err, &se) || se.status != http.StatusTeapot {
		t.Fatalf("other = %v", err)
	}
	if err := postPeerJSON(ctx, srv.Client(), "http://127.0.0.1:1/x", "me", "pat", struct{}{}, &out); err == nil {
		t.Fatal("unreachable peer succeeded")
	}
	if err := postPeerJSON(ctx, srv.Client(), srv.URL, "me", "pat", make(chan int), &out); err == nil {
		t.Fatal("unencodable body succeeded")
	}
	if err := postPeerJSON(ctx, srv.Client(), "://bad", "me", "pat", struct{}{}, &out); err == nil {
		t.Fatal("bad URL succeeded")
	}
}

func TestPKIFileErrors(t *testing.T) {
	dir := t.TempDir()
	// The target is a non-empty directory: the rename fails, the temp file
	// is cleaned up.
	target := filepath.Join(dir, "node.crt")
	if err := os.MkdirAll(filepath.Join(target, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(target, []byte("x"), 0o644); err == nil {
		t.Fatal("rename onto a directory succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
	// The CA store path is a file.
	file := filepath.Join(dir, "file")
	_ = os.WriteFile(file, []byte("x"), 0o600)
	if err := SaveClusterCA(filepath.Join(file, "ca"), mustCA(t)); err == nil {
		t.Fatal("CA store under a file")
	}
	if err := SaveClusterCA(dir, nil); err == nil {
		t.Fatal("nil CA saved")
	}
	// ca.key unreadable (a directory).
	caDir := filepath.Join(dir, "ca")
	_ = os.MkdirAll(filepath.Join(caDir, caStoreKeyFile), 0o700)
	if _, err := LoadClusterCA(caDir); err == nil {
		t.Fatal("ca.key as a directory loaded")
	}
	// A renewer with a logger logs its failure.
	r := &certRenewer{nodeID: "n", logger: slog.New(slog.NewTextHandler(io.Discard, nil)), now: time.Now}
	certRenewFailingSince.Set(0)
	if err := r.failed(errors.New("x")); err == nil || certRenewFailingSince.Value() == 0 {
		t.Fatal("failed()")
	}
	certRenewFailingSince.Set(0)
}
