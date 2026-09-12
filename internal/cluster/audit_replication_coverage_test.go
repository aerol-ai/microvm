package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestFetchSandboxAuditFromPeerWrappers(t *testing.T) {
	ctx := context.Background()
	if _, err := (*Cluster)(nil).FetchSandboxAuditFromPeer(ctx, "peer", "sb", 1, "", "", ""); err == nil {
		t.Fatal("nil cluster")
	}
	if _, err := (*Agent)(nil).FetchSandboxAuditFromPeer(ctx, "peer", "sb", 1, "", "", ""); err == nil {
		t.Fatal("nil agent")
	}
	if _, err := (*Noop)(nil).FetchSandboxAuditFromPeer(ctx, "peer", "sb", 1, "", "", ""); err == nil {
		t.Fatal("noop")
	}

	c := &Cluster{nodeID: "self"}
	if _, err := c.FetchSandboxAuditFromPeer(ctx, "peer", "sb", 1, "", "", ""); err == nil {
		t.Fatal("cluster unavailable")
	}
	a := &Agent{nodeID: "self"}
	if _, err := a.FetchSandboxAuditFromPeer(ctx, "peer", "sb", 1, "", "", ""); err == nil {
		t.Fatal("agent unavailable")
	}

	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "dead", Alive: false, InternalURL: "https://dead.internal"})
	index.upsert(Member{NodeID: "plain", Alive: true, InternalURL: "http://plain.internal"})
	c.gossip = &gossipNode{memberIndex: index}
	c.setInternalClient(http.DefaultClient)
	a.gossip = &gossipNode{memberIndex: index}
	a.internalClient = http.DefaultClient

	if _, err := c.FetchSandboxAuditFromPeer(ctx, "missing", "sb", 1, "", "", ""); err == nil {
		t.Fatal("missing peer")
	}
	if _, err := a.FetchSandboxAuditFromPeer(ctx, "dead", "sb", 1, "", "", ""); err == nil {
		t.Fatal("dead peer")
	}
	if _, err := c.FetchSandboxAuditFromPeer(ctx, "plain", "sb", 1, "", "", ""); !errors.Is(err, ErrPeerInternalURLInvalid) {
		t.Fatalf("plaintext cluster = %v", err)
	}
	if _, err := a.FetchSandboxAuditFromPeer(ctx, "plain", "sb", 1, "", "", ""); !errors.Is(err, ErrPeerInternalURLInvalid) {
		t.Fatalf("plaintext agent = %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/audit") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuditPeerPage{NextCursor: "c1"})
	})
	srv, client := newNodeBoundForwardServer(t, "self", "peer-audit", handler)
	live := newGossipMemberIndex()
	live.upsert(Member{NodeID: "peer-audit", Alive: true, InternalURL: srv.URL})
	c.gossip = &gossipNode{memberIndex: live}
	c.setInternalClient(client)
	c.patToken = "pat"
	page, err := c.FetchSandboxAuditFromPeer(ctx, "peer-audit", "sb-1", 10, "cur", "secret", "inc")
	if err != nil || page.NextCursor != "c1" {
		t.Fatalf("cluster fetch = %+v err=%v", page, err)
	}
	a.gossip = &gossipNode{memberIndex: live}
	a.internalClient = client
	if _, err := a.FetchSandboxAuditFromPeer(ctx, "peer-audit", "sb-1", 0, "", "", ""); err != nil {
		t.Fatalf("agent fetch: %v", err)
	}
}
