package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestFetchSandboxAuditFromPeerOK(t *testing.T) {
	srv, internalClient := newNodeBoundForwardServer(t, "caller", "peer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pat" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != PublicInternalSandboxAuditPath+"sb-1/audit" {
			http.Error(w, "bad path "+r.URL.Path, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(AuditPeerPage{
			Events: []AuditEventDTO{{
				Time: time.Unix(1, 0).UTC(), SandboxID: "sb-1", Result: "success", Actor: "peer",
			}},
			NextCursor: "cursor",
		})
	}))

	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "peer", APIURL: srv.URL, InternalURL: srv.URL, Alive: true})
	c := &Cluster{nodeID: "caller", internalClient: internalClient, patToken: "pat", gossip: &gossipNode{memberIndex: index}}
	page, err := c.FetchSandboxAuditFromPeer(context.Background(), "peer", "sb-1", 10, "", "", "")
	if err != nil {
		t.Fatalf("FetchSandboxAuditFromPeer: %v", err)
	}
	if len(page.Events) != 1 || page.NextCursor != "cursor" {
		t.Fatalf("page = %+v", page)
	}

	a := &Agent{nodeID: "caller", internalClient: internalClient, patToken: "pat", gossip: &gossipNode{memberIndex: index}}
	if _, err := a.FetchSandboxAuditFromPeer(context.Background(), "peer", "sb-1", 10, "", "", ""); err != nil {
		t.Fatalf("Agent fetch: %v", err)
	}

	if _, err := NewNoop("n", "", "").FetchSandboxAuditFromPeer(context.Background(), "peer", "sb-1", 10, "", "", ""); err == nil {
		t.Fatal("expected Noop fetch error")
	}
}

func TestFetchSandboxAuditFromPeerErrorStatus(t *testing.T) {
	srv, internalClient := newNodeBoundForwardServer(t, "caller", "peer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "peer", APIURL: srv.URL, InternalURL: srv.URL, Alive: true})
	c := &Cluster{nodeID: "caller", internalClient: internalClient, patToken: "pat", gossip: &gossipNode{memberIndex: index}}
	if _, err := c.FetchSandboxAuditFromPeer(context.Background(), "peer", "sb-1", 10, "", "", ""); err == nil {
		t.Fatal("expected error")
	}
}
