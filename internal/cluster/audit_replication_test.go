package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestFetchSandboxAuditFromPeerValidationAndResponseVariants(t *testing.T) {
	if _, err := fetchSandboxAuditFromPeer(context.Background(), nil, "", "self", "https://peer", "sb", 0, "", "", ""); err == nil {
		t.Fatal("expected nil-client error")
	}
	if _, err := fetchSandboxAuditFromPeer(context.Background(), http.DefaultClient, "", "self", "https://peer", " ", 0, "", "", ""); err == nil {
		t.Fatal("expected empty-sandbox error")
	}
	if _, err := fetchSandboxAuditFromPeer(context.Background(), http.DefaultClient, "", "self", " ", "sb", 0, "", "", ""); err == nil {
		t.Fatal("expected empty-peer-url error")
	}

	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		if r.Header.Get(PeerNodeIDHeader) != "self" || r.Header.Get("Authorization") != "Bearer pat" {
			http.Error(w, "headers", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	page, err := fetchSandboxAuditFromPeer(context.Background(), srv.Client(), "pat", "self", srv.URL, "sb/a", 25, "cursor/value", "egress", "inc-1")
	if err != nil {
		t.Fatalf("empty success response: %v", err)
	}
	if len(page.Events) != 0 || page.NextCursor != "" {
		t.Fatalf("empty page = %+v", page)
	}
	for _, want := range []string{"limit=25", "cursor=cursor%2Fvalue", "kind=egress", "incarnation_id=inc-1"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer badJSON.Close()
	if _, err := fetchSandboxAuditFromPeer(context.Background(), badJSON.Client(), "", "self", badJSON.URL, "sb", 0, "", "", ""); err == nil || !strings.Contains(err.Error(), "peer audit decode") {
		t.Fatalf("decode error = %v", err)
	}
}
