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

func TestFetchSandboxOwnerRefResponseAndWrappers(t *testing.T) {
	if _, _, err := fetchSandboxOwnerRef(context.Background(), nil, "", "self", "https://peer", "sb"); err == nil {
		t.Fatal("expected nil-client error")
	}
	if _, _, err := fetchSandboxOwnerRef(context.Background(), http.DefaultClient, "", "self", "", "sb"); err == nil {
		t.Fatal("expected empty-peer-url error")
	}

	srv, internalClient := newNodeBoundForwardServer(t, "caller", "peer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalSandboxAuditPath+"sb-1/meta" {
			http.Error(w, "bad path", http.StatusNotFound)
			return
		}
		if r.Header.Get(PeerNodeIDHeader) != "caller" || r.Header.Get("Authorization") != "Bearer pat" {
			http.Error(w, "bad headers", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(SandboxOwnerMeta{OwnerRef: "tenant-a", Exists: true})
	}))
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "peer", InternalURL: srv.URL, Alive: true})
	gossip := &gossipNode{memberIndex: index}

	c := &Cluster{nodeID: "caller", internalClient: internalClient, patToken: "pat", gossip: gossip}
	owner, exists, err := c.FetchSandboxOwnerRef(context.Background(), "peer", "sb-1")
	if err != nil || !exists || owner != "tenant-a" {
		t.Fatalf("Cluster FetchSandboxOwnerRef owner=%q exists=%v err=%v", owner, exists, err)
	}
	a := &Agent{nodeID: "caller", internalClient: internalClient, patToken: "pat", gossip: gossip}
	owner, exists, err = a.FetchSandboxOwnerRef(context.Background(), "peer", "sb-1")
	if err != nil || !exists || owner != "tenant-a" {
		t.Fatalf("Agent FetchSandboxOwnerRef owner=%q exists=%v err=%v", owner, exists, err)
	}
	if _, _, err := NewNoop("n", "", "").FetchSandboxOwnerRef(context.Background(), "peer", "sb-1"); err == nil {
		t.Fatal("expected Noop owner-ref fetch error")
	}

	for name, fetch := range map[string]func() error{
		"cluster_nil": func() error {
			_, _, err := (*Cluster)(nil).FetchSandboxOwnerRef(context.Background(), "peer", "sb")
			return err
		},
		"agent_nil": func() error {
			_, _, err := (*Agent)(nil).FetchSandboxOwnerRef(context.Background(), "peer", "sb")
			return err
		},
		"cluster_unknown": func() error {
			_, _, err := c.FetchSandboxOwnerRef(context.Background(), "missing", "sb")
			return err
		},
		"agent_unknown": func() error {
			_, _, err := a.FetchSandboxOwnerRef(context.Background(), "missing", "sb")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := fetch(); err == nil {
				t.Fatal("expected unavailable error")
			}
		})
	}
}

func TestFetchSandboxOwnerRefResponseVariants(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantExists bool
		wantErr    string
	}{
		{name: "not_found", status: http.StatusNotFound},
		{name: "not_exists", status: http.StatusOK, body: `{"exists":false}`},
		{name: "bad_status", status: http.StatusServiceUnavailable, body: "nope", wantErr: "returned 503"},
		{name: "bad_json", status: http.StatusOK, body: `{`, wantErr: "peer sandbox meta decode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, exists, err := fetchSandboxOwnerRef(context.Background(), srv.Client(), "", "self", srv.URL, "sb")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || exists != tc.wantExists {
				t.Fatalf("exists=%v err=%v", exists, err)
			}
		})
	}
}
