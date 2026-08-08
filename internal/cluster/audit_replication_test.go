package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchSandboxAuditFromPeerOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	t.Cleanup(srv.Close)

	c := &Cluster{httpClient: srv.Client(), patToken: "pat"}
	page, err := c.FetchSandboxAuditFromPeer(context.Background(), srv.URL, "sb-1", 10, "", "")
	if err != nil {
		t.Fatalf("FetchSandboxAuditFromPeer: %v", err)
	}
	if len(page.Events) != 1 || page.NextCursor != "cursor" {
		t.Fatalf("page = %+v", page)
	}

	a := &Agent{httpClient: srv.Client(), patToken: "pat"}
	if _, err := a.FetchSandboxAuditFromPeer(context.Background(), srv.URL, "sb-1", 10, "", ""); err != nil {
		t.Fatalf("Agent fetch: %v", err)
	}

	if _, err := NewNoop("n", "", "").FetchSandboxAuditFromPeer(context.Background(), srv.URL, "sb-1", 10, "", ""); err == nil {
		t.Fatal("expected Noop fetch error")
	}
}

func TestFetchSandboxAuditFromPeerErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	c := &Cluster{httpClient: srv.Client(), patToken: "pat"}
	if _, err := c.FetchSandboxAuditFromPeer(context.Background(), srv.URL, "sb-1", 10, "", ""); err == nil {
		t.Fatal("expected error")
	}
}
