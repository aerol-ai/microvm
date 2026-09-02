package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestPushSecretBlobToPeersIdempotentAndAuth(t *testing.T) {
	var posts atomic.Int32
	srv, internalClient := newNodeBoundForwardServer(t, "self", "peer-a", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PublicInternalSecretPath {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-pat" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		posts.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))

	members := []Member{
		{NodeID: "self", Alive: true, APIURL: "http://self"},
		{NodeID: "peer-a", Alive: true, InternalURL: srv.URL},
		{NodeID: "peer-b", Alive: false, InternalURL: srv.URL},
	}
	blob := secrets.SecretBlob{
		Ref:           "cluster-secret://sandbox/sb1/v1",
		SandboxID:     "sb1",
		Version:       1,
		Recipients:    []string{"self", "peer-a"},
		SealedPayload: []byte(`{}`),
	}
	acked, err := pushSecretBlobToPeers(context.Background(), members, internalClient, "test-pat", "self", blob, []string{"self", "peer-a"})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if len(acked) != 1 || acked[0] != "peer-a" {
		t.Fatalf("acked = %v, want [peer-a]", acked)
	}
	if posts.Load() != 1 {
		t.Fatalf("posts = %d, want 1", posts.Load())
	}
	// Retry is idempotent at the peer (handler returns 204 again).
	acked, err = pushSecretBlobToPeers(context.Background(), members, internalClient, "test-pat", "self", blob, []string{"self", "peer-a"})
	if err != nil || len(acked) != 1 {
		t.Fatalf("retry acked=%v err=%v", acked, err)
	}
}

func TestPushSecretBlobUnauthenticatedRejected(t *testing.T) {
	srv, internalClient := newNodeBoundForwardServer(t, "self", "peer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	members := []Member{{NodeID: "peer", Alive: true, InternalURL: srv.URL}}
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "s", SealedPayload: []byte("x")}
	_, err := pushSecretBlobToPeers(context.Background(), members, internalClient, "", "self", blob, []string{"peer"})
	if err == nil {
		t.Fatal("expected unauthenticated push to fail")
	}
}

func TestDeleteSecretOnPeers(t *testing.T) {
	var deletes atomic.Int32
	var gotGen string
	srv, internalClient := newNodeBoundForwardServer(t, "self", "peer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("method = %s", r.Method)
		}
		gotGen = r.URL.Query().Get("generation")
		deletes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	members := []Member{{NodeID: "peer", Alive: true, InternalURL: srv.URL}}
	acked, pending, err := deleteSecretOnPeers(context.Background(), members, internalClient, "pat", "self", "sb-del", []string{"peer", "offline"}, 7)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deletes.Load() != 1 {
		t.Fatalf("deletes = %d", deletes.Load())
	}
	if gotGen != "7" {
		t.Fatalf("generation query = %q, want 7", gotGen)
	}
	if len(acked) != 1 || acked[0] != "peer" {
		t.Fatalf("acked = %v", acked)
	}
	if len(pending) != 1 || pending[0] != "offline" {
		t.Fatalf("pending = %v, want offline still pending", pending)
	}
}

func TestPostSecretBlobRoundTripBody(t *testing.T) {
	var got secrets.SecretBlob
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	want := secrets.SecretBlob{Ref: "r1", SandboxID: "sb", Version: 1, Recipients: []string{"a"}, SealedPayload: []byte("sealed")}
	body, _ := json.Marshal(want)
	if err := postSecretBlob(context.Background(), srv.Client(), srv.URL+PublicInternalSecretPath, "p", "self", body); err != nil {
		t.Fatalf("post: %v", err)
	}
	if got.Ref != want.Ref || got.SandboxID != want.SandboxID || string(got.SealedPayload) != "sealed" {
		t.Fatalf("got %+v", got)
	}
}

func TestSecretReplicationPrefersInternalTransportWithoutPublicDowngrade(t *testing.T) {
	var internalHits atomic.Int32
	internal, internalClient := newNodeBoundForwardServer(t, "self", "peer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		internalHits.Add(1)
		http.Error(w, "internal unavailable", http.StatusServiceUnavailable)
	}))

	var publicHits atomic.Int32
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer public.Close()

	members := []Member{{
		NodeID:      "peer",
		Alive:       true,
		APIURL:      public.URL,
		InternalURL: internal.URL,
	}}
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "s", SealedPayload: []byte("x")}
	acked, err := pushSecretBlobToPeers(
		context.Background(), members, internalClient, "pat", "self", blob, []string{"peer"},
	)
	if err == nil {
		t.Fatal("expected the internal transport error")
	}
	if len(acked) != 0 {
		t.Fatalf("acked = %v, want none", acked)
	}
	if internalHits.Load() != secretFanoutMaxAttempts {
		t.Fatalf("internal hits = %d, want %d retries", internalHits.Load(), secretFanoutMaxAttempts)
	}
	if publicHits.Load() != 0 {
		t.Fatalf("public hits = %d, secret replication downgraded after internal failure", publicHits.Load())
	}
}

func TestSecretReplicationSupportsInternalOnlyMember(t *testing.T) {
	internal, internalClient := newNodeBoundForwardServer(t, "self", "peer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	members := []Member{{NodeID: "peer", Alive: true, InternalURL: internal.URL}}
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "s", SealedPayload: []byte("x")}
	acked, err := pushSecretBlobToPeers(
		context.Background(), members, internalClient, "pat", "self", blob, []string{"peer"},
	)
	if err != nil {
		t.Fatalf("push over internal-only transport: %v", err)
	}
	if len(acked) != 1 || acked[0] != "peer" {
		t.Fatalf("acked = %v, want [peer]", acked)
	}
}

func TestSecretReplicationFailClosedWithoutInternalURL(t *testing.T) {
	var publicHits atomic.Int32
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer public.Close()

	members := []Member{{NodeID: "peer", Alive: true, APIURL: public.URL}}
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "s", SealedPayload: []byte("x")}
	acked, err := pushSecretBlobToPeers(
		context.Background(), members, public.Client(), "pat", "self", blob, []string{"peer"},
	)
	if err == nil {
		t.Fatal("expected fail-closed dial when internal client is set without InternalURL")
	}
	if len(acked) != 0 {
		t.Fatalf("acked = %v, want none", acked)
	}
	if publicHits.Load() != 0 {
		t.Fatalf("public hits = %d, want 0 (no APIURL fallback)", publicHits.Load())
	}

	acked, pending, delErr := deleteSecretOnPeers(
		context.Background(), members, public.Client(), "pat", "self", "sb", []string{"peer"}, 1,
	)
	if delErr == nil {
		t.Fatal("expected delete fail-closed dial error")
	}
	if len(acked) != 0 || len(pending) != 1 || pending[0] != "peer" {
		t.Fatalf("acked=%v pending=%v", acked, pending)
	}
	holding, probeErr := probeSecretOnPeers(
		context.Background(), members, public.Client(), "pat", "self", "sb", []string{"peer"}, 1,
	)
	if probeErr == nil {
		t.Fatal("expected probe fail-closed dial error")
	}
	if len(holding) != 0 {
		t.Fatalf("holding = %v, want none", holding)
	}
	if publicHits.Load() != 0 {
		t.Fatalf("public hits after delete/probe = %d, want 0", publicHits.Load())
	}
}

func TestPushSecretBlobDeadRecipientIncomplete(t *testing.T) {
	var posts atomic.Int32
	srv, internalClient := newNodeBoundForwardServer(t, "self", "peer-a", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))

	members := []Member{
		{NodeID: "self", Alive: true, APIURL: "http://self"},
		{NodeID: "peer-a", Alive: true, InternalURL: srv.URL},
		{NodeID: "peer-b", Alive: false, InternalURL: srv.URL},
	}
	blob := secrets.SecretBlob{
		Ref: "r", SandboxID: "s", SealedPayload: []byte("x"),
		Recipients: []string{"self", "peer-a", "peer-b"},
	}
	acked, err := pushSecretBlobToPeers(context.Background(), members, internalClient, "pat", "self", blob, []string{"self", "peer-a", "peer-b"})
	if err == nil {
		t.Fatal("expected incomplete fan-out when a recipient is dead")
	}
	if len(acked) != 1 || acked[0] != "peer-a" {
		t.Fatalf("acked = %v, want [peer-a]", acked)
	}
	if posts.Load() != 1 {
		t.Fatalf("posts = %d, want 1", posts.Load())
	}

	acked, err = pushSecretBlobToPeers(context.Background(), members, internalClient, "pat", "self", blob, []string{"missing"})
	if err == nil {
		t.Fatal("expected incomplete fan-out for unknown recipient")
	}
	if len(acked) != 0 {
		t.Fatalf("acked = %v, want none", acked)
	}
}

func TestDeleteAndProbeSecretOnPeersLookup(t *testing.T) {
	var deletes, heads atomic.Int32
	srv, internalClient := newNodeBoundForwardServer(t, "self", "peer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodHead:
			heads.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("method = %s", r.Method)
		}
	}))
	lookup := func(id string) (Member, bool) {
		if id != "peer" {
			return Member{}, false
		}
		return Member{NodeID: "peer", Alive: true, InternalURL: srv.URL}, true
	}
	acked, pending, err := deleteSecretOnPeersLookup(context.Background(), lookup, internalClient, "pat", "self", "sb", []string{"peer", "missing"}, 3)
	if err != nil {
		t.Fatalf("delete lookup: %v", err)
	}
	if deletes.Load() != 1 || len(acked) != 1 || acked[0] != "peer" || len(pending) != 1 || pending[0] != "missing" {
		t.Fatalf("acked=%v pending=%v deletes=%d", acked, pending, deletes.Load())
	}
	holding, err := probeSecretOnPeersLookup(context.Background(), lookup, internalClient, "pat", "self", "sb", []string{"peer", "missing"}, 3)
	if err != nil {
		t.Fatalf("probe lookup: %v", err)
	}
	if heads.Load() != 1 || len(holding) != 1 || holding[0] != "peer" {
		t.Fatalf("holding=%v heads=%d", holding, heads.Load())
	}
}
