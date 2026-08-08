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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer srv.Close()

	members := []Member{
		{NodeID: "self", Alive: true, APIURL: "http://self"},
		{NodeID: "peer-a", Alive: true, APIURL: srv.URL},
		{NodeID: "peer-b", Alive: false, APIURL: srv.URL},
	}
	blob := secrets.SecretBlob{
		Ref:           "cluster-secret://sandbox/sb1/v1",
		SandboxID:     "sb1",
		Version:       1,
		Recipients:    []string{"self", "peer-a"},
		SealedPayload: []byte(`{}`),
	}
	acked, err := pushSecretBlobToPeers(context.Background(), members, srv.Client(), "test-pat", "self", blob, []string{"self", "peer-a"})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if acked != 1 {
		t.Fatalf("acked = %d, want 1", acked)
	}
	if posts.Load() != 1 {
		t.Fatalf("posts = %d, want 1", posts.Load())
	}
	// Retry is idempotent at the peer (handler returns 204 again).
	acked, err = pushSecretBlobToPeers(context.Background(), members, srv.Client(), "test-pat", "self", blob, []string{"self", "peer-a"})
	if err != nil || acked != 1 {
		t.Fatalf("retry acked=%d err=%v", acked, err)
	}
}

func TestPushSecretBlobUnauthenticatedRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	members := []Member{{NodeID: "peer", Alive: true, APIURL: srv.URL}}
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "s", SealedPayload: []byte("x")}
	_, err := pushSecretBlobToPeers(context.Background(), members, srv.Client(), "", "self", blob, []string{"peer"})
	if err == nil {
		t.Fatal("expected unauthenticated push to fail")
	}
}

func TestDeleteSecretOnPeers(t *testing.T) {
	var deletes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("method = %s", r.Method)
		}
		deletes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	members := []Member{{NodeID: "peer", Alive: true, APIURL: srv.URL}}
	if err := deleteSecretOnPeers(context.Background(), members, srv.Client(), "pat", "self", "sb-del", []string{"peer"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if deletes.Load() != 1 {
		t.Fatalf("deletes = %d", deletes.Load())
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
	if err := postSecretBlob(context.Background(), srv.Client(), srv.URL+PublicInternalSecretPath, "p", body); err != nil {
		t.Fatalf("post: %v", err)
	}
	if got.Ref != want.Ref || got.SandboxID != want.SandboxID || string(got.SealedPayload) != "sealed" {
		t.Fatalf("got %+v", got)
	}
}
