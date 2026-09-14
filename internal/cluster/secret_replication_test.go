package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

func TestPushSecretBlobToAnyPeerRacesRecipientsAndSkipsMissingInternalURL(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(750 * time.Millisecond):
			http.Error(w, "unreachable", http.StatusServiceUnavailable)
		}
	}))
	defer slow.Close()
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer fast.Close()

	members := map[string]Member{
		"no-url": {NodeID: "no-url", Alive: true},
		"slow":   {NodeID: "slow", Alive: true, InternalURL: "https://slow.internal"},
		"fast":   {NodeID: "fast", Alive: true, InternalURL: "https://fast.internal"},
	}
	var missingURLDialed atomic.Bool
	dial := func(m Member) (*http.Client, string, error) {
		switch m.NodeID {
		case "no-url":
			missingURLDialed.Store(true)
			return nil, "", errors.New("missing URL should have been filtered")
		case "slow":
			return slow.Client(), slow.URL, nil
		default:
			return fast.Client(), fast.URL, nil
		}
	}
	lookup := func(id string) (Member, bool) {
		m, ok := members[id]
		return m, ok
	}
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "sb", SealedPayload: []byte("sealed")}
	started := time.Now()
	acked, err := pushSecretBlobToPeersLookupDialUntil(context.Background(), lookup, nil, dial, "pat", "self", blob, []string{"no-url", "slow", "fast"}, true)
	if err != nil || len(acked) != 1 || acked[0] != "fast" {
		t.Fatalf("first ACK = %v, %v", acked, err)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("first ACK waited behind unreachable peer: %s", elapsed)
	}
	if missingURLDialed.Load() {
		t.Fatal("member without InternalURL entered the dial/ACK race")
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
	var gotIncarnation string
	srv, internalClient := newNodeBoundForwardServer(t, "self", "peer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("method = %s", r.Method)
		}
		gotGen = r.URL.Query().Get("generation")
		gotIncarnation = r.URL.Query().Get("incarnation_id")
		deletes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	members := []Member{{NodeID: "peer", Alive: true, InternalURL: srv.URL}}
	acked, err := deleteSecretOnPeers(context.Background(), members, internalClient, "pat", "self", "sb-del", "inc-del", []string{"peer", "offline"}, 7)
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("delete incomplete error: %v", err)
	}
	if deletes.Load() != 1 {
		t.Fatalf("deletes = %d", deletes.Load())
	}
	if gotGen != "7" {
		t.Fatalf("generation query = %q, want 7", gotGen)
	}
	if gotIncarnation != "inc-del" {
		t.Fatalf("incarnation query = %q, want inc-del", gotIncarnation)
	}
	if len(acked) != 1 || acked[0] != "peer" {
		t.Fatalf("acked = %v", acked)
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

	acked, delErr := deleteSecretOnPeers(
		context.Background(), members, public.Client(), "pat", "self", "sb", "inc-test", []string{"peer"}, 1,
	)
	if delErr == nil {
		t.Fatal("expected delete fail-closed dial error")
	}
	if len(acked) != 0 {
		t.Fatalf("acked=%v", acked)
	}
	holding, probeErr := probeSecretOnPeers(
		context.Background(), members, public.Client(), "pat", "self", "sb", "inc-test", []string{"peer"}, 1,
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
			if got := r.URL.Query().Get("incarnation_id"); got != "inc-test" {
				t.Fatalf("probe incarnation_id = %q", got)
			}
			if got := r.URL.Query().Get("min_generation"); got != "3" {
				t.Fatalf("probe min_generation = %q", got)
			}
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
	acked, err := deleteSecretOnPeersLookup(context.Background(), lookup, internalClient, "pat", "self", "sb", "inc-test", []string{"peer", "missing"}, 3)
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("delete lookup incomplete error: %v", err)
	}
	if deletes.Load() != 1 || len(acked) != 1 || acked[0] != "peer" {
		t.Fatalf("acked=%v deletes=%d", acked, deletes.Load())
	}
	holding, err := probeSecretOnPeersLookup(context.Background(), lookup, internalClient, "pat", "self", "sb", "inc-test", []string{"peer", "missing"}, 3)
	if err != nil {
		t.Fatalf("probe lookup: %v", err)
	}
	if heads.Load() != 1 || len(holding) != 1 || holding[0] != "peer" {
		t.Fatalf("holding=%v heads=%d", holding, heads.Load())
	}
}

func TestClusterAndAgentSecretReplicationWrappers(t *testing.T) {
	var posts, deletes, heads atomic.Int32
	srv, internalClient := newNodeBoundForwardServer(t, "self", "peer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			posts.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			deletes.Add(1)
			w.WriteHeader(http.StatusNotFound) // idempotent delete is an ACK
		case http.MethodHead:
			heads.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("method = %s", r.Method)
		}
	}))
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "peer", Alive: true, InternalURL: srv.URL})
	gossip := &gossipNode{memberIndex: index}
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "sb", Version: 1, SealedPayload: []byte("sealed")}

	for name, pusher := range map[string]SecretPeerPusher{
		"cluster": &Cluster{nodeID: "self", patToken: "pat", internalClient: internalClient, gossip: gossip},
		"agent":   &Agent{nodeID: "self", patToken: "pat", internalClient: internalClient, gossip: gossip},
	} {
		t.Run(name, func(t *testing.T) {
			acked, err := pusher.PushSecretBlobToPeers(context.Background(), blob, []string{"self", "peer"})
			if err != nil || len(acked) != 1 || acked[0] != "peer" {
				t.Fatalf("push acked=%v err=%v", acked, err)
			}
			acked, err = pusher.DeleteSecretOnPeers(context.Background(), "sb", "inc-test", []string{"self", "peer"}, 1)
			if err != nil || len(acked) != 1 {
				t.Fatalf("delete acked=%v err=%v", acked, err)
			}
			holding, err := pusher.ProbeSecretOnPeers(context.Background(), "sb", "inc-test", []string{"self", "peer"}, 1)
			if err != nil || len(holding) != 1 || holding[0] != "peer" {
				t.Fatalf("probe holding=%v err=%v", holding, err)
			}
		})
	}
	if posts.Load() != 2 || deletes.Load() != 2 || heads.Load() != 2 {
		t.Fatalf("posts=%d deletes=%d heads=%d, want 2 each", posts.Load(), deletes.Load(), heads.Load())
	}
}

func TestNilClusterAndAgentSecretReplicationWrappers(t *testing.T) {
	ctx := context.Background()
	recipients := []string{"peer"}
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "sb", Version: 1, SealedPayload: []byte("sealed")}

	for name, pusher := range map[string]SecretPeerPusher{
		"cluster": (*Cluster)(nil),
		"agent":   (*Agent)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			if acked, err := pusher.PushSecretBlobToPeers(ctx, blob, recipients); !errors.Is(err, ErrPeerInternalURLRequired) || len(acked) != 0 {
				t.Fatalf("nil push acked=%v err=%v", acked, err)
			}
			acked, err := pusher.DeleteSecretOnPeers(ctx, "sb", "inc-test", recipients, 1)
			if !errors.Is(err, ErrPeerInternalURLRequired) || len(acked) != 0 {
				t.Fatalf("nil delete acked=%v err=%v", acked, err)
			}
			if holding, err := pusher.ProbeSecretOnPeers(ctx, "sb", "inc-test", recipients, 1); !errors.Is(err, ErrPeerInternalURLRequired) || len(holding) != 0 {
				t.Fatalf("nil probe holding=%v err=%v", holding, err)
			}
		})
	}

	for name, pusher := range map[string]SecretPeerPusher{
		"cluster": &Cluster{nodeID: "self"},
		"agent":   &Agent{nodeID: "self"},
	} {
		t.Run(name+" self-only", func(t *testing.T) {
			if acked, err := pusher.PushSecretBlobToPeers(ctx, blob, []string{"self"}); err != nil || len(acked) != 0 {
				t.Fatalf("self-only push acked=%v err=%v", acked, err)
			}
			if acked, err := pusher.DeleteSecretOnPeers(ctx, "sb", "inc-test", []string{"self"}, 1); err != nil || len(acked) != 0 {
				t.Fatalf("self-only delete acked=%v err=%v", acked, err)
			}
			if holding, err := pusher.ProbeSecretOnPeers(ctx, "sb", "inc-test", []string{"self"}, 1); err != nil || len(holding) != 0 {
				t.Fatalf("self-only probe holding=%v err=%v", holding, err)
			}
		})
	}
}

func TestSecretReplicationInputAndDialFailuresStayPending(t *testing.T) {
	ctx := context.Background()
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "sb", SealedPayload: []byte("sealed")}
	lookup := func(string) (Member, bool) {
		return Member{NodeID: "peer", Alive: true, InternalURL: "https://peer.internal"}, true
	}
	if acked, err := pushSecretBlobToPeersLookupDial(ctx, lookup, nil, nil, "", "self", blob, []string{"peer"}); !errors.Is(err, ErrPeerInternalURLRequired) || len(acked) != 0 {
		t.Fatalf("transportless push acked=%v err=%v", acked, err)
	}
	if acked, err := pushSecretBlobToPeersLookupDial(ctx, nil, nil, nil, "", "self", blob, []string{"peer"}); err != nil || acked != nil {
		t.Fatalf("nil-lookup push acked=%v err=%v", acked, err)
	}
	if acked, err := deleteSecretOnPeersLookupDial(ctx, lookup, nil, nil, "", "self", "sb", "inc-test", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLRequired) || len(acked) != 0 {
		t.Fatalf("transportless delete acked=%v err=%v", acked, err)
	}
	if acked, err := deleteSecretOnPeersLookupDial(ctx, nil, nil, nil, "", "self", "", "inc-test", []string{"peer"}, 1); err != nil || acked != nil {
		t.Fatalf("invalid delete input acked=%v err=%v", acked, err)
	}
	if holding, err := probeSecretOnPeersLookupDial(ctx, lookup, nil, nil, "", "self", "sb", "inc-test", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLRequired) || holding != nil {
		t.Fatalf("transportless probe holding=%v err=%v", holding, err)
	}
	if holding, err := probeSecretOnPeersLookupDial(ctx, nil, nil, nil, "", "self", "", "", []string{"peer"}, 1); err != nil || holding != nil {
		t.Fatalf("invalid probe input holding=%v err=%v", holding, err)
	}

	dialFailure := errors.New("certificate identity mismatch")
	dial := func(Member) (*http.Client, string, error) { return nil, "", dialFailure }
	if acked, err := pushSecretBlobToPeersLookupDial(ctx, lookup, nil, dial, "", "self", blob, []string{"", "self", "peer"}); !errors.Is(err, dialFailure) || len(acked) != 0 {
		t.Fatalf("failed-dial push acked=%v err=%v", acked, err)
	}
	if acked, err := deleteSecretOnPeersLookupDial(ctx, lookup, nil, dial, "", "self", "sb", "inc-test", []string{"", "self", "peer"}, 1); !errors.Is(err, dialFailure) || len(acked) != 0 {
		t.Fatalf("failed-dial delete acked=%v err=%v", acked, err)
	}
	if holding, err := probeSecretOnPeersLookupDial(ctx, lookup, nil, dial, "", "self", "sb", "inc-test", []string{"", "self", "peer"}, 1); !errors.Is(err, dialFailure) || len(holding) != 0 {
		t.Fatalf("failed-dial probe holding=%v err=%v", holding, err)
	}
	if acked, err := deleteSecretOnPeersLookupDial(ctx, lookup, nil, dial, "", "self", "sb", "inc-test", []string{"peer"}, 0); err == nil || len(acked) != 0 {
		t.Fatalf("invalid delete generation acked=%v err=%v", acked, err)
	}
	if holding, err := probeSecretOnPeersLookupDial(ctx, lookup, nil, dial, "", "self", "sb", "inc-test", []string{"peer"}, 0); err == nil || len(holding) != 0 {
		t.Fatalf("invalid probe generation holding=%v err=%v", holding, err)
	}
}

func TestSecretReplicationHTTPStatusAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			http.Error(w, "probe denied", http.StatusForbidden)
		case http.MethodDelete:
			http.Error(w, "delete denied", http.StatusForbidden)
		case http.MethodPost:
			http.Error(w, "push denied", http.StatusForbidden)
		}
	}))
	defer server.Close()
	if ok, err := headSecretBlob(context.Background(), server.Client(), server.URL, "pat", "self"); err == nil || ok {
		t.Fatalf("forbidden HEAD = (%v, %v)", ok, err)
	}
	if err := deleteSecretBlob(context.Background(), server.Client(), server.URL, "pat", "self"); err == nil {
		t.Fatal("forbidden DELETE succeeded")
	}
	if err := postSecretBlob(context.Background(), server.Client(), server.URL, "pat", "self", []byte(`{}`)); err == nil {
		t.Fatal("forbidden POST succeeded")
	}
	if ok, err := headSecretBlob(context.Background(), server.Client(), ":", "", ""); err == nil || ok {
		t.Fatalf("invalid HEAD endpoint = (%v, %v)", ok, err)
	}
	if err := deleteSecretBlob(context.Background(), server.Client(), ":", "", ""); err == nil {
		t.Fatal("invalid DELETE endpoint succeeded")
	}
	if err := postSecretBlob(context.Background(), server.Client(), ":", "", "", nil); err == nil {
		t.Fatal("invalid POST endpoint succeeded")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err := withSecretFanoutBackoff(cancelled, func() error {
		called = true
		return errors.New("should not run")
	})
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("pre-cancelled backoff err=%v called=%v", err, called)
	}
}
