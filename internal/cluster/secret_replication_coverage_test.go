package cluster

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestSecretReplicationNilErrorAndNoDialBranches(t *testing.T) {
	ctx := context.Background()
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "sb", SealedPayload: []byte("sealed")}

	// Dead recipient must stay pending on delete, matching put-outbox semantics.
	members := []Member{{NodeID: "peer", Alive: false, InternalURL: "https://peer.internal"}}
	if acked, err := deleteSecretOnPeers(ctx, members, http.DefaultClient, "pat", "self", "sb", "inc", []string{"peer"}, 1); err == nil || len(acked) != 0 {
		t.Fatalf("dead delete acked=%v err=%v", acked, err)
	}
	if holding, err := probeSecretOnPeers(ctx, members, http.DefaultClient, "pat", "self", "sb", "inc", []string{"peer"}, 1); err != nil || len(holding) != 0 {
		t.Fatalf("dead probe holding=%v err=%v", holding, err)
	}

	// Dial succeeded with no usable client/URL — incomplete, not silent ACK.
	lookup := func(string) (Member, bool) {
		return Member{NodeID: "peer", Alive: true, InternalURL: "https://peer.internal"}, true
	}
	noPath := func(Member) (*http.Client, string, error) { return nil, "", nil }
	if acked, err := pushSecretBlobToPeersLookupDial(ctx, lookup, http.DefaultClient, noPath, "pat", "self", blob, []string{"peer"}); err == nil || len(acked) != 0 {
		t.Fatalf("no-path push acked=%v err=%v", acked, err)
	}
	if acked, err := deleteSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, noPath, "pat", "self", "sb", "inc", []string{"peer"}, 1); err == nil || len(acked) != 0 {
		t.Fatalf("no-path delete acked=%v err=%v", acked, err)
	}
	if holding, err := probeSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, noPath, "pat", "self", "sb", "inc", []string{"peer"}, 1); err != nil || len(holding) != 0 {
		t.Fatalf("no-path probe holding=%v err=%v", holding, err)
	}

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.Method {
		case http.MethodHead:
			if hits == 1 {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case http.MethodPost, http.MethodDelete:
			if hits == 1 {
				http.Error(w, "retry", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)
	dial := func(Member) (*http.Client, string, error) { return srv.Client(), srv.URL, nil }

	holding, err := probeSecretOnPeersLookupDial(ctx, lookup, srv.Client(), dial, "pat", "self", "sb", "inc", []string{"peer"}, 1)
	if err != nil || len(holding) != 1 {
		t.Fatalf("HEAD 200 holding=%v err=%v", holding, err)
	}
	holding, err = probeSecretOnPeersLookupDial(ctx, lookup, srv.Client(), dial, "pat", "self", "sb", "inc", []string{"peer"}, 1)
	if err != nil || len(holding) != 0 {
		t.Fatalf("HEAD 404 holding=%v err=%v", holding, err)
	}

	// First attempt fails so withSecretFanoutBackoff exercises the timer path.
	hits = 0
	if acked, err := pushSecretBlobToPeersLookupDial(ctx, lookup, srv.Client(), dial, "pat", "self", blob, []string{"peer"}); err != nil || len(acked) != 1 {
		t.Fatalf("retry push acked=%v err=%v", acked, err)
	}
	hits = 0
	if acked, err := deleteSecretOnPeersLookupDial(ctx, lookup, srv.Client(), dial, "pat", "self", "sb", "inc", []string{"peer"}, 1); err != nil || len(acked) != 1 {
		t.Fatalf("retry delete acked=%v err=%v", acked, err)
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	attempt := 0
	err = withSecretFanoutBackoff(cancelCtx, func() error {
		attempt++
		cancel()
		return errors.New("force backoff")
	})
	if !errors.Is(err, context.Canceled) || attempt != 1 {
		t.Fatalf("cancel-during-backoff err=%v attempt=%d", err, attempt)
	}

	// Cluster/Agent wrappers go through PeerDialMember, which rejects plaintext.
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "peer", Alive: true, InternalURL: "http://peer.internal"})
	c := &Cluster{nodeID: "self", patToken: "pat", gossip: &gossipNode{memberIndex: index}}
	c.setInternalClient(http.DefaultClient)
	a := &Agent{nodeID: "self", patToken: "pat", internalClient: http.DefaultClient, gossip: &gossipNode{memberIndex: index}}
	if _, err := c.PushSecretBlobToPeers(ctx, blob, []string{"peer"}); !errors.Is(err, ErrPeerInternalURLInvalid) {
		t.Fatalf("cluster plaintext push = %v", err)
	}
	if _, err := a.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLInvalid) {
		t.Fatalf("agent plaintext delete = %v", err)
	}
	if _, err := c.ProbeSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLInvalid) {
		t.Fatalf("cluster plaintext probe = %v", err)
	}
}

func TestLift3SecretWrapperRemainingGuards(t *testing.T) {
	ctx := context.Background()
	blob := secrets.SecretBlob{Ref: "r", SandboxID: "sb", SealedPayload: []byte("sealed")}

	// Gossip-nil Cluster/Agent still distinguish self-only no-ops from remote
	// transport-required errors so outbox retry does not drop a peer copy.
	bare := &Cluster{nodeID: "self"}
	if _, err := bare.PushSecretBlobToPeers(ctx, blob, []string{"peer"}); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("cluster gossip-nil remote push = %v", err)
	}
	if _, err := (*Cluster)(nil).DeleteSecretOnPeers(ctx, "sb", "inc", nil, 1); err != nil {
		t.Fatalf("nil cluster self-only delete: %v", err)
	}
	if _, err := bare.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("cluster gossip-nil remote delete = %v", err)
	}
	if _, err := (*Cluster)(nil).ProbeSecretOnPeers(ctx, "sb", "inc", nil, 1); err != nil {
		t.Fatalf("nil cluster self-only probe: %v", err)
	}
	if _, err := (*Agent)(nil).DeleteSecretOnPeers(ctx, "sb", "inc", nil, 1); err != nil {
		t.Fatalf("nil agent self-only delete: %v", err)
	}
	bareAgent := &Agent{nodeID: "self"}
	if _, err := bareAgent.DeleteSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("agent gossip-nil remote delete = %v", err)
	}
	if _, err := (*Agent)(nil).ProbeSecretOnPeers(ctx, "sb", "inc", nil, 1); err != nil {
		t.Fatalf("nil agent self-only probe: %v", err)
	}
	if _, err := bareAgent.ProbeSecretOnPeers(ctx, "sb", "inc", []string{"peer"}, 1); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("agent gossip-nil remote probe = %v", err)
	}
}

func TestLift3SecretFanoutAndCapacityHTTP(t *testing.T) {
	ctx := context.Background()
	lookup := func(id string) (Member, bool) {
		switch id {
		case "dead":
			return Member{NodeID: "dead", Alive: false}, true
		case "missing":
			return Member{}, false
		case "plain":
			return Member{NodeID: "plain", Alive: true, InternalURL: "http://127.0.0.1:1"}, true
		default:
			return Member{}, false
		}
	}

	if _, err := deleteSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, nil, "", "self", "sb", "", []string{"dead"}, 1); err == nil {
		t.Fatal("delete empty incarnation")
	}
	if _, err := deleteSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, nil, "", "self", "sb", "inc", []string{"dead"}, 0); err == nil {
		t.Fatal("delete non-positive generation")
	}
	if _, err := probeSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, nil, "", "self", "sb", "", []string{"dead"}, 1); err == nil {
		t.Fatal("probe empty incarnation")
	}
	if _, err := pushSecretBlobToPeersLookupDial(ctx, lookup, http.DefaultClient, nil, "", "self", secrets.SecretBlob{Ref: "r"}, []string{"missing", "dead"}); err == nil {
		t.Fatal("push missing/dead")
	}
	if _, err := deleteSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, nil, "", "self", "sb", "inc", []string{"missing", "dead"}, 1); err == nil {
		t.Fatal("delete missing/dead")
	}
	if _, err := probeSecretOnPeersLookupDial(ctx, lookup, http.DefaultClient, nil, "", "self", "sb", "inc", []string{"dead"}, 1); err != nil {
		t.Fatalf("probe dead is skip, not error: %v", err)
	}

	failDial := func(Member) (*http.Client, string, error) { return nil, "", errors.New("dial") }
	if _, err := pushSecretBlobToPeersLookupDial(ctx, lookup, nil, failDial, "", "self", secrets.SecretBlob{Ref: "r"}, []string{"plain"}); err == nil {
		t.Fatal("push dial fail")
	}
	if _, err := deleteSecretOnPeersLookupDial(ctx, lookup, nil, failDial, "", "self", "sb", "inc", []string{"plain"}, 1); err == nil {
		t.Fatal("delete dial fail")
	}
	if _, err := probeSecretOnPeersLookupDial(ctx, lookup, nil, failDial, "", "self", "sb", "inc", []string{"plain"}, 1); err == nil {
		t.Fatal("probe dial fail")
	}

	if _, err := headSecretBlob(ctx, http.DefaultClient, "http://127.0.0.1:1", "pat", "self"); err == nil {
		t.Fatal("head dial")
	}
	if err := postSecretBlob(ctx, http.DefaultClient, "http://127.0.0.1:1", "pat", "self", []byte("{}")); err == nil {
		t.Fatal("post dial")
	}
	if err := deleteSecretBlob(ctx, http.DefaultClient, "http://127.0.0.1:1", "pat", "self"); err == nil {
		t.Fatal("delete dial")
	}
	if _, err := headSecretBlob(ctx, http.DefaultClient, "http://%zz", "", ""); err == nil {
		t.Fatal("head bad URL")
	}
	if err := postSecretBlob(ctx, http.DefaultClient, "http://%zz", "", "", nil); err == nil {
		t.Fatal("post bad URL")
	}
	if err := deleteSecretBlob(ctx, http.DefaultClient, "http://%zz", "", ""); err == nil {
		t.Fatal("delete bad URL")
	}

	if _, err := fetchCapacitySnapshot(ctx, http.DefaultClient, "http://%zz", "pat"); err == nil {
		t.Fatal("capacity bad URL")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pat" {
			http.Error(w, "no pat", http.StatusUnauthorized)
			return
		}
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(bad.Close)
	if _, err := fetchCapacitySnapshot(ctx, bad.Client(), bad.URL, "pat"); err == nil {
		t.Fatal("capacity 500")
	}
	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{not-json")
	}))
	t.Cleanup(junk.Close)
	if _, err := fetchCapacitySnapshot(ctx, junk.Client(), junk.URL, ""); err == nil {
		t.Fatal("capacity decode")
	}
}
