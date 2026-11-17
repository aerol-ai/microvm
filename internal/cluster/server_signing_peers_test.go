package cluster

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// signingPeer answers the signing feed and the two sign calls with keys
// of its own, and counts the sign calls.
func signingPeer(t *testing.T, ca *ClusterCA, nodeID, role string, since int64, signs *atomic.Int32) (string, ed25519.PublicKey) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	feed := SigningKeys{SinceUnixNano: since, TokenKeys: map[uint32][]byte{1 << 31: pub}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case PublicInternalSigningKeysPath:
			_ = json.NewEncoder(w).Encode(feed)
		case PublicInternalSandboxTokenSignPath:
			signs.Add(1)
			_ = json.NewEncoder(w).Encode(SandboxTokenSignResponse{Token: "avmst_" + nodeID})
		case PublicInternalIdentityTokenSignPath:
			signs.Add(1)
			_ = json.NewEncoder(w).Encode(IdentityTokenSignResponse{Token: "jwt-" + nodeID})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return tokenForwardServer(t, ca, nodeID, role, h).URL, pub
}

func signingAgent(base *http.Client, members ...Member) *Agent {
	index := newGossipMemberIndex()
	for _, m := range members {
		index.upsert(m)
	}
	return &Agent{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), nodeID: "wkr-1", internalClient: base,
		gossip: &gossipNode{memberIndex: index}}
}

// The signing feed and the two sign calls go only to a peer whose
// certificate names the server role. A member that only says so in
// gossip (role server, or no role, which counts as one) is skipped for the
// next, and never answers on its own.
func TestSigningCallsGoOnlyToProvenServers(t *testing.T) {
	ca, base := tokenForwardCA(t)
	var workerSigns, serverSigns atomic.Int32
	workerURL, _ := signingPeer(t, ca, "wkr-other", JoinRoleWorker, 1, &workerSigns)
	serverURL, serverPub := signingPeer(t, ca, "srv-1", JoinRoleServer, 7, &serverSigns)
	ctx := context.Background()
	for _, gossiped := range []string{config.NodeRoleServer, ""} {
		other := Member{NodeID: "wkr-other", InternalURL: workerURL, Alive: true, Role: gossiped}
		alone := signingAgent(base, other)
		if got, err := alone.FetchSigningKeys(ctx); err == nil || len(got.TokenKeys) > 0 {
			t.Errorf("gossiped %q: a worker's certificate answered the feed: %+v", gossiped, got)
		}
		if _, err := alone.SignSandboxToken(ctx, SandboxTokenSignRequest{Claims: json.RawMessage(`{}`)}); err == nil {
			t.Errorf("gossiped %q: a sandbox token was signed by a worker's certificate", gossiped)
		}
		if _, err := alone.SignIdentityToken(ctx, IdentityTokenSignRequest{SandboxID: "sb-1"}); err == nil {
			t.Errorf("gossiped %q: an identity token was signed by a worker's certificate", gossiped)
		}
		// With a server too, every call reaches the server, whichever of
		// the two is tried first.
		both := signingAgent(base, other, Member{NodeID: "srv-1", InternalURL: serverURL, Alive: true, Role: config.NodeRoleServer})
		for i := 0; i < 20; i++ {
			got, err := both.FetchSigningKeys(ctx)
			if err != nil || got.SinceUnixNano != 7 || !ed25519.PublicKey(got.TokenKeys[1<<31]).Equal(serverPub) {
				t.Fatalf("gossiped %q: feed = %+v %v", gossiped, got, err)
			}
			if resp, err := both.SignSandboxToken(ctx, SandboxTokenSignRequest{Claims: json.RawMessage(`{}`)}); err != nil || resp.Token != "avmst_srv-1" {
				t.Fatalf("gossiped %q: sign = %+v %v", gossiped, resp, err)
			}
			if resp, err := both.SignIdentityToken(ctx, IdentityTokenSignRequest{SandboxID: "sb-1"}); err != nil || resp.Token != "jwt-srv-1" {
				t.Fatalf("gossiped %q: identity sign = %+v %v", gossiped, resp, err)
			}
		}
	}
	if n := workerSigns.Load(); n != 0 {
		t.Fatalf("%d sign calls reached a worker's certificate", n)
	}
	if serverSigns.Load() == 0 {
		t.Fatal("no sign call reached the server")
	}
	// No internal client, or one with no TLS to pin a server's
	// certificate with: nothing is read, not even from a peer that
	// answers plain HTTP.
	if _, err := signingAgent(nil, Member{NodeID: "srv-1", InternalURL: serverURL, Alive: true, Role: config.NodeRoleServer}).FetchSigningKeys(ctx); err == nil {
		t.Fatal("a feed read went out with no internal client")
	}
	plainPeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(SigningKeys{SinceUnixNano: 3, TokenKeys: map[uint32][]byte{1 << 31: serverPub}})
	}))
	defer plainPeer.Close()
	plain := signingAgent(&http.Client{}, Member{NodeID: "srv-1", InternalURL: plainPeer.URL, Alive: true, Role: config.NodeRoleServer})
	if got, err := plain.FetchSigningKeys(ctx); err == nil || got.SinceUnixNano != 0 {
		t.Fatalf("a feed read over plain HTTP: %+v %v", got, err)
	}
}
