package cluster

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

// roleLessPeer serves h with a certificate like cluster-sign-node.sh's:
// node:<id>, no role.
func roleLessPeer(t *testing.T, ca *ClusterCA, nodeID string, h http.Handler) string {
	t.Helper()
	key, keyPEM, err := NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: nodeID},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames: []string{clusterServerName, "node:" + nodeID},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tokenForwardTLS(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, h).URL
}

// In a cluster whose servers' certificates name no role (made before
// roles), no server can sign, so the feed answers that servers do not
// sign, and tokens are signed as before. Once one server proves its role,
// the feed is its answer; a member whose certificate names another role
// is not one that names none.
func TestRoleLessServersAnswerThatServersDoNotSign(t *testing.T) {
	ca, base := tokenForwardCA(t)
	feed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(SigningKeys{SinceUnixNano: 99})
	})
	old1, old2 := roleLessPeer(t, ca, "srv-1", feed), roleLessPeer(t, ca, "srv-2", feed)
	var signs atomic.Int32
	roleURL, rolePub := signingPeer(t, ca, "srv-3", JoinRoleServer, 7, &signs)
	workerURL, _ := signingPeer(t, ca, "wkr-other", JoinRoleWorker, 1, &signs)
	ctx := context.Background()
	server := func(id, url string) Member {
		return Member{NodeID: id, InternalURL: url, Alive: true, Role: config.NodeRoleServer}
	}

	// Every server's certificate names no role: no record, as before.
	roleLess := signingAgent(base, server("srv-1", old1), server("srv-2", old2))
	got, err := roleLess.FetchSigningKeys(ctx)
	if err != nil || got.SinceUnixNano != 0 || len(got.TokenKeys) != 0 {
		t.Fatalf("role-less servers: %+v %v", got, err)
	}
	if _, err := roleLess.SignSandboxToken(ctx, SandboxTokenSignRequest{Claims: json.RawMessage(`{}`)}); !errors.Is(err, ErrServersNameNoRole) {
		t.Fatalf("a sign call to role-less servers = %v", err)
	}
	// Mixed: a server that proves its role answers, whichever is tried first.
	mixed := signingAgent(base, server("srv-1", old1), server("srv-3", roleURL))
	for i := 0; i < 20; i++ {
		got, err := mixed.FetchSigningKeys(ctx)
		if err != nil || got.SinceUnixNano != 7 || !ed25519.PublicKey(got.TokenKeys[1<<31]).Equal(rolePub) {
			t.Fatalf("mixed servers: %+v %v", got, err)
		}
	}
	// A role-less server beside a member whose certificate names another
	// role, or one that cannot be reached: not every server names none.
	for name, other := range map[string]Member{
		"a worker's certificate": server("wkr-other", workerURL),
		"no answer":              server("srv-9", "https://127.0.0.1:1"),
	} {
		a := signingAgent(base, server("srv-1", old1), other)
		if got, err := a.FetchSigningKeys(ctx); err == nil || errors.Is(err, ErrServersNameNoRole) {
			t.Errorf("%s: %+v %v", name, got, err)
		}
	}
	if n := signs.Load(); n != 0 {
		t.Fatalf("%d sign calls answered", n)
	}
}

// An upgrade with no rollout moves the active version only once every
// live member reports the new build. One that does not is named, the gate
// says it is held, the gauge and its alert fire, and the operator may
// start server signing anyway, since every server runs the build.
func TestAMemberOnAnOlderBuildIsNamedAndSigningCanStart(t *testing.T) {
	c, cleanup := newTestCluster(t, "ldr-older", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	c.selfCertRole = func() string { return JoinRoleServer }
	setActive(t, c, 1, serverSigningFSMOpsVersion-1, 0, "")
	self := c.gossip.selfMember()
	self.FSMOpsVersion, self.Alive = fsmOpsVersion, true
	older := recreateCandidate("wkr-older", "worker", 10)
	older.FSMOpsVersion = serverSigningFSMOpsVersion - 1
	seedGossipView(t, c, []Member{self, older})
	c.reconcileActiveVersion(context.Background())
	if fv := c.fsm.activeFVValue(); fv != serverSigningFSMOpsVersion-1 {
		t.Fatalf("the active version moved to %d past a member on an older build", fv)
	}
	c.refreshServerSigningGauges()
	g := c.ServerSigningGate(false)
	if g.Allowed || !g.Held() || serverSigningHeld.Value() != 1 || len(g.Waiting) != 1 || g.Waiting[0] != "wkr-older" || !strings.Contains(g.Reason, "wkr-older") {
		t.Fatalf("held: %+v gauge %d", g, serverSigningHeld.Value())
	}
	rec, err := c.WriteServerSigning(context.Background(), ServerSigningWrite{Signing: ServerSigning{Sealed: []byte("s"), SinceUnixNano: time.Now().Add(time.Minute).UnixNano()}}, true)
	if err != nil || string(rec.Sealed) != "s" {
		t.Fatalf("the operator's start: %+v %v", rec, err)
	}
	c.refreshServerSigningGauges()
	if serverSigningOn.Value() != 1 || serverSigningHeld.Value() != 0 {
		t.Fatalf("after the start: on %d held %d", serverSigningOn.Value(), serverSigningHeld.Value())
	}
}

// A server that answers 503 (cut off from the leader) is passed over for
// the next one.
func TestSigningFeedPassesOverACutOffServer(t *testing.T) {
	ca, base := tokenForwardCA(t)
	cutOff := tokenForwardServer(t, ca, "srv-1", JoinRoleServer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, ErrStalePlacementView.Error(), http.StatusServiceUnavailable)
	})).URL
	var signs atomic.Int32
	liveURL, _ := signingPeer(t, ca, "srv-2", JoinRoleServer, 7, &signs)
	a := signingAgent(base, Member{NodeID: "srv-1", InternalURL: cutOff, Alive: true, Role: config.NodeRoleServer},
		Member{NodeID: "srv-2", InternalURL: liveURL, Alive: true, Role: config.NodeRoleServer})
	for i := 0; i < 10; i++ {
		if got, err := a.FetchSigningKeys(context.Background()); err != nil || got.SinceUnixNano != 7 {
			t.Fatalf("feed past a cut-off server: %+v %v", got, err)
		}
	}
	alone := signingAgent(base, Member{NodeID: "srv-1", InternalURL: cutOff, Alive: true, Role: config.NodeRoleServer})
	if _, err := alone.FetchSigningKeys(context.Background()); err == nil {
		t.Fatal("a cut-off server's 503 read as an answer")
	}
}
