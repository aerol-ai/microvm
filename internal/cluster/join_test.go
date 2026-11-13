package cluster

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/testport"
	"github.com/aerol-ai/microvm/internal/version"
)

// End-to-end tests of the join service on real single- and two-node
// clusters: the join port, the one-winner rule under concurrency, the
// dial-back, role binding, adopt, renewal and the tombstone on internal
// calls.

// writeSharedCAStore writes the shared test CA (the one
// writeTestClusterTLSDir signs node certs with) into a CA store.
func writeSharedCAStore(t *testing.T) string {
	t.Helper()
	sharedTestCAOnce.Do(initSharedTestCA)
	dir := filepath.Join(t.TempDir(), "cluster-ca")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(sharedTestCAKey)})
	ca, err := ParseClusterCA(sharedTestCAPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveClusterCA(dir, ca); err != nil {
		t.Fatal(err)
	}
	return dir
}

func sharedCAKeyPEM(t *testing.T) []byte {
	t.Helper()
	sharedTestCAOnce.Do(initSharedTestCA)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(sharedTestCAKey)})
}

type joinClusterOpts struct {
	role     string
	caDir    string // "" = no CA store
	joinAddr string // "" = no join listener
	mutate   func(*config.Config)
}

// newJoinTestCluster builds a server node with the join service's settings
// and a test internal handler standing in for pkg/api/v1's join routes.
func newJoinTestCluster(t *testing.T, nodeID string, bootstrap bool, peers []string, o joinClusterOpts) (*Cluster, func()) {
	t.Helper()
	testClusterMu.Lock()
	dir := t.TempDir()
	cfg := config.Config{
		EnableCluster:                 true,
		NodeID:                        nodeID,
		NodeRole:                      o.role,
		RaftBindAddr:                  "127.0.0.1:0",
		RaftAdvertiseAddr:             "127.0.0.1:0",
		RaftDataDir:                   filepath.Join(dir, "raft"),
		GossipBindAddr:                "127.0.0.1:0",
		GossipAdvertiseAddr:           "127.0.0.1:0",
		BootstrapPeers:                peers,
		ClusterBootstrap:              bootstrap,
		SelfAPIAdvertiseURL:           fmt.Sprintf("http://127.0.0.1:%d", pickFreeTCPPort(t)),
		ClusterRaftCommitTimeout:      2 * time.Second,
		ClusterCapacityGossipInterval: time.Second,
		ClusterTLSDir:                 writeTestClusterTLSDir(t, nodeID),
		ClusterInternalListenAddr:     "127.0.0.1:0",
		ClusterJoinListenAddr:         o.joinAddr,
		ClusterCADir:                  o.caDir,
		ClusterGossipSecretKey:        "",
		CredentialEncryptionKeyPath:   filepath.Join(dir, "credential_encryption.key"),
		CredentialKeyCustody:          "file",
	}
	if o.mutate != nil {
		o.mutate(&cfg)
	}
	c, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	testClusterMu.Unlock()
	if err != nil {
		t.Fatalf("cluster.New(%s): %v", nodeID, err)
	}
	c.AttachInternalHandler(joinTestHandler(c))
	return c, func() {
		testClusterMu.Lock()
		defer testClusterMu.Unlock()
		_ = c.Close()
		time.Sleep(50 * time.Millisecond)
	}
}

// joinTestHandler mirrors pkg/api/v1's three internal join routes.
func joinTestHandler(c *Cluster) http.Handler {
	mux := http.NewServeMux()
	writeErr := func(w http.ResponseWriter, err error) {
		w.WriteHeader(JoinErrorStatus(err))
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
	}
	mux.HandleFunc("POST "+PublicInternalJoinWritePath, func(w http.ResponseWriter, r *http.Request) {
		peer, err := AuthenticatedPeerNodeID(r)
		if err != nil || !c.IsJoinWritePeer(peer) {
			writeErr(w, ErrPeerNotServer)
			return
		}
		var req JoinWriteRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp, err := c.WriteJoin(r.Context(), req)
		if err != nil {
			if out := JoinWriteOutcome(err); out.Code != "" {
				_ = json.NewEncoder(w).Encode(out)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("POST "+PublicInternalCAKeyPath, func(w http.ResponseWriter, r *http.Request) {
		peer, _ := AuthenticatedPeerNodeID(r)
		resp, err := c.CAKeyForPeer(peer)
		if err != nil {
			writeErr(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("POST "+PublicInternalRenewCertPath, func(w http.ResponseWriter, r *http.Request) {
		peer, _ := AuthenticatedPeerNodeID(r)
		var req RenewCertRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp, err := c.RenewNodeCert(r.Context(), peer, r.TLS.PeerCertificates[0], []byte(req.CSR))
		if err != nil {
			writeErr(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}

// dialBackListeners opens n TCP listeners on 127.0.0.1 that accept and
// close, and returns their ports.
func dialBackListeners(t *testing.T, n int) []int {
	t.Helper()
	var ports []int
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	return ports
}

// closedPort is a port nothing listens on, for the "unreachable" cases. A
// ":0" pick would be an ephemeral port, which an outgoing connection could
// be using by the time the preflight dials it; below the ephemeral range
// nothing binds a port by itself, so it stays closed.
func closedPort(t *testing.T) int {
	t.Helper()
	return testport.Reserve(t, false)
}

// joinClient talks to a join port as a new machine does before it trusts
// anything: no client cert, server cert not yet verified.
func joinClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // a joiner checks the CA by HMAC, not by chain
}

func joinPost(t *testing.T, base, path string, body any) (int, []byte) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := joinClient().Post(base+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func joinGet(t *testing.T, base, path string) (int, []byte) {
	t.Helper()
	resp, err := joinClient().Get(base + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func newCSR(t *testing.T, nodeID string) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, _, err := NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := NewNodeCSR(key, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(csr)
}

type auditCapture struct {
	mu     sync.Mutex
	events []JoinAuditEvent
}

func (a *auditCapture) RecordClusterJoin(ev JoinAuditEvent) {
	a.mu.Lock()
	a.events = append(a.events, ev)
	a.mu.Unlock()
}

func (a *auditCapture) snapshot() []JoinAuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]JoinAuditEvent(nil), a.events...)
}

// recreatorWithAudit is a SandboxRecreator that also records joins.
type recreatorWithAudit struct {
	SandboxRecreator
	*auditCapture
}

func TestJoinPortEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newJoinTestCluster(t, "join-seed", true, nil, joinClusterOpts{caDir: writeSharedCAStore(t), joinAddr: "127.0.0.1:0"})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	audit := &auditCapture{}
	leader.AttachRecreator(recreatorWithAudit{auditCapture: audit})
	if err := os.WriteFile(leader.cfg.CredentialEncryptionKeyPath, []byte("c2VjcmV0LWtleQ==\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	base := "https://" + leader.joinServer.Addr()
	// This test makes more calls from 127.0.0.1 than one burst allows.
	leader.joinServer.limiter.burst = 1000

	created, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleWorker, CreatedBy: "operator:alice"})
	if err != nil {
		t.Fatal(err)
	}
	if created.ExpiresAt == nil || time.Until(*created.ExpiresAt) > DefaultJoinTokenTTL || created.CACertHash != leader.clusterID() || len(created.JoinURLs) == 0 {
		t.Fatalf("created = %+v", created)
	}
	if !strings.HasSuffix(created.JoinURLs[0], fmt.Sprintf(":%d", leader.joinAdvertisePort)) {
		t.Fatalf("join URL %q does not name the join port %d", created.JoinURLs[0], leader.joinAdvertisePort)
	}

	// The join port presents this server's node cert, chained to the CA the
	// token's discovery check vouches for, and asks for no client cert.
	conn, err := tls.Dial("tcp", leader.joinServer.Addr(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // inspecting the served chain
	if err != nil {
		t.Fatalf("handshake without a client cert: %v", err)
	}
	served := conn.ConnectionState().PeerCertificates[0]
	_ = conn.Close()
	if ExtractPeerNodeID(served) != "join-seed" || served.CheckSignatureFrom(sharedTestCACert) != nil {
		t.Fatalf("join port served %v", served.DNSNames)
	}

	// cluster-info: the CA and MACs that only the token can check.
	code, body := joinGet(t, base, JoinClusterInfoPath+"?token_id="+created.ID)
	var info ClusterInfo
	if code != http.StatusOK || json.Unmarshal(body, &info) != nil {
		t.Fatalf("cluster-info = %d %s", code, body)
	}
	if !VerifyClusterInfo(created.Token, info) || info.Version != version.Version || info.ClusterID != created.CACertHash {
		t.Fatalf("cluster-info failed its own check: %+v", info)
	}
	wrong, _ := GenerateJoinToken()
	if VerifyClusterInfo(wrong, info) {
		t.Fatal("cluster-info passed a wrong token's check")
	}
	tampered := info
	tampered.Version = "v0.0.1"
	if VerifyClusterInfo(created.Token, tampered) {
		t.Fatal("a swapped version passed the info MAC")
	}
	for _, q := range []string{"?token_id=zzzzzz", "?token_id=BAD", ""} {
		if code, _ := joinGet(t, base, JoinClusterInfoPath+q); code == http.StatusOK {
			t.Fatalf("cluster-info%s answered 200", q)
		}
	}

	// Only the three join paths exist on the join port.
	for _, p := range []string{"/internal/apply", "/v1/cluster/members", "/v1/cluster/join-tokens", "/health", "/v1/join/other"} {
		if code, _ := joinGet(t, base, p); code != http.StatusNotFound {
			t.Fatalf("GET %s on the join port = %d, want 404", p, code)
		}
	}

	ports := dialBackListeners(t, 3)
	jp := &JoinPorts{Raft: ports[0], Gossip: ports[1], Internal: ports[2]}

	// Preflight checks the token and dials back, using nothing up.
	code, body = joinPost(t, base, JoinPreflightPath, PreflightRequest{Token: created.Token, Ports: jp})
	var pre PreflightResponse
	if code != http.StatusOK || json.Unmarshal(body, &pre) != nil || !pre.OK || len(pre.DialBack) != 2 || pre.Role != JoinRoleWorker {
		t.Fatalf("preflight = %d %s", code, body)
	}
	code, body = joinPost(t, base, JoinPreflightPath, PreflightRequest{Token: created.Token, Ports: &JoinPorts{Gossip: closedPort(t), Internal: ports[2]}})
	if json.Unmarshal(body, &pre) != nil || code != http.StatusOK || pre.OK {
		t.Fatalf("preflight to a closed port = %d %s", code, body)
	}
	if code, _ := joinPost(t, base, JoinPreflightPath, PreflightRequest{Token: wrong}); code != http.StatusForbidden {
		t.Fatalf("preflight with a wrong token = %d", code)
	}

	// A join whose dial-back fails signs nothing and leaves the token unused.
	_, csr := newCSR(t, "wkr-a")
	code, body = joinPost(t, base, JoinPath, JoinRequest{Token: created.Token, NodeID: "wkr-a", CSR: csr, Version: version.Version, Ports: &JoinPorts{Gossip: closedPort(t), Internal: ports[2]}})
	var refusal joinErrorBody
	if code != http.StatusPreconditionFailed || json.Unmarshal(body, &refusal) != nil || refusal.Reason != "dial_back" || len(refusal.DialBack) != 2 {
		t.Fatalf("join with a closed port = %d %s", code, body)
	}
	if tok, _ := leader.fsm.joinToken(created.ID); len(tok.UsedBy) != 0 {
		t.Fatalf("failed dial-back used the token: %+v", tok.UsedBy)
	}
	// A build that may not join is refused before anything is used.
	code, _ = joinPost(t, base, JoinPath, JoinRequest{Token: created.Token, NodeID: "wkr-a", CSR: csr, Version: "v0.0.0-ancient", Ports: jp})
	if code != http.StatusPreconditionFailed {
		t.Fatalf("join from a stale build = %d", code)
	}

	// The real join.
	code, body = joinPost(t, base, JoinPath, JoinRequest{Token: created.Token, NodeID: "wkr-a", CSR: csr, Version: version.Version, Ports: jp})
	var joined JoinResponse
	if code != http.StatusOK || json.Unmarshal(body, &joined) != nil {
		t.Fatalf("join = %d %s", code, body)
	}
	leaf, err := firstPEMCertificate([]byte(joined.NodeCert))
	if err != nil || ExtractPeerNodeID(leaf) != "wkr-a" || ExtractPeerRole(leaf) != JoinRoleWorker || leaf.CheckSignatureFrom(sharedTestCACert) != nil {
		t.Fatalf("joined cert = %v %v", leaf, err)
	}
	if joined.CAKey != "" {
		t.Fatal("a worker's join answer carried the CA key")
	}
	if joined.Credentials.Custody != "file" || joined.Credentials.Key == "" || joined.ClusterID != created.CACertHash || len(joined.BootstrapPeers) == 0 || joined.Replay {
		t.Fatalf("join answer = %+v", joined)
	}
	if rec, ok := leader.AdmittedNode("wkr-a"); !ok || rec.KeyHash != CertKeyHash(leaf) || rec.Role != JoinRoleWorker {
		t.Fatalf("admitted = %+v %v", rec, ok)
	}

	// Safe to retry: the same key and node ID get the same answer.
	code, body = joinPost(t, base, JoinPath, JoinRequest{Token: created.Token, NodeID: "wkr-a", CSR: csr, Version: version.Version, Ports: jp})
	if code != http.StatusOK || json.Unmarshal(body, &joined) != nil || !joined.Replay {
		t.Fatalf("retry = %d %s", code, body)
	}
	// Anything else on a used single-use token is refused.
	_, csr2 := newCSR(t, "wkr-b")
	if code, body := joinPost(t, base, JoinPath, JoinRequest{Token: created.Token, NodeID: "wkr-b", CSR: csr2, Version: version.Version, Ports: jp}); code != http.StatusForbidden {
		t.Fatalf("second node on a single-use token = %d %s", code, body)
	}
	if code, body := joinPost(t, base, JoinPath, JoinRequest{Token: created.Token, NodeID: "wkr-a", Role: JoinRoleServer, CSR: csr, Version: version.Version, Ports: jp}); code != http.StatusForbidden || !strings.Contains(string(body), "role") {
		t.Fatalf("role escalation = %d %s", code, body)
	}

	// A server token's answer carries the CA key (D5).
	srvTok, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleServer, TTL: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	_, csr3 := newCSR(t, "srv-b")
	code, body = joinPost(t, base, JoinPath, JoinRequest{Token: srvTok.Token, NodeID: "srv-b", CSR: csr3, Version: version.Version, Ports: jp})
	if code != http.StatusOK || json.Unmarshal(body, &joined) != nil || joined.CAKey == "" || joined.Role != JoinRoleServer || len(joined.DialBack) != 3 {
		t.Fatalf("server join = %d %s", code, body)
	}
	if _, err := ParseClusterCA([]byte(joined.CACert), []byte(joined.CAKey)); err != nil {
		t.Fatalf("server join CA key does not match: %v", err)
	}

	// Bad bodies.
	for name, req := range map[string]JoinRequest{
		"bad node id": {Token: srvTok.Token, NodeID: "bad id!", CSR: csr3, Version: version.Version},
		"bad csr":     {Token: srvTok.Token, NodeID: "srv-c", CSR: "nope", Version: version.Version},
		"bad port":    {Token: srvTok.Token, NodeID: "srv-c", CSR: csr3, Version: version.Version, Ports: &JoinPorts{Raft: 70000}},
		"bad token":   {Token: "garbage", NodeID: "srv-c", CSR: csr3, Version: version.Version},
	} {
		if code, body := joinPost(t, base, JoinPath, req); code < 400 || code > 403 {
			t.Fatalf("%s = %d %s", name, code, body)
		}
	}
	resp, err := joinClient().Post(base+JoinPath, "application/json", strings.NewReader("{"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("broken JSON = %d", resp.StatusCode)
	}
	resp, err = joinClient().Post(base+JoinPreflightPath, "application/json", strings.NewReader("{"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("broken preflight JSON = %d", resp.StatusCode)
	}

	// Every call that passed the limiter was audited, never with a secret.
	events := audit.snapshot()
	var success, failure int
	for _, ev := range events {
		if strings.Contains(fmt.Sprintf("%+v", ev), strings.SplitN(created.Token, ".", 2)[1]) {
			t.Fatal("an audit record carried a token secret")
		}
		switch ev.Result {
		case "success":
			success++
		case "failure":
			failure++
		}
	}
	if success < 4 || failure < 8 {
		t.Fatalf("audit = %d success, %d failure: %+v", success, failure, events)
	}
	if got := joinAttempts.Get("success").String(); !strings.Contains(got, "\"ok\"") || !strings.Contains(got, "\"replay\"") {
		t.Fatalf("join attempt metric = %s", got)
	}

	// List and revoke.
	list, err := leader.ListJoinTokens(ctx)
	if err != nil || len(list.Tokens) != 2 {
		t.Fatalf("list = %+v %v", list, err)
	}
	for _, tok := range list.Tokens {
		if tok.ID == created.ID && (len(tok.UsedBy) != 1 || tok.UsedBy[0].NodeID != "wkr-a" || tok.CreatedBy != "operator:alice") {
			t.Fatalf("listed token = %+v", tok)
		}
	}
	if err := leader.RevokeJoinToken(ctx, srvTok.ID); err != nil {
		t.Fatal(err)
	}
	if err := leader.RevokeJoinToken(ctx, srvTok.ID); err != nil {
		t.Fatalf("second revoke = %v", err)
	}
	if err := leader.RevokeJoinToken(ctx, "BAD"); !errors.Is(err, ErrJoinBadRequest) {
		t.Fatalf("revoke bad id = %v", err)
	}
	if code, _ := joinGet(t, base, JoinClusterInfoPath+"?token_id="+srvTok.ID); code != http.StatusForbidden {
		t.Fatalf("cluster-info for a revoked token = %d", code)
	}
}

// Exactly one of two concurrent joins for one node ID wins (§4, T10).
func TestJoinOneWinnerPerNodeIDConcurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newJoinTestCluster(t, "race-seed", true, nil, joinClusterOpts{caDir: writeSharedCAStore(t)})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	ports := dialBackListeners(t, 2)
	jp := &JoinPorts{Gossip: ports[0], Internal: ports[1]}
	const racers = 6
	tokens := make([]string, racers)
	for i := range tokens {
		created, err := leader.CreateJoinToken(context.Background(), JoinTokenCreateRequest{Role: JoinRoleWorker})
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = created.Token
	}
	var wins, inUse atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(token string) {
			defer wg.Done()
			_, csr := newCSR(t, "contested")
			<-start
			_, err := leader.Join(context.Background(), JoinRequest{Token: token, NodeID: "contested", CSR: csr, Version: version.Version, Ports: jp}, netip.MustParseAddr("127.0.0.1"))
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrNodeIDInUse):
				inUse.Add(1)
			default:
				t.Errorf("join: %v", err)
			}
		}(tokens[i])
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || inUse.Load() != racers-1 {
		t.Fatalf("%d winners, %d refused with ErrNodeIDInUse", wins.Load(), inUse.Load())
	}
}

func TestJoinRefusesLiveMemberAndNoSigner(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newJoinTestCluster(t, "live-seed", true, nil, joinClusterOpts{})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	created, err := leader.CreateJoinToken(context.Background(), JoinTokenCreateRequest{Role: JoinRoleServer, TTL: "30m"})
	if err != nil {
		t.Fatal(err)
	}
	_, csr := newCSR(t, "x")
	src := netip.MustParseAddr("127.0.0.1")
	// No CA key on this server: refused before the token is used.
	if _, err := leader.Join(context.Background(), JoinRequest{Token: created.Token, NodeID: "new-1", CSR: csr, Version: version.Version}, src); !errors.Is(err, ErrNoCASigner) {
		t.Fatalf("join without a signer = %v", err)
	}
	if tok, _ := leader.fsm.joinToken(created.ID); len(tok.UsedBy) != 0 {
		t.Fatal("token used without a signature")
	}
	// The live member's own ID is taken.
	if _, err := leader.WriteJoin(context.Background(), JoinWriteRequest{Kind: joinWriteAdmit, Admit: &JoinAdmitCommand{
		TokenID: created.ID, NodeID: "live-seed", Role: JoinRoleServer, KeyHash: testKey("other"),
	}}); !errors.Is(err, ErrNodeIDInUse) {
		t.Fatalf("join over a live member = %v", err)
	}
	for _, bad := range []JoinWriteRequest{{Kind: "nope"}, {Kind: joinWriteAdmit}} {
		if _, err := leader.WriteJoin(context.Background(), bad); !errors.Is(err, ErrJoinBadRequest) {
			t.Fatalf("bad write %+v = %v", bad, err)
		}
	}
	var none *Cluster
	if _, err := none.WriteJoin(context.Background(), JoinWriteRequest{}); err == nil {
		t.Fatal("nil cluster wrote")
	}
}

func TestJoinTokenTTLRules(t *testing.T) {
	cases := []struct {
		name       string
		role, ttl  string
		enterprise bool
		custody    string
		wantTTL    time.Duration
		wantErr    error
		warn       bool
	}{
		{"default", JoinRoleWorker, "", false, "file", DefaultJoinTokenTTL, nil, false},
		{"server 24h", JoinRoleServer, "24h", false, "file", 24 * time.Hour, nil, false},
		{"server over 24h", JoinRoleServer, "25h", false, "file", 0, ErrJoinTTLInvalid, false},
		{"server never", JoinRoleServer, "0", false, "file", 0, ErrJoinTTLInvalid, false},
		{"worker never", JoinRoleWorker, "0", false, "file", 0, nil, true},
		{"ingress never", JoinRoleIngress, "0s", false, "file", 0, nil, true},
		{"enterprise never, file custody", JoinRoleWorker, "0", true, "file", 0, ErrJoinTTLNeedsWrappedCustody, false},
		{"enterprise never, wrapped custody", JoinRoleWorker, "0", true, "wrapped", 0, nil, true},
		{"enterprise 2h, file custody", JoinRoleWorker, "2h", true, "file", 2 * time.Hour, nil, false},
		{"worker 30d", JoinRoleWorker, "720h", false, "file", 720 * time.Hour, nil, false},
		{"negative", JoinRoleWorker, "-1h", false, "file", 0, ErrJoinTTLInvalid, false},
		{"garbage", JoinRoleWorker, "soon", false, "file", 0, ErrJoinTTLInvalid, false},
		{"too short", JoinRoleWorker, "10s", false, "file", 0, ErrJoinTTLInvalid, false},
	}
	for _, tc := range cases {
		c := &Cluster{cfg: config.Config{EnterpriseMode: tc.enterprise, CredentialKeyCustody: tc.custody}}
		ttl, warning, err := c.validateJoinTokenTTL(tc.role, tc.ttl)
		if !errors.Is(err, tc.wantErr) || (err == nil && ttl != tc.wantTTL) || (warning != "") != tc.warn {
			t.Fatalf("%s: ttl %s warning %q err %v", tc.name, ttl, warning, err)
		}
	}
	// The create path applies the same rules before any write.
	c := &Cluster{cfg: config.Config{EnterpriseMode: true, CredentialKeyCustody: "file"}}
	if _, err := c.CreateJoinToken(context.Background(), JoinTokenCreateRequest{Role: JoinRoleWorker, TTL: "0"}); !errors.Is(err, ErrJoinTTLNeedsWrappedCustody) {
		t.Fatalf("enterprise ttl 0 create = %v", err)
	}
	if _, err := c.CreateJoinToken(context.Background(), JoinTokenCreateRequest{Role: "boss"}); !errors.Is(err, ErrJoinBadRequest) {
		t.Fatalf("bad role create = %v", err)
	}
}

// The dial-back dials only the call's source IP, on the role's ports, and
// gives up on each port after joinDialTimeout.
func TestJoinDialBackSourceIPOnlyAndTimeouts(t *testing.T) {
	old := joinDialTimeout
	joinDialTimeout = 150 * time.Millisecond
	defer func() { joinDialTimeout = old }()
	var mu sync.Mutex
	var dialed []string
	hang := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ports, err := dialBackPorts(JoinRoleServer, &JoinPorts{Gossip: 17001})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	results, ok := dialBack(context.Background(), hang, netip.MustParseAddr("::ffff:10.1.2.3"), ports)
	took := time.Since(start)
	if ok || len(results) != 3 {
		t.Fatalf("results = %+v ok %v", results, ok)
	}
	// In parallel: three hung ports cost one timeout, not three.
	if took < joinDialTimeout || took > 3*joinDialTimeout {
		t.Fatalf("dial-back took %s with a %s timeout per port", took, joinDialTimeout)
	}
	mu.Lock()
	defer mu.Unlock()
	want := map[string]bool{"10.1.2.3:7000": true, "10.1.2.3:17001": true, "10.1.2.3:7002": true}
	for _, addr := range dialed {
		if !want[addr] {
			t.Fatalf("dialed %s; only the source IP on the role's ports is allowed", addr)
		}
		delete(want, addr)
	}
	if len(want) != 0 {
		t.Fatalf("never dialed %v", want)
	}
	for _, r := range results {
		if r.OK || r.Error == "" {
			t.Fatalf("hung port reported %+v", r)
		}
	}
	// Workers are not dialed on the Raft port.
	if wp, _ := dialBackPorts(JoinRoleWorker, nil); len(wp) != 2 || wp[0].Name != "gossip" || wp[1].Port != DefaultInternalPort {
		t.Fatalf("worker ports = %+v", wp)
	}
	if _, err := dialBackPorts(JoinRoleWorker, &JoinPorts{Internal: -1}); !errors.Is(err, ErrJoinBadRequest) {
		t.Fatalf("negative port = %v", err)
	}
	// The default dialer reaches a real listener.
	live := dialBackListeners(t, 1)
	if res, ok := dialBack(context.Background(), nil, netip.MustParseAddr("127.0.0.1"), []DialBackResult{{Name: "gossip", Port: live[0]}}); !ok || !res[0].OK {
		t.Fatalf("real dial-back = %+v", res)
	}
	if (&JoinDialBackError{Results: results}).Error() == "" || !errors.Is(&JoinDialBackError{}, ErrJoinDialBack) {
		t.Fatal("JoinDialBackError")
	}
}

func TestJoinRateLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newJoinRateLimiter()
	l.now = func() time.Time { return now }
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	for i := 0; i < joinRateBurst; i++ {
		if !l.allow(a) {
			t.Fatalf("call %d inside the burst refused", i)
		}
	}
	if l.allow(a) {
		t.Fatal("call past the burst allowed")
	}
	if !l.allow(b) {
		t.Fatal("another address shares the first one's bucket")
	}
	now = now.Add(2 * time.Second)
	if !l.allow(a) {
		t.Fatal("bucket did not refill")
	}
	// The map is bounded, and past the cap the source seen longest ago is
	// forgotten instead of the new one being refused (J13): an attacker
	// with many addresses cannot lock real joiners out.
	l.max = 2
	if !l.allow(netip.MustParseAddr("10.0.0.3")) {
		t.Fatal("a new address past the cap refused")
	}
	if len(l.sources) != 2 || l.sources[b] != nil {
		t.Fatalf("the oldest source (b) was not the one forgotten: %d sources", len(l.sources))
	}
	for i := 0; i < 50; i++ {
		l.allow(netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i)))
	}
	if len(l.sources) != 2 || l.byAge.Len() != 2 {
		t.Fatalf("limiter grew past its cap: %d", len(l.sources))
	}
	// Idle sources go on the next call.
	now = now.Add(joinRateIdle)
	if !l.allow(netip.MustParseAddr("10.0.0.9")) || len(l.sources) != 1 {
		t.Fatalf("idle entries never dropped: %d sources", len(l.sources))
	}
	l.max = joinRateMaxSources

	// IPv6 shares one bucket per /64: a host cycling through its /64 is
	// still one source. Another /64 is another source; an IPv4-mapped
	// address is its IPv4 address.
	v6a, v6b := netip.MustParseAddr("2001:db8:1:2::1"), netip.MustParseAddr("2001:db8:1:2:ffff::9")
	for i := 0; i < joinRateBurst; i++ {
		l.allow(v6a)
	}
	if l.allow(v6b) {
		t.Fatal("another address in the same /64 got its own bucket")
	}
	if !l.allow(netip.MustParseAddr("2001:db8:1:3::1")) {
		t.Fatal("another /64 shares the bucket")
	}
	if got := joinRateKey(netip.MustParseAddr("::ffff:10.0.0.7")); got != netip.MustParseAddr("10.0.0.7") {
		t.Fatalf("mapped address key = %v", got)
	}
	if got := joinRateKey(v6b); got != netip.MustParseAddr("2001:db8:1:2::") {
		t.Fatalf("v6 key = %v", got)
	}
	// The server answers 429 past the limit and counts it.
	s := &joinServer{svc: &Cluster{fsm: newPlacementFSM()}, limiter: newJoinRateLimiter()}
	s.limiter.burst = 1
	h := s.handler()
	do := func(path string) int {
		req, _ := http.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		req.RemoteAddr = "192.0.2.7:4444"
		w := &joinRecorder{header: http.Header{}}
		h.ServeHTTP(w, req)
		return w.code
	}
	do(JoinPath)
	if code := do(JoinPath); code != http.StatusTooManyRequests {
		t.Fatalf("second call = %d", code)
	}
	if got := joinAttempts.Get("failure").String(); !strings.Contains(got, "rate_limited") {
		t.Fatalf("rate-limited calls not counted: %s", got)
	}
	req, _ := http.NewRequest(http.MethodGet, JoinClusterInfoPath, nil)
	req.RemoteAddr = "not-an-address"
	w := &joinRecorder{header: http.Header{}}
	h.ServeHTTP(w, req)
	if w.code != http.StatusTooManyRequests {
		t.Fatalf("call with no source address = %d", w.code)
	}
	if publicTokenID("abcdef.secret") != "abcdef" || publicTokenID("bad") != "" {
		t.Fatal("publicTokenID")
	}
}

type joinRecorder struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (r *joinRecorder) Header() http.Header         { return r.header }
func (r *joinRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *joinRecorder) WriteHeader(code int)        { r.code = code }

func TestJoinErrorStatusAndReason(t *testing.T) {
	cases := map[error]int{
		ErrJoinBadRequest:             400,
		ErrJoinTokenInvalid:           403,
		ErrJoinTokenUsed:              403,
		ErrJoinTTLNeedsWrappedCustody: 403,
		ErrNodeIDInUse:                409,
		ErrClusterVersion:             409,
		ErrJoinVersion:                412,
		ErrNotAdmitted:                412,
		&JoinDialBackError{}:          412,
		ErrNoCASigner:                 503,
		ErrNotLeader:                  503,
		errors.New("boom"):            500,
	}
	for err, want := range cases {
		if got := JoinErrorStatus(fmt.Errorf("wrapped: %w", err)); got != want {
			t.Fatalf("JoinErrorStatus(%v) = %d, want %d", err, got, want)
		}
	}
	reasons := map[error]string{
		nil: "ok", ErrJoinTokenUsed: "token_used", ErrJoinTokenFormat: "token_invalid", ErrJoinVersion: "version",
		&JoinDialBackError{}: "dial_back", ErrNoCASigner: "no_ca_signer", ErrJoinNodeIDInvalid: "bad_request",
		ErrNotLeader: "not_leader", errors.New("x"): "error",
	}
	for err, want := range reasons {
		if got := JoinReason(err); got != want {
			t.Fatalf("JoinReason(%v) = %q, want %q", err, got, want)
		}
	}
	// Codes survive a forwarding hop.
	for _, c := range joinWriteCodes {
		out := JoinWriteOutcome(fmt.Errorf("x: %w", c.err))
		if out.Code != c.code || !errors.Is(out.err(), c.err) {
			t.Fatalf("round trip %s = %+v", c.code, out)
		}
	}
	if JoinWriteOutcome(nil).Code != "" || JoinWriteOutcome(errors.New("x")).Code != "" {
		t.Fatal("outcome of a plain error")
	}
	if err := (JoinWriteResponse{Code: "mystery", Message: "m"}).err(); err == nil || !strings.Contains(err.Error(), "mystery") {
		t.Fatalf("unknown code = %v", err)
	}
}

// Workers and ingress nodes never open the join port, whatever their config
// says; only servers do.
func TestJoinPortOnlyOnServers(t *testing.T) {
	if testing.Short() {
		t.Skip("starts gossip")
	}
	port := pickFreeTCPPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	testClusterMu.Lock()
	a, err := NewAgent(config.Config{
		EnableCluster: true, NodeID: "wkr-nojoin", NodeRole: config.NodeRoleWorker,
		GossipBindAddr: "127.0.0.1:0", GossipAdvertiseAddr: "127.0.0.1:0",
		SelfAPIAdvertiseURL: fmt.Sprintf("http://127.0.0.1:%d", pickFreeTCPPort(t)), ClusterCapacityGossipInterval: time.Second,
		ClusterTLSDir: writeTestClusterTLSDir(t, "wkr-nojoin"), ClusterInternalListenAddr: "127.0.0.1:0",
		ClusterJoinListenAddr: addr,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	testClusterMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("a worker opened the join port")
	}
	// A server with the listener off has none either.
	leader, cleanup := newJoinTestCluster(t, "srv-nojoin", true, nil, joinClusterOpts{})
	defer cleanup()
	if leader.joinServer != nil {
		t.Fatal("a server with no join address opened a listener")
	}
	// A taken port is logged, never fatal: the cluster keeps serving.
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	busy, cleanup2 := newJoinTestCluster(t, "srv-busy", true, nil, joinClusterOpts{joinAddr: hold.Addr().String()})
	defer cleanup2()
	if busy.joinServer != nil {
		t.Fatal("join listener claimed a taken port")
	}
}

// 7002 still demands a client cert on every connection (eng D3): the join
// port is the only door a cert-less caller can reach.
func TestInternalPortStillRequiresClientCert(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newJoinTestCluster(t, "strict-7002", true, nil, joinClusterOpts{joinAddr: "127.0.0.1:0"})
	defer cleanup()
	if got := leader.tls.serverConfig().ClientAuth; got != tls.RequireAndVerifyClientCert {
		t.Fatalf("7002 client auth = %v", got)
	}
	if got := joinTLSConfig(leader.tls, false).ClientAuth; got != tls.NoClientCert {
		t.Fatalf("7003 client auth = %v", got)
	}
	pool := x509.NewCertPool()
	pool.AddCert(sharedTestCACert)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: clusterServerName}}}
	for _, p := range []string{InternalAPIPath, PublicInternalJoinWritePath, PublicInternalRenewCertPath, PublicInternalCAKeyPath, JoinPath} {
		resp, err := client.Post("https://"+leader.internalServer.Addr()+p, "application/json", strings.NewReader("{}"))
		if err == nil {
			resp.Body.Close()
			t.Fatalf("POST %s on 7002 without a client cert got %d; the handshake must fail", p, resp.StatusCode)
		}
	}
	// The same cert-less client reaches the join port.
	resp, err := client.Get("https://" + leader.joinServer.Addr() + JoinClusterInfoPath + "?token_id=abcdef")
	if err != nil {
		t.Fatalf("join port refused a cert-less client: %v", err)
	}
	resp.Body.Close()
}

// Role binding (Codex eng finding 1): a node admitted as a worker that
// gossips "server" with a Raft address is never added to Raft and never gets
// the CA key.
func TestAdmittedWorkerGossipingServerNeverJoinsRaft(t *testing.T) {
	if testing.Short() {
		t.Skip("starts two raft nodes")
	}
	leader, cleanup := newJoinTestCluster(t, "bind-seed", true, nil, joinClusterOpts{caDir: writeSharedCAStore(t)})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	ctx := context.Background()
	// Admit "liar" as a worker before it shows up.
	if _, err := leader.WriteJoin(ctx, JoinWriteRequest{Kind: joinWriteAdopt, Adopt: &JoinAdoptCommand{Nodes: []AdmittedNode{
		{NodeID: "liar", Role: JoinRoleWorker, KeyHash: testKey("liar")},
	}}}); err != nil {
		t.Fatal(err)
	}
	if !leader.peerForcedNonVoter("liar") || !leader.admittedNonServer("liar") {
		t.Fatal("admitted worker is voter-eligible")
	}
	// It runs a server build and gossips role=server with a Raft address.
	_, cleanupLiar := newJoinTestCluster(t, "liar", false, []string{leader.gossip.ml.LocalNode().Address()}, joinClusterOpts{role: config.NodeRoleServer})
	defer cleanupLiar()
	waitFor(t, 10*time.Second, "liar in gossip", func() bool {
		m, ok := leader.gossip.lookupMember("liar")
		return ok && m.Alive && m.RaftAddr != ""
	})
	for i := 0; i < 3; i++ {
		leader.handleMemberJoin("liar")
		time.Sleep(200 * time.Millisecond)
	}
	if _, ok := leader.configuredServer("liar"); ok {
		t.Fatal("an admitted worker gossiping server was added to Raft")
	}
	if _, err := leader.CAKeyForPeer("liar"); !errors.Is(err, ErrPeerNotServer) {
		t.Fatalf("CA key to an admitted worker = %v", err)
	}
	if leader.IsJoinWritePeer("liar") {
		t.Fatal("an admitted worker may write join state")
	}
	// A node with no admitted record keeps today's rule (gossiped role).
	if leader.peerForcedNonVoter("nobody") || leader.admittedNonServer("nobody") {
		t.Fatal("an unadmitted node lost voter eligibility")
	}
	if !leader.peerIsServer("bind-seed") {
		t.Fatal("the seed is not a server")
	}
	var none *Cluster
	if none.peerIsServer("x") {
		t.Fatal("nil cluster")
	}
}

// Tombstones on real internal calls: after a delete and a fresh join for
// the same ID, the old cert is refused on 7002 and the new one accepted.
func TestInternalCallsRefuseOldCertOfReusedID(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newJoinTestCluster(t, "tomb-seed", true, nil, joinClusterOpts{caDir: writeSharedCAStore(t)})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	ctx := context.Background()
	ca := leader.ca.get()
	oldKey, _, _ := NewNodeKey()
	_, oldLeaf, _ := ca.SignNodeCert(NodeCertRequest{PublicKey: &oldKey.PublicKey, NodeID: "wkr-r", Role: JoinRoleWorker})
	newKey, _, _ := NewNodeKey()
	_, newLeaf, _ := ca.SignNodeCert(NodeCertRequest{PublicKey: &newKey.PublicKey, NodeID: "wkr-r", Role: JoinRoleWorker})
	if _, err := leader.WriteJoin(ctx, JoinWriteRequest{Kind: joinWriteAdopt, Adopt: &JoinAdoptCommand{Nodes: []AdmittedNode{
		{NodeID: "wkr-r", Role: JoinRoleWorker, KeyHash: CertKeyHash(oldLeaf)},
	}}}); err != nil {
		t.Fatal(err)
	}
	if err := leader.CheckPeerKey("wkr-r", oldLeaf); err != nil {
		t.Fatalf("admitted key refused: %v", err)
	}
	if err := leader.CheckPeerKey("wkr-r", newLeaf); !errors.Is(err, ErrPeerKeyNotAdmitted) {
		t.Fatalf("unadmitted key = %v", err)
	}
	if _, err := leader.writeNodeDeny(ctx, "wkr-r", config.NodeRoleWorker); err != nil {
		t.Fatal(err)
	}
	tok, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleWorker})
	if err != nil {
		t.Fatal(err)
	}
	written, err := leader.WriteJoin(ctx, JoinWriteRequest{Kind: joinWriteAdmit, Admit: &JoinAdmitCommand{
		TokenID: tok.ID, NodeID: "wkr-r", Role: JoinRoleWorker, KeyHash: CertKeyHash(newLeaf),
	}})
	if err != nil || written.Admit == nil || !written.Admit.ReplacedDeny {
		t.Fatalf("fresh join = %+v %v", written, err)
	}
	if err := leader.CheckPeerKey("wkr-r", oldLeaf); !errors.Is(err, ErrPeerKeyRevoked) {
		t.Fatalf("old cert of the reused ID = %v", err)
	}
	if err := leader.CheckPeerKey("wkr-r", newLeaf); err != nil {
		t.Fatalf("new cert refused: %v", err)
	}
	if err := RefusePeerKey(leader, "wkr-r", oldLeaf); !errors.Is(err, ErrPeerKeyRevoked) {
		t.Fatalf("RefusePeerKey = %v", err)
	}
	if RefusePeerKey(NewNoop("a", "http://a", ""), "wkr-r", oldLeaf) != nil || RefusePeerKey(leader, "wkr-r", nil) != nil {
		t.Fatal("Noop or nil leaf refused")
	}
	// Workers refuse the tombstone too, from the mirror: the key one and
	// the by-identity one the fresh join wrote.
	resp, changed := leader.DeniedNodes(0)
	if !changed || len(resp.RevokedKeys) != 2 || len(resp.Nodes) != 0 {
		t.Fatalf("deny feed = %+v %v", resp, changed)
	}
	agent := &Agent{denyHits: &denyHitRecorder{}}
	agent.deny.merge(resp)
	if err := agent.CheckPeerKey("wkr-r", oldLeaf); !errors.Is(err, ErrPeerKeyRevoked) {
		t.Fatalf("worker check of the old cert = %v", err)
	}
	if err := agent.CheckPeerKey("wkr-r", newLeaf); err != nil {
		t.Fatalf("worker refused the new cert: %v", err)
	}
	if agent.IsNodeDenied("wkr-r") {
		t.Fatal("worker kept the replaced deny record")
	}

	// J7: a node deleted before it was ever admitted (adopt skipped it,
	// it was down) has no key to tombstone. Once a fresh join reuses its
	// ID, its old cert, issued before the delete, is still refused: on
	// servers, and on workers, which check only tombstones.
	legacyKey, _, _ := NewNodeKey()
	_, legacyLeaf, _ := ca.SignNodeCert(NodeCertRequest{PublicKey: &legacyKey.PublicKey, NodeID: "wkr-legacy", Role: JoinRoleWorker, Now: time.Now().Add(-time.Hour)})
	if _, err := leader.writeNodeDeny(ctx, "wkr-legacy", config.NodeRoleWorker); err != nil {
		t.Fatal(err)
	}
	tok2, err := leader.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleWorker})
	if err != nil {
		t.Fatal(err)
	}
	freshKey, _, _ := NewNodeKey()
	_, freshLeaf, _ := ca.SignNodeCert(NodeCertRequest{PublicKey: &freshKey.PublicKey, NodeID: "wkr-legacy", Role: JoinRoleWorker})
	written, err = leader.WriteJoin(ctx, JoinWriteRequest{Kind: joinWriteAdmit, Admit: &JoinAdmitCommand{
		TokenID: tok2.ID, NodeID: "wkr-legacy", Role: JoinRoleWorker, KeyHash: CertKeyHash(freshLeaf),
	}})
	if err != nil || written.Admit == nil || !written.Admit.ReplacedDeny {
		t.Fatalf("fresh join over a never-admitted node = %+v %v", written, err)
	}
	if err := leader.CheckPeerKey("wkr-legacy", legacyLeaf); !errors.Is(err, ErrPeerKeyRevoked) {
		t.Fatalf("server check of the never-admitted node's old cert = %v", err)
	}
	if err := leader.CheckPeerKey("wkr-legacy", freshLeaf); err != nil {
		t.Fatalf("server refused the fresh cert: %v", err)
	}
	resp, changed = leader.DeniedNodes(resp.Version)
	if !changed {
		t.Fatal("the deny feed did not move")
	}
	legacyAgent := &Agent{denyHits: &denyHitRecorder{}}
	legacyAgent.deny.merge(resp)
	if err := legacyAgent.CheckPeerKey("wkr-legacy", legacyLeaf); !errors.Is(err, ErrPeerKeyRevoked) {
		t.Fatalf("worker check of the never-admitted node's old cert = %v", err)
	}
	if err := legacyAgent.CheckPeerKey("wkr-legacy", freshLeaf); err != nil {
		t.Fatalf("worker refused the fresh cert: %v", err)
	}
	if legacyAgent.IsNodeDenied("wkr-legacy") || legacyAgent.CheckPeerKey("wkr-r", newLeaf) != nil {
		t.Fatal("worker refused a node it should accept")
	}
	var nilAgent *Agent
	var nilCluster *Cluster
	if nilAgent.CheckPeerKey("x", oldLeaf) != nil || nilCluster.CheckPeerKey("x", oldLeaf) != nil {
		t.Fatal("nil checkers refused")
	}
	if _, ok := nilCluster.AdmittedNode("x"); ok {
		t.Fatal("nil cluster admitted")
	}
}

func TestInternalServerRefusesUnadmittedKey(t *testing.T) {
	pool, tlsCert, err := generateTestCertForNode("worker-k")
	if err != nil {
		t.Fatal(err)
	}
	ct := &ClusterTLS{nodeCert: tlsCert, caPool: pool}
	srv, err := startInternalServer("127.0.0.1:0", ct, func(context.Context, []byte) error { return nil }, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.SetPeerAuthorizer(func(string) bool { return true })
	refuse := atomic.Bool{}
	srv.SetPeerKeyCheck(func(id string, leaf *x509.Certificate) error {
		if refuse.Load() && id == "worker-k" && leaf != nil {
			return ErrPeerKeyRevoked
		}
		return nil
	})
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: ct.clientConfig()}}
	post := func() (int, string) {
		resp, err := client.Post("https://"+srv.Addr()+InternalAPIPath, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, _ := post(); code != http.StatusNoContent {
		t.Fatalf("admitted key = %d", code)
	}
	refuse.Store(true)
	if code, body := post(); code != http.StatusForbidden || !strings.Contains(body, "revoked") {
		t.Fatalf("revoked key = %d %q", code, body)
	}
	srv.SetPeerKeyCheck(nil)
	if code, _ := post(); code != http.StatusNoContent {
		t.Fatalf("after removing the check = %d", code)
	}
	var nilSrv *internalServer
	nilSrv.SetPeerKeyCheck(nil)
}

// Adopt (§4.4): the seed imports ca.key and admits every live member in one
// op; another server fetches the CA key over 7002 mTLS.
func TestAdoptSeedThenFollower(t *testing.T) {
	if testing.Short() {
		t.Skip("starts two raft nodes")
	}
	seedCA := filepath.Join(t.TempDir(), "seed-ca")
	leader, cleanup := newJoinTestCluster(t, "adopt-seed", true, nil, joinClusterOpts{caDir: seedCA})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	ctx := context.Background()
	followerCA := filepath.Join(t.TempDir(), "follower-ca")
	follower, cleanupF := newJoinTestCluster(t, "adopt-f", false, []string{leader.gossip.ml.LocalNode().Address()}, joinClusterOpts{caDir: followerCA})
	defer cleanupF()
	waitForVoter(t, leader, "adopt-f", 15*time.Second)
	waitForFollowerToReachLeader(t, follower, "adopt-seed", 10*time.Second)

	// Nothing to sign with anywhere yet: the follower can't adopt.
	if _, err := follower.Adopt(ctx, AdoptRequest{}); err == nil {
		t.Fatal("adopt with no CA key anywhere succeeded")
	}
	// A key that is not this cluster's is refused.
	if _, err := leader.Adopt(ctx, AdoptRequest{CAKey: string(mustCA(t).KeyPEM())}); err == nil {
		t.Fatal("adopt accepted another CA's key")
	}
	res, err := leader.Adopt(ctx, AdoptRequest{CAKey: string(sharedCAKeyPEM(t))})
	if err != nil {
		t.Fatal(err)
	}
	if !res.CAImported || res.CASource != "request" || len(res.Admitted) != 2 || res.ClusterID != leader.clusterID() {
		t.Fatalf("seed adopt = %+v", res)
	}
	if _, err := os.Stat(filepath.Join(seedCA, caStoreKeyFile)); err != nil {
		t.Fatalf("CA key not in the store: %v", err)
	}
	seedLeaf, _ := leader.currentLeaf()
	if rec, ok := leader.AdmittedNode("adopt-seed"); !ok || rec.KeyHash != CertKeyHash(seedLeaf) || !rec.IsServer() {
		t.Fatalf("seed admitted = %+v", rec)
	}
	waitFor(t, 5*time.Second, "follower FSM has the admitted records", func() bool {
		_, ok := follower.AdmittedNode("adopt-f")
		return ok
	})
	again, err := leader.Adopt(ctx, AdoptRequest{})
	if err != nil || again.CAImported || again.CASource != "ca_store" || len(again.Already) != 2 {
		t.Fatalf("second seed adopt = %+v %v", again, err)
	}
	// The follower fetches the key from the seed over mTLS.
	fres, err := follower.Adopt(ctx, AdoptRequest{})
	if err != nil || fres.CASource != "peer" || !fres.CAImported {
		t.Fatalf("follower adopt = %+v %v", fres, err)
	}
	if follower.ca.get() == nil {
		t.Fatal("follower holds no signer after adopt")
	}
	// Follower writes forward to the leader: a token made on the follower.
	tok, err := follower.CreateJoinToken(ctx, JoinTokenCreateRequest{Role: JoinRoleIngress, TTL: "0"})
	if err != nil || tok.ExpiresAt != nil || tok.Warning == "" {
		t.Fatalf("follower create = %+v %v", tok, err)
	}
	if _, ok := leader.fsm.joinToken(tok.ID); !ok {
		t.Fatal("forwarded token not on the leader")
	}
	// A forwarded refusal keeps its sentinel.
	if _, err := follower.WriteJoin(ctx, JoinWriteRequest{Kind: joinWriteRekey, Rekey: &JoinRekeyCommand{NodeID: "nobody", OldKeyHash: testKey("a"), NewKeyHash: testKey("b")}}); !errors.Is(err, ErrNotAdmitted) {
		t.Fatalf("forwarded refusal = %v", err)
	}

	// Renewal on the follower, in-process (it holds the key now), same key.
	fLeaf, _ := follower.currentLeaf()
	fKey := mustTLSKey(t, follower)
	csr, _ := NewNodeCSR(fKey, "adopt-f")
	renewed, err := follower.renewViaServers(ctx, csr)
	if err != nil {
		t.Fatal(err)
	}
	rl, _ := firstPEMCertificate(renewed)
	if CertKeyHash(rl) != CertKeyHash(fLeaf) || ExtractPeerRole(rl) != JoinRoleServer {
		t.Fatalf("renewed cert = %v", rl.DNSNames)
	}
	// And through the leader over 7002 when the follower's own signer is gone.
	follower.ca.set(nil)
	if renewed, err = follower.renewViaServers(ctx, csr); err != nil || len(renewed) == 0 {
		t.Fatalf("renew via the leader = %v", err)
	}
	// A rekey: a CSR for a new key moves the admitted record.
	newKey, _, _ := NewNodeKey()
	newCSRPEM, _ := NewNodeCSR(newKey, "adopt-f")
	resp, err := leader.RenewNodeCert(ctx, "adopt-f", fLeaf, newCSRPEM)
	if err != nil || !resp.Rekeyed {
		t.Fatalf("rekey renew = %+v %v", resp, err)
	}
	newHash, _ := PublicKeyHash(&newKey.PublicKey)
	if rec, _ := leader.AdmittedNode("adopt-f"); rec.KeyHash != newHash || rec.PrevKeyHash != CertKeyHash(fLeaf) {
		t.Fatalf("after rekey = %+v", rec)
	}
	// Refusals: no record, no signer, garbage CSR.
	if _, err := leader.RenewNodeCert(ctx, "nobody", fLeaf, csr); !errors.Is(err, ErrNotAdmitted) {
		t.Fatalf("renew without a record = %v", err)
	}
	if _, err := leader.RenewNodeCert(ctx, "adopt-f", fLeaf, []byte("junk")); !errors.Is(err, ErrJoinBadRequest) {
		t.Fatalf("renew with junk = %v", err)
	}
	if _, err := follower.RenewNodeCert(ctx, "adopt-f", fLeaf, csr); !errors.Is(err, ErrNoCASigner) {
		t.Fatalf("renew without a signer = %v", err)
	}
	if _, err := follower.CAKeyForPeer("adopt-seed"); !errors.Is(err, ErrNoCASigner) {
		t.Fatalf("CA key without a signer = %v", err)
	}
}

func mustTLSKey(t *testing.T, c *Cluster) crypto.Signer {
	t.Helper()
	cert, err := c.tls.certificateForHandshake()
	if err != nil {
		t.Fatal(err)
	}
	return cert.PrivateKey.(crypto.Signer)
}
