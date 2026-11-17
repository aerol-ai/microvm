package cluster

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// tokenForwardServer is a TLS server presenting a node cert the cluster CA
// signed for nodeID with role, answering with h (a teapot when nil).
func tokenForwardServer(t *testing.T, ca *ClusterCA, nodeID, role string, h http.Handler) *httptest.Server {
	t.Helper()
	key, keyPEM, err := NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := ca.SignNodeCert(NodeCertRequest{PublicKey: key.Public(), NodeID: nodeID, Role: role, Lifetime: time.Hour, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return tokenForwardTLS(t, certPEM, keyPEM, h)
}

// tokenForwardExternalCAServer presents what an external CA signs (plan
// §15.2.1): the node and its role as URI SANs, node:<id> and
// aerolvm-role:<role>, and no DNS role name.
func tokenForwardExternalCAServer(t *testing.T, ca *ClusterCA, nodeID, role string, h http.Handler) *httptest.Server {
	t.Helper()
	key, keyPEM, err := NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	node, _ := url.Parse("node:" + nodeID)
	roleURI, _ := url.Parse(certRoleSANprefix + role)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: nodeID},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames: []string{clusterServerName}, URIs: []*url.URL{node, roleURI},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tokenForwardTLS(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, h)
}

func tokenForwardTLS(t *testing.T, certPEM, keyPEM []byte, h http.Handler) *httptest.Server {
	t.Helper()
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		h = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// tokenForwardCA is a test cluster CA and a client that trusts it.
func tokenForwardCA(t *testing.T) (*ClusterCA, *http.Client) {
	t.Helper()
	caPEM, caKeyPEM, err := GenerateClusterCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseClusterCA(caPEM, caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return ca, &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: clusterServerName}}}
}

// A caller's credential goes only to a node whose certificate proves it is
// a server (DNS:role:server), never to one that says so in gossip: a
// worker's certificate, even under the server's node id, fails the
// handshake, and so does a node id other than the one asked for.
func TestServerClientForPeerPinsTheServerRole(t *testing.T) {
	ca, base := tokenForwardCA(t)
	get := func(srv *httptest.Server, asked string) error {
		c := ServerClientForPeer(base, asked)
		if c == nil {
			t.Fatal("no client")
		}
		resp, err := c.Get(srv.URL)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get(tokenForwardServer(t, ca, "srv-1", JoinRoleServer, nil), "srv-1"); err != nil {
		t.Fatalf("a server's cert: %v", err)
	}
	// External-CA mode names the role as a URI SAN (PR 2 review, round 3:
	// every such server read as role "" and a worker's forward found none).
	if err := get(tokenForwardExternalCAServer(t, ca, "srv-1", JoinRoleServer, nil), "srv-1"); err != nil {
		t.Fatalf("an external-CA server's cert: %v", err)
	}
	for _, tc := range []struct {
		name        string
		srv         *httptest.Server
		asked, want string
	}{
		{"a worker's cert under the server's node id", tokenForwardServer(t, ca, "srv-1", JoinRoleWorker, nil), "srv-1", "not a server's"},
		{"a gateway's cert", tokenForwardServer(t, ca, "gw-1", JoinRoleIngress, nil), "gw-1", "not a server's"},
		{"an external-CA worker's cert", tokenForwardExternalCAServer(t, ca, "srv-1", JoinRoleWorker, nil), "srv-1", "not a server's"},
		{"a server's cert for another node", tokenForwardServer(t, ca, "srv-2", JoinRoleServer, nil), "srv-1", "node id mismatch"},
	} {
		if err := get(tc.srv, tc.asked); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want a handshake refused with %q", tc.name, err, tc.want)
		}
	}
	if ServerClientForPeer(&http.Client{}, "srv-1") != nil {
		t.Error("a client with no TLS forwards a caller's credential")
	}
}

// ExtractPeerRole reads both forms a node cert names its role in: the
// cluster CA's DNS role:<role> and an external CA's URI aerolvm-role:<role>
// (the round 3 review's TestReviewR3ExternalCAServerRole). Two URI roles
// name none.
func TestExtractPeerRoleReadsBothForms(t *testing.T) {
	uri := func(s string) *url.URL { u, _ := url.Parse(s); return u }
	for _, tc := range []struct {
		name string
		cert *x509.Certificate
		want string
	}{
		{"cluster CA", &x509.Certificate{DNSNames: []string{"node:s", "role:server"}}, JoinRoleServer},
		{"external CA", &x509.Certificate{DNSNames: []string{"aerolvm-servers.aerolvm-system.svc"}, URIs: []*url.URL{uri("node:aerolvm-server-0"), uri("aerolvm-role:server")}}, JoinRoleServer},
		{"external CA, worker", &x509.Certificate{URIs: []*url.URL{uri("aerolvm-role:worker")}}, JoinRoleWorker},
		{"two URI roles", &x509.Certificate{URIs: []*url.URL{uri("aerolvm-role:worker"), uri("aerolvm-role:server")}}, ""},
		{"an unknown role", &x509.Certificate{URIs: []*url.URL{uri("aerolvm-role:admin")}}, ""},
		{"none", &x509.Certificate{DNSNames: []string{"node:s"}}, ""},
		{"nil", nil, ""},
		// Node certificates get only what their role needs: a DNS role and
		// a URI role that disagree name none, whichever comes first.
		{"DNS server, URI worker", &x509.Certificate{DNSNames: []string{"node:w", "role:server"}, URIs: []*url.URL{uri("aerolvm-role:worker")}}, ""},
		{"DNS worker, URI server", &x509.Certificate{DNSNames: []string{"node:w", "role:worker"}, URIs: []*url.URL{uri("aerolvm-role:server")}}, ""},
		{"DNS and URI agree", &x509.Certificate{DNSNames: []string{"node:w", "role:worker"}, URIs: []*url.URL{uri("aerolvm-role:worker")}}, JoinRoleWorker},
		{"two DNS roles", &x509.Certificate{DNSNames: []string{"node:w", "role:worker", "role:server"}}, ""},
		{"an unknown DNS role beside a known one", &x509.Certificate{DNSNames: []string{"node:w", "role:admin", "role:worker"}}, ""},
	} {
		if got := ExtractPeerRole(tc.cert); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A worker hands a token write to the next server when one cannot be
// reached or answers 5xx, sending the same body again, and stops at a 4xx:
// a server authenticated the caller and refused it, so the others would
// only repeat that.
func TestForwardToServerTriesTheNextServer(t *testing.T) {
	ca, base := tokenForwardCA(t)
	type hit struct{ node, body string }
	var mu sync.Mutex
	var hits []hit
	answer := func(node string, code int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			hits = append(hits, hit{node, string(b)})
			mu.Unlock()
			w.WriteHeader(code)
		})
	}
	closed := tokenForwardServer(t, ca, "srv-gone", JoinRoleServer, nil)
	closed.Close()
	agentWith := func(members ...Member) *Agent {
		index := newGossipMemberIndex()
		for _, m := range members {
			m.Alive, m.Role = true, config.NodeRoleServer
			index.upsert(m)
		}
		return &Agent{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), nodeID: "wkr-1", internalClient: base,
			gossip: &gossipNode{memberIndex: index}}
	}
	server := func(node string, code int) Member {
		return Member{NodeID: node, InternalURL: tokenForwardServer(t, ca, node, JoinRoleServer, answer(node, code)).URL}
	}
	for _, tc := range []struct {
		name     string
		members  []Member
		want     int
		wantHits int
	}{
		{"a 503 then a server that answers", []Member{server("srv-a", 503), server("srv-b", 201)}, 201, -1},
		{"an unreachable server then one that answers", []Member{{NodeID: "srv-gone", InternalURL: closed.URL}, server("srv-b", 201)}, 201, 1},
		{"a 401 is the answer", []Member{server("srv-a", 401), server("srv-b", 401)}, 401, 1},
		{"every server answers 503", []Member{server("srv-a", 503), server("srv-b", 503)}, http.StatusBadGateway, 2},
	} {
		mu.Lock()
		hits = nil
		mu.Unlock()
		req := httptest.NewRequest(http.MethodPost, "/v1/tokens", strings.NewReader(`{"name":"ci"}`))
		rr := httptest.NewRecorder()
		agentWith(tc.members...).ForwardToServer(rr, req)
		mu.Lock()
		got := append([]hit(nil), hits...)
		mu.Unlock()
		if rr.Code != tc.want || (tc.wantHits >= 0 && len(got) != tc.wantHits) {
			t.Errorf("%s: %d after %v, want %d after %d tries", tc.name, rr.Code, got, tc.want, tc.wantHits)
		}
		for _, h := range got {
			if h.body != `{"name":"ci"}` {
				t.Errorf("%s: %s got body %q", tc.name, h.node, h.body)
			}
		}
	}
}

// With no server to send it to, or a token write that is itself a forward,
// a worker answers the caller and forwards nothing.
func TestForwardToServerRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    *Agent
		hdr  string
		want int
	}{
		{"no agent", nil, "", http.StatusServiceUnavailable},
		{"no server known", &Agent{}, "", http.StatusServiceUnavailable},
		{"already forwarded", &Agent{}, "1", http.StatusMisdirectedRequest},
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/tokens", nil)
		if tc.hdr != "" {
			req.Header.Set(HeaderForwarded, tc.hdr)
		}
		rr := httptest.NewRecorder()
		tc.a.ForwardToServer(rr, req)
		if rr.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, rr.Code, tc.want)
		}
	}
}

// A call not safe to run twice (a create with no Idempotency-Key) goes to
// the next server only when the first never got it: a 5xx, or a server
// that took the call and gave no answer, is the caller's answer.
func TestForwardToServerOnce(t *testing.T) {
	ca, base := tokenForwardCA(t)
	var mu sync.Mutex
	var hits []string
	answer := func(node string, code int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			mu.Lock()
			hits = append(hits, node)
			mu.Unlock()
			if code == 0 {
				// Took the call, then dropped the connection.
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			w.WriteHeader(code)
		})
	}
	closed := tokenForwardServer(t, ca, "srv-gone", JoinRoleServer, nil)
	closed.Close()
	agentWith := func(members ...Member) *Agent {
		index := newGossipMemberIndex()
		for _, m := range members {
			m.Alive, m.Role = true, config.NodeRoleServer
			index.upsert(m)
		}
		return &Agent{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), nodeID: "wkr-1", internalClient: base,
			gossip: &gossipNode{memberIndex: index}}
	}
	server := func(node string, code int) Member {
		return Member{NodeID: node, InternalURL: tokenForwardServer(t, ca, node, JoinRoleServer, answer(node, code)).URL}
	}
	for _, tc := range []struct {
		name     string
		members  []Member
		want     int
		wantHits []string
	}{
		// The agent tries servers in a random order: each case holds either way.
		{"a 503 is the answer", []Member{server("srv-a", 503), server("srv-b", 503)}, 503, []string{"one"}},
		{"an unreachable server, then one that answers", []Member{{NodeID: "srv-gone", InternalURL: closed.URL}, server("srv-b", 201)}, 201, []string{"srv-b"}},
		{"a server that took it and gave no answer", []Member{server("srv-a", 0), server("srv-b", 0)}, http.StatusBadGateway, []string{"one"}},
	} {
		mu.Lock()
		hits = nil
		mu.Unlock()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
		rr := httptest.NewRecorder()
		agentWith(tc.members...).ForwardToServerOnce(rr, req)
		mu.Lock()
		got := strings.Join(hits, ",")
		mu.Unlock()
		want := strings.Join(tc.wantHits, ",")
		if want == "one" && len(hits) == 1 {
			want = got
		}
		if rr.Code != tc.want || got != want {
			t.Errorf("%s: %d after %q, want %d after %v", tc.name, rr.Code, got, tc.want, tc.wantHits)
		}
	}
}
