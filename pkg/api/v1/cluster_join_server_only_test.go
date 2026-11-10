package v1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// A server join token and adopt refuse a caller whose verified cert names a
// node that is not a server, directly or as a forward; an operator with
// the PAT and no node cert, and a server node, still get them (J1: a
// leaked worker token must never lead to the CA key or a Raft seat).
func TestServerTokenAndAdoptRefuseNonServerNodes(t *testing.T) {
	stub := newJoinStub()
	stub.writePeers = map[string]bool{"srv-2": true}
	stub.created = cluster.JoinTokenCreated{ID: "abcdef", Role: "server"}
	stub.adopt = cluster.AdoptResponse{ClusterID: "sha256:x"}
	mux := joinRoutesMux(t, stub, joinOperator())
	call := func(path, body string, cert *x509.Certificate, forwarded bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if cert != nil {
			addVerifiedClientCertificate(req, cert)
		}
		if forwarded {
			req.Header.Set(cluster.HeaderForwarded, "1")
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	node := func(id string) *x509.Certificate { return &x509.Certificate{DNSNames: []string{"node:" + id}} }
	noNodeSAN := &x509.Certificate{DNSNames: []string{"aerolvm-cluster-node"}}
	cases := []struct {
		name      string
		path      string
		body      string
		cert      *x509.Certificate
		forwarded bool
		want      int
	}{
		{"operator, no node cert: server token", cluster.PublicJoinTokensPath, `{"role":"server","ttl":"2h"}`, nil, false, http.StatusCreated},
		{"worker cert: server token", cluster.PublicJoinTokensPath, `{"role":"server","ttl":"2h"}`, node("wkr-1"), false, http.StatusForbidden},
		{"worker cert, odd case: server token", cluster.PublicJoinTokensPath, `{"role":" Server "}`, node("wkr-1"), false, http.StatusForbidden},
		{"worker forwarding an operator: server token", cluster.PublicJoinTokensPath, `{"role":"server"}`, node("wkr-1"), true, http.StatusForbidden},
		{"cert with no node identity: server token", cluster.PublicJoinTokensPath, `{"role":"server"}`, noNodeSAN, false, http.StatusForbidden},
		{"server cert: server token", cluster.PublicJoinTokensPath, `{"role":"server","ttl":"2h"}`, node("srv-2"), false, http.StatusCreated},
		{"worker cert: worker token", cluster.PublicJoinTokensPath, `{"role":"worker"}`, node("wkr-1"), false, http.StatusCreated},
		{"worker cert: the default role is worker", cluster.PublicJoinTokensPath, `{}`, node("wkr-1"), false, http.StatusCreated},
		{"operator, no node cert: adopt", cluster.PublicAdoptPath, `{}`, nil, false, http.StatusOK},
		{"worker cert: adopt", cluster.PublicAdoptPath, `{"ca_key":"PEM"}`, node("wkr-1"), false, http.StatusForbidden},
		{"worker forwarding an operator: adopt", cluster.PublicAdoptPath, `{"ca_key":"PEM"}`, node("wkr-1"), true, http.StatusForbidden},
		{"cert with no node identity: adopt", cluster.PublicAdoptPath, `{"ca_key":"PEM"}`, noNodeSAN, false, http.StatusForbidden},
		{"server cert: adopt", cluster.PublicAdoptPath, `{}`, node("srv-2"), false, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub.createReq, stub.adoptReq = cluster.JoinTokenCreateRequest{}, cluster.AdoptRequest{}
			rr := call(tc.path, tc.body, tc.cert, tc.forwarded)
			if rr.Code != tc.want {
				t.Fatalf("= %d %s, want %d", rr.Code, rr.Body.String(), tc.want)
			}
			if tc.want != http.StatusForbidden {
				return
			}
			if !strings.Contains(rr.Body.String(), "not an admitted server") || stub.createReq.Role != "" || stub.adoptReq.CAKey != "" {
				t.Fatalf("refusal reached the cluster: %s %+v %+v", rr.Body.String(), stub.createReq, stub.adoptReq)
			}
		})
	}

	// A node with no Raft view (a worker's agent) cannot tell who serves,
	// so it refuses a node cert asking it for a server token; the server
	// tier would refuse the worker's relay anyway.
	agentLike := &tokenOnlyCluster{Noop: cluster.NewNoop("wkr-9", "http://wkr-9", "")}
	req := httptest.NewRequest(http.MethodPost, cluster.PublicJoinTokensPath, strings.NewReader(`{"role":"server"}`))
	addVerifiedClientCertificate(req, node("srv-2"))
	rr := httptest.NewRecorder()
	joinRoutesMux(t, agentLike, joinOperator()).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden || agentLike.created {
		t.Fatalf("agent asked by a node cert = %d, created %v", rr.Code, agentLike.created)
	}
}

// tokenOnlyCluster manages join tokens but has no Raft view, like a
// worker's agent.
type tokenOnlyCluster struct {
	*cluster.Noop
	created bool
}

func (c *tokenOnlyCluster) CreateJoinToken(context.Context, cluster.JoinTokenCreateRequest) (cluster.JoinTokenCreated, error) {
	c.created = true
	return cluster.JoinTokenCreated{}, nil
}

func (c *tokenOnlyCluster) ListJoinTokens(context.Context) (cluster.JoinTokenList, error) {
	return cluster.JoinTokenList{}, nil
}

func (c *tokenOnlyCluster) RevokeJoinToken(context.Context, string) error { return nil }

// The same rule over a real mTLS connection: a worker's cert signed by
// the cluster CA (what a worker's API presents when it relays an
// operator's call, agent_join.go) is refused a server token; a server's
// cert, and an operator with no cert, are not.
func TestServerTokenOverRealMTLS(t *testing.T) {
	caPEM, caKeyPEM, err := cluster.GenerateClusterCA("test-ca", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := cluster.ParseClusterCA(caPEM, caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	nodeCert := func(id, role string) *tls.Certificate {
		key, keyPEM, err := cluster.NewNodeKey()
		if err != nil {
			t.Fatal(err)
		}
		certPEM, _, err := ca.SignNodeCert(cluster.NodeCertRequest{PublicKey: &key.PublicKey, NodeID: id, Role: role})
		if err != nil {
			t.Fatal(err)
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return &pair
	}
	stub := newJoinStub()
	stub.writePeers = map[string]bool{"srv-2": true}
	ts := httptest.NewUnstartedServer(joinRoutesMux(t, stub, joinOperator()))
	ts.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	ts.StartTLS()
	defer ts.Close()
	post := func(cert *tls.Certificate) int {
		tr := ts.Client().Transport.(*http.Transport).Clone()
		if cert != nil {
			tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL+cluster.PublicJoinTokensPath, strings.NewReader(`{"role":"server","ttl":"2h"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(nodeCert("wkr-1", cluster.JoinRoleWorker)); code != http.StatusForbidden {
		t.Fatalf("worker cert = %d", code)
	}
	if code := post(nodeCert("srv-2", cluster.JoinRoleServer)); code != http.StatusCreated {
		t.Fatalf("server cert = %d", code)
	}
	if code := post(nil); code != http.StatusCreated {
		t.Fatalf("no cert (operator) = %d", code)
	}
}
