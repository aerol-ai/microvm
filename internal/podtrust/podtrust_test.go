package podtrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// cell is a cluster CA made the cluster's own way, so the certificates
// the tests use are real worker certificates.
type cell struct {
	ca   *cluster.ClusterCA
	pool *x509.CertPool
}

func newCell(t *testing.T) *cell {
	t.Helper()
	certPEM, keyPEM, err := cluster.GenerateClusterCA("test-cell", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := cluster.ParseClusterCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := LoadCAs(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &cell{ca: ca, pool: pool}
}

// node is a node certificate the cell signs, for role and id.
func (c *cell) node(t *testing.T, id, role string) tls.Certificate {
	t.Helper()
	key, _, err := cluster.NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	_, leaf, err := c.ca.SignNodeCert(cluster.NodeCertRequest{PublicKey: key.Public(), NodeID: id, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
}

// handshake runs one TLS handshake between ServerConfig(pool, worker)
// and a client presenting cert (none when nil); it returns the server's
// answer.
func handshake(t *testing.T, pool *x509.CertPool, worker string, cert *tls.Certificate) error {
	t.Helper()
	cfg, err := ServerConfig(pool, worker)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	srvErr := make(chan error, 1)
	go func() {
		s := tls.Server(a, cfg)
		srvErr <- s.Handshake()
		s.Close()
	}()
	clientCfg := &tls.Config{InsecureSkipVerify: true} // the server's identity is PR 4's question
	if cert != nil {
		clientCfg.Certificates = []tls.Certificate{*cert}
	}
	c := tls.Client(b, clientCfg)
	_ = c.Handshake()
	// TLS 1.3: the server's verdict on the client reaches the client only
	// with its next read; the server's own error is the answer.
	go func() { _, _ = c.Read(make([]byte, 1)) }()
	select {
	case err := <-srvErr:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("handshake hung")
		return nil
	}
}

func TestServerConfigAcceptsOnlyItsWorker(t *testing.T) {
	home := newCell(t)
	other := newCell(t)
	worker := home.node(t, "worker-0", "worker")

	if err := handshake(t, home.pool, "worker-0", &worker); err != nil {
		t.Fatalf("its own worker was refused: %v", err)
	}
	cases := []struct {
		name string
		cert *tls.Certificate
		want string
	}{
		{"no client certificate", nil, "certificate"},
		{"another worker of the same cell", ptr(home.node(t, "worker-7", "worker")), "does not name this sandbox's worker"},
		{"a server node of the same cell", ptr(home.node(t, "server-0", "server")), "does not name this sandbox's worker"},
		{"the same node ID from another cell's CA", ptr(other.node(t, "worker-0", "worker")), "certificate"},
		{"a certificate no CA signed", ptr(selfSignedNode(t, "worker-0")), "certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := handshake(t, home.pool, "worker-0", tc.cert)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("handshake = %v, want a refusal with %q", err, tc.want)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// selfSignedNode claims node:<id> with no CA behind it.
func selfSignedNode(t *testing.T, id string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: id},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"node:" + id},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// NodeIDOf must give the cluster's own answer (internal/cluster
// ExtractPeerNodeID) for every form a node certificate can take.
func TestNodeIDOfAgreesWithTheCluster(t *testing.T) {
	home := newCell(t)
	real := home.node(t, "worker-3", "worker")
	certs := map[string]*x509.Certificate{
		"a cluster-signed worker":      real.Leaf,
		"nil":                          nil,
		"no SANs":                      {},
		"DNS SAN":                      {DNSNames: []string{"aerolvm-cluster-node", "node:w1"}},
		"only the shared server name":  {DNSNames: []string{"node:aerolvm-cluster-node"}},
		"empty id":                     {DNSNames: []string{"node: "}},
		"padded":                       {DNSNames: []string{" node:w2 "}},
		"URI SAN opaque":               {URIs: []*url.URL{{Scheme: "node", Opaque: "w3"}}},
		"URI SAN path":                 {URIs: []*url.URL{{Scheme: "spiffe", Host: "cell", Path: "/node:w4"}}},
		"URI SAN nil":                  {URIs: []*url.URL{nil}},
		"common name only":             {Subject: pkix.Name{CommonName: "node:w5"}},
		"DNS wins over URI":            {DNSNames: []string{"node:w6"}, URIs: []*url.URL{{Scheme: "node", Opaque: "w7"}}},
		"other SANs then node":         {DNSNames: []string{"role:worker", "node:w8"}},
		"lookalike prefix not matched": {DNSNames: []string{"nodes:w9"}},
	}
	for name, cert := range certs {
		if got, want := NodeIDOf(cert), cluster.ExtractPeerNodeID(cert); got != want {
			t.Errorf("%s: NodeIDOf = %q, cluster says %q", name, got, want)
		}
	}
	if got := NodeIDOf(real.Leaf); got != "worker-3" {
		t.Errorf("real worker certificate = %q", got)
	}
}

func TestServerConfigNeedsItsInputs(t *testing.T) {
	pool := x509.NewCertPool()
	if _, err := ServerConfig(nil, "w"); err == nil {
		t.Error("no CA: want an error")
	}
	if _, err := ServerConfig(pool, " "); err == nil {
		t.Error("no worker: want an error")
	}
	cfg, err := ServerConfig(pool, "w")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("config = %+v", cfg)
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil || leaf.NotAfter.Before(time.Now().Add(365*24*time.Hour)) {
		t.Errorf("toolboxd's own certificate = %v, %v: want one that outlives a long sandbox", leaf, err)
	}
	if err := checkWorker(nil, "w"); !errors.Is(err, ErrNotThisWorker) {
		t.Errorf("no verified chain = %v", err)
	}
	if _, err := LoadCAs([]byte("no pem here")); err == nil {
		t.Error("LoadCAs of no certificate: want an error")
	}
}
