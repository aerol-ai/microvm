package cluster

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

func TestValidateClusterNodeCertificateRemaining(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"AerolVM Test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	mint := func(dns []string, eku []x509.ExtKeyUsage) tls.Certificate {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "node"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  eku,
			DNSNames:     dns,
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}

	if _, _, err := validateClusterNodeCertificate(&tls.Certificate{}, pool); err == nil {
		t.Fatal("empty cert accepted")
	}

	valid := mint([]string{clusterServerName, "node:n1"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	valid.Certificate = append(valid.Certificate, []byte("not-a-cert"))
	if _, _, err := validateClusterNodeCertificate(&valid, pool); err == nil {
		t.Fatal("garbage intermediate accepted")
	}

	good := mint([]string{clusterServerName, "node:n1"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	if _, _, err := validateClusterNodeCertificate(&good, x509.NewCertPool()); err == nil {
		t.Fatal("untrusted pool accepted")
	}

	serverOnly := mint([]string{clusterServerName, "node:n1"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if _, _, err := validateClusterNodeCertificate(&serverOnly, pool); err == nil {
		t.Fatal("server-only EKU accepted")
	}

	noNodeSAN := mint([]string{clusterServerName}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	if _, _, err := validateClusterNodeCertificate(&noNodeSAN, pool); err == nil {
		t.Fatal("missing node SAN accepted")
	}

	id, expiry, err := validateClusterNodeCertificate(&good, pool)
	if err != nil || id != "n1" || expiry.IsZero() {
		t.Fatalf("valid cert id=%q expiry=%v err=%v", id, expiry, err)
	}

	// leafCertificate prefers an already-parsed Leaf so reload skips ParseCertificate.
	parsed, err := x509.ParseCertificate(good.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	good.Leaf = parsed
	if leaf, err := leafCertificate(&good); err != nil || leaf != parsed {
		t.Fatalf("cached leaf = %v err=%v", leaf, err)
	}
}

func TestLift3TLSForwardCapacityNew(t *testing.T) {
	if _, err := (*ClusterTLS)(nil).certificateForHandshake(); err == nil {
		t.Fatal("nil tls handshake")
	}
	empty := &ClusterTLS{}
	if cert, err := empty.certificateForHandshake(); err != nil || cert != &empty.nodeCert {
		t.Fatalf("empty paths = %v err=%v", cert, err)
	}
	missing := &ClusterTLS{certPath: filepath.Join(t.TempDir(), "missing.crt"), keyPath: filepath.Join(t.TempDir(), "missing.key")}
	if _, err := missing.certificateForHandshake(); err == nil {
		t.Fatal("stat missing cert")
	}
	dir := writeTestClusterTLSDir(t, "hs-node")
	loaded, err := loadClusterTLS(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.certificateForHandshake(); err != nil {
		t.Fatalf("warm handshake: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "node.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.certificateForHandshake(); err != nil {
		// lastGood should keep the previous leaf after key disappearance
		t.Fatalf("lastGood after key unlink: %v", err)
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9),
		Subject:               pkix.Name{Organization: []string{"lift3"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{clusterServerName, "node:peer-a"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://cluster.internal/x", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	req.Header.Set(PeerNodeIDHeader, "wrong-peer")
	if _, err := AuthenticatedPeerNodeID(req); err == nil {
		t.Fatal("claimed peer mismatch")
	}

	pc := newProxyCache()
	if _, err := pc.getForPeer("", "https://peer.internal", http.DefaultTransport); err == nil {
		t.Fatal("empty peer id")
	}
	if _, err := pc.getForPeer("n", "http://peer.internal", http.DefaultTransport); err == nil {
		t.Fatal("plaintext peer URL")
	}
	if _, err := pc.getForPeer("n", "https://peer.internal", nil); err == nil {
		t.Fatal("nil transport")
	}

	rec := httptest.NewRecorder()
	fwdReq := httptest.NewRequest(http.MethodGet, "http://src/x", nil)
	fwdReq.Header.Set("X-Cluster-Forwarded", "1")
	forwardHTTPWithMetrics(pc, func(string) *http.Client { return http.DefaultClient }, Endpoint{NodeID: "n", InternalURL: "https://peer.internal"}, rec, fwdReq)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("loop = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	forwardHTTPWithMetrics(nil, nil, Endpoint{}, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://src/x", nil))
	rec = httptest.NewRecorder()
	forwardHTTPWithMetrics(pc, func(string) *http.Client { return &http.Client{} }, Endpoint{NodeID: "n", InternalURL: "https://peer.internal"}, rec, httptest.NewRequest(http.MethodGet, "http://src/x", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil transport client = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	if err := servePeerProxy(pc, "n", "http://peer.internal", http.DefaultTransport, rec, httptest.NewRequest(http.MethodGet, "http://src/x", nil)); err == nil {
		t.Fatal("serve plaintext")
	}

	_ = newCapacityLeaseCache("self", nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var nilLeases *capacityLeaseCache
	nilLeases.SetLocalTemplateCatalogProvider(nil)
	nilLeases.set("", capacity.Snapshot{}, time.Now())
	nilLeases.set("n", capacity.Snapshot{}, time.Now())
	(&Cluster{}).startCapacityLeaseLoop(0)
	(&Cluster{capacityLeases: newCapacityLeaseCache("self", nil, time.Second, nil)}).startCapacityLeaseLoop(-1)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := New(config.Config{}, logger, nil); err == nil {
		t.Fatal("cluster disabled")
	}
	if _, err := New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, logger, nil); err == nil {
		t.Fatal("worker role")
	}
	if _, err := New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil); err == nil {
		t.Fatal("missing advertise URL")
	}
	raftFile := filepath.Join(t.TempDir(), "raft-is-file")
	if err := os.WriteFile(raftFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleServer, NodeID: "n-badraft",
		SelfAPIAdvertiseURL: "http://127.0.0.1:1", RaftDataDir: raftFile,
	}, logger, nil); err == nil {
		t.Fatal("recovery store onto file")
	}
	dirs := writeTestClusterTLSDirs(t, "tls-node")
	if _, err := New(config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleServer, NodeID: "other-id",
		SelfAPIAdvertiseURL: "http://127.0.0.1:1", RaftDataDir: t.TempDir(),
		ClusterTLSDir: dirs["tls-node"],
	}, logger, nil); err == nil {
		t.Fatal("tls identity mismatch")
	}
	if _, err := NewAgent(config.Config{
		EnableCluster: true, NodeRole: config.NodeRoleWorker, NodeID: "ag-badlisten",
		SelfAPIAdvertiseURL: "http://127.0.0.1:1", ClusterTLSDir: writeTestClusterTLSDir(t, "ag-badlisten"),
		ClusterInternalListenAddr: "not-a-listen-addr",
	}, logger, nil); err == nil {
		t.Fatal("agent bad listen")
	}
	if _, err := decodeGossipSecretKey(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("short gossip key")
	}
}
