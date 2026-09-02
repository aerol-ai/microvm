package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtractPeerNodeID(t *testing.T) {
	id := ExtractPeerNodeID(&x509.Certificate{DNSNames: []string{"aerolvm-cluster-node", "node:worker-9"}})
	if id != "worker-9" {
		t.Fatalf("got id=%q", id)
	}
	id = ExtractPeerNodeID(&x509.Certificate{
		Subject:  pkix.Name{CommonName: "aerolvm-cluster-node"},
		DNSNames: []string{"aerolvm-cluster-node"},
	})
	if id != "" {
		t.Fatalf("shared-SAN cert id=%q, want empty", id)
	}
	u, err := url.Parse("node:uri-node")
	if err != nil {
		t.Fatal(err)
	}
	id = ExtractPeerNodeID(&x509.Certificate{URIs: []*url.URL{u}})
	if id != "uri-node" {
		t.Fatalf("URI SAN id=%q", id)
	}
	if !VerifyPeerNodeID(&x509.Certificate{DNSNames: []string{"node:n1"}}, "n1") {
		t.Fatal("VerifyPeerNodeID should accept matching SAN")
	}
	if VerifyPeerNodeID(&x509.Certificate{DNSNames: []string{"node:n1"}}, "n2") {
		t.Fatal("VerifyPeerNodeID should reject mismatch")
	}
}

func TestLoadClusterTLS(t *testing.T) {
	// Empty dir string
	ct, err := loadClusterTLS("")
	if err != nil || ct != nil {
		t.Errorf("expected nil, nil for empty dir")
	}

	dir := t.TempDir()

	// Missing CA
	_, err = loadClusterTLS(dir)
	if err == nil {
		t.Errorf("expected error missing CA")
	}

	// Invalid CA
	os.WriteFile(filepath.Join(dir, tlsCAFile), []byte("invalid"), 0644)
	_, err = loadClusterTLS(dir)
	if err == nil {
		t.Errorf("expected error invalid CA")
	}

	// Valid CA but missing node cert
	pool, tlsCert, err := generateTestCert()
	if err != nil {
		t.Fatalf("cert gen: %v", err)
	}

	// How to write valid CA? I don't have the raw PEM easily.
	// We can use x509.MarshalCertificate maybe, but generateTestCert doesn't export PEM.
	// Wait, we can test serverConfig and clientConfig easily without loadClusterTLS.
	ct = &ClusterTLS{caPool: pool, nodeCert: tlsCert}
	sCfg := ct.serverConfig()
	if sCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected RequireAndVerifyClientCert")
	}
	if err := sCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{clusterServerName}}}}); err == nil {
		t.Fatal("server TLS accepted a CA-valid peer without node identity")
	}
	if err := sCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{DNSNames: []string{clusterServerName, "node:worker-1"}}}}); err != nil {
		t.Fatalf("server TLS rejected node-bound peer: %v", err)
	}
	cCfg := ct.clientConfig()
	if cCfg.ServerName != clusterServerName {
		t.Errorf("expected clusterServerName")
	}

	validDir := writeTestClusterTLSDir(t, "node-load")
	loaded, err := loadClusterTLS(validDir)
	if err != nil {
		t.Fatalf("load valid node-bound certificate: %v", err)
	}
	if loaded.NodeID() != "node-load" {
		t.Fatalf("loaded node id = %q, want node-load", loaded.NodeID())
	}

	sharedSANDir := writeTestClusterTLSDir(t, "")
	if _, err := loadClusterTLS(sharedSANDir); err == nil || !strings.Contains(err.Error(), "node:<id> SAN") {
		t.Fatalf("shared-SAN certificate error = %v, want node SAN rejection", err)
	}
}

func TestClientForPeerNoopWithoutTLS(t *testing.T) {
	base := &http.Client{}
	if got := ClientForPeer(base, "n1"); got != base {
		t.Fatal("ClientForPeer without TLS transport should return base")
	}
	if got := ClientForPeer(nil, "n1"); got != nil {
		t.Fatal("nil base should stay nil")
	}
}

func TestPeerClientCacheSamePointer(t *testing.T) {
	base := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	var cache peerClientCache
	a := cache.get(base, "worker-1")
	b := cache.get(base, "worker-1")
	if a == nil || a == base {
		t.Fatal("expected distinct VerifyPeer client")
	}
	if a != b {
		t.Fatal("two dials for same node must return same client pointer")
	}
	c := cache.get(base, "worker-2")
	if c == a {
		t.Fatal("different nodes must not share the same cached client")
	}
	cache.invalidate("worker-1")
	d := cache.get(base, "worker-1")
	if d == a {
		t.Fatal("invalidate must drop cached client")
	}
}

func TestClusterTLSReloadRejectsWrongNodeIdentity(t *testing.T) {
	dirs := writeTestClusterTLSDirs(t, "node-a", "node-b")
	loaded, err := loadClusterTLS(dirs["node-a"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.certificateForHandshake(); err != nil {
		t.Fatalf("initial handshake certificate: %v", err)
	}
	for _, name := range []string{tlsNodeCertFile, tlsNodeKeyFile} {
		raw, err := os.ReadFile(filepath.Join(dirs["node-b"], name))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dirs["node-a"], name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		future := time.Now().Add(2 * time.Second)
		if err := os.Chtimes(path, future, future); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loaded.certificateForHandshake(); err == nil || !strings.Contains(err.Error(), "does not match node id") {
		t.Fatalf("rotated identity error = %v", err)
	}
}
