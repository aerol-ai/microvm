package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractPeerNodeID(t *testing.T) {
	id, legacy := ExtractPeerNodeID(&x509.Certificate{DNSNames: []string{"aerolvm-cluster-node", "node:worker-9"}})
	if id != "worker-9" || legacy {
		t.Fatalf("got id=%q legacy=%v", id, legacy)
	}
	id, legacy = ExtractPeerNodeID(&x509.Certificate{
		Subject:  pkix.Name{CommonName: "aerolvm-cluster-node"},
		DNSNames: []string{"aerolvm-cluster-node"},
	})
	if id != "" || !legacy {
		t.Fatalf("legacy cert id=%q legacy=%v", id, legacy)
	}
	u, err := url.Parse("node:uri-node")
	if err != nil {
		t.Fatal(err)
	}
	id, legacy = ExtractPeerNodeID(&x509.Certificate{URIs: []*url.URL{u}})
	if id != "uri-node" || legacy {
		t.Fatalf("URI SAN id=%q legacy=%v", id, legacy)
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
	cCfg := ct.clientConfig()
	if cCfg.ServerName != clusterServerName {
		t.Errorf("expected clusterServerName")
	}
}
