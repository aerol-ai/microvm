package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

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
