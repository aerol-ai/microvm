package cluster

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func generateTestCert() (*x509.CertPool, tls.Certificate, error) {
	return generateTestCertForNode("")
}

func generateTestCertForNode(nodeID string) (*x509.CertPool, tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	dns := []string{"aerolvm-cluster-node", "localhost"}
	if nodeID != "" {
		dns = append(dns, "node:"+nodeID)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   nodeID,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dns,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	return pool, tlsCert, nil
}

func TestInternalServerSetup(t *testing.T) {
	_, err := startInternalServer(":0", nil, nil, slog.Default())
	if err == nil {
		t.Errorf("expected error without tls")
	}
}

func TestInternalServerHandlers(t *testing.T) {
	pool, tlsCert, err := generateTestCert()
	if err != nil {
		t.Fatalf("cert gen: %v", err)
	}

	ct := &ClusterTLS{
		nodeCert: tlsCert,
		caPool:   pool,
	}

	applyErr := error(nil)
	handler := func(ctx context.Context, b []byte) error {
		return applyErr
	}

	srv, err := startInternalServer("127.0.0.1:0", ct, handler, slog.Default())
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Close()

	if srv.Addr() == "" {
		t.Errorf("expected bound address")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: ct.clientConfig(),
		},
	}

	// 1. Success apply
	resp, err := client.Post("https://"+srv.Addr()+InternalAPIPath, "application/json", bytes.NewReader([]byte("ok")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204, got %d", resp.StatusCode)
	}

	// 2. ErrNotLeader
	applyErr = ErrNotLeader
	resp, _ = client.Post("https://"+srv.Addr()+InternalAPIPath, "application/json", bytes.NewReader([]byte("x")))
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}

	// 3. ErrCreateBackpressure
	applyErr = ErrCreateBackpressure
	resp, _ = client.Post("https://"+srv.Addr()+InternalAPIPath, "application/json", bytes.NewReader([]byte("x")))
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", resp.StatusCode)
	}

	// 4. ErrCapacityExceeded
	applyErr = ErrCapacityExceeded
	resp, _ = client.Post("https://"+srv.Addr()+InternalAPIPath, "application/json", bytes.NewReader([]byte("x")))
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}

	// 5. Generic error
	applyErr = errors.New("boom")
	resp, _ = client.Post("https://"+srv.Addr()+InternalAPIPath, "application/json", bytes.NewReader([]byte("x")))
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}

	// 6. Test extra handler not attached
	resp, _ = client.Get("https://" + srv.Addr() + "/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}

	// 7. Attach and test
	extra := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	srv.SetExtraHandler(extra)

	resp, _ = client.Get("https://" + srv.Addr() + "/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("expected 202, got %d", resp.StatusCode)
	}

	// 8. Detach and test
	srv.SetExtraHandler(nil)
	resp, _ = client.Get("https://" + srv.Addr() + "/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
}

func TestInternalServerNilCheck(t *testing.T) {
	var s *internalServer
	s.SetExtraHandler(nil)
	s.Close()
}
