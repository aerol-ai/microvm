package v1

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithInternalMTLSBoundary(t *testing.T) {
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	})
	guarded := withInternalMTLS(next)

	publicReq := httptest.NewRequest(http.MethodPost, "http://public/v1/cluster/internal/secrets", nil)
	publicRec := httptest.NewRecorder()
	guarded.ServeHTTP(publicRec, publicReq)
	if publicRec.Code != http.StatusForbidden || calls != 0 {
		t.Fatalf("public internal route = %d calls=%d, want 403 without dispatch", publicRec.Code, calls)
	}

	peerReq := httptest.NewRequest(http.MethodPost, "https://internal/v1/cluster/internal/secrets", nil)
	addVerifiedClientCertificate(peerReq)
	peerRec := httptest.NewRecorder()
	guarded.ServeHTTP(peerRec, peerReq)
	if peerRec.Code != http.StatusNoContent || calls != 1 {
		t.Fatalf("mTLS internal route = %d calls=%d, want 204 and dispatch", peerRec.Code, calls)
	}
}

func addVerifiedClientCertificate(req *http.Request) {
	peerCert := &x509.Certificate{}
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{peerCert},
		VerifiedChains:   [][]*x509.Certificate{{peerCert}},
	}
}
