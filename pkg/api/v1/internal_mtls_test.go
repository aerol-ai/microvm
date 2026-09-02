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
	guarded := withInternalMTLS(Deps{}, next)

	publicReq := httptest.NewRequest(http.MethodPost, "http://public/v1/cluster/internal/secrets", nil)
	publicRec := httptest.NewRecorder()
	guarded.ServeHTTP(publicRec, publicReq)
	if publicRec.Code != http.StatusForbidden || calls != 0 {
		t.Fatalf("public internal route = %d calls=%d, want 403 without dispatch", publicRec.Code, calls)
	}

	peerReq := httptest.NewRequest(http.MethodPost, "https://internal/v1/cluster/internal/secrets", nil)
	addVerifiedClientCertificate(peerReq, &x509.Certificate{DNSNames: []string{"aerolvm-cluster-node", "node:worker-boundary"}})
	peerRec := httptest.NewRecorder()
	guarded.ServeHTTP(peerRec, peerReq)
	if peerRec.Code != http.StatusNoContent || calls != 1 {
		t.Fatalf("mTLS internal route = %d calls=%d, want 204 and dispatch", peerRec.Code, calls)
	}
}

func TestWithInternalMTLSNodeIdentity(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	guarded := withInternalMTLS(Deps{}, next)

	t.Run("matching_header_and_san", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://internal/v1/cluster/internal/secrets", nil)
		addVerifiedClientCertificate(req, &x509.Certificate{DNSNames: []string{"aerolvm-cluster-node", "node:worker-1"}})
		req.Header.Set(clusterPeerNodeIDHeader, "worker-1")
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status=%d, want 204", rec.Code)
		}
	})

	t.Run("mismatched_header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://internal/v1/cluster/internal/secrets", nil)
		addVerifiedClientCertificate(req, &x509.Certificate{DNSNames: []string{"node:worker-1"}})
		req.Header.Set(clusterPeerNodeIDHeader, "worker-2")
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status=%d, want 403", rec.Code)
		}
	})

	t.Run("shared_san_without_node_identity_is_rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://internal/v1/cluster/internal/secrets", nil)
		addVerifiedClientCertificate(req, &x509.Certificate{
			DNSNames: []string{"aerolvm-cluster-node"},
		})
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status=%d, want 403", rec.Code)
		}
	})
}

func addVerifiedClientCertificate(req *http.Request, peerCert *x509.Certificate) {
	if peerCert == nil {
		peerCert = &x509.Certificate{}
	}
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{peerCert},
		VerifiedChains:   [][]*x509.Certificate{{peerCert}},
	}
}
