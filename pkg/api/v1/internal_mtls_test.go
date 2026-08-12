package v1

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"expvar"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestWithInternalMTLSBoundary(t *testing.T) {
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	})
	guarded := withInternalMTLS(false, next)

	publicReq := httptest.NewRequest(http.MethodPost, "http://public/v1/cluster/internal/secrets", nil)
	publicRec := httptest.NewRecorder()
	guarded.ServeHTTP(publicRec, publicReq)
	if publicRec.Code != http.StatusForbidden || calls != 0 {
		t.Fatalf("public internal route = %d calls=%d, want 403 without dispatch", publicRec.Code, calls)
	}

	peerReq := httptest.NewRequest(http.MethodPost, "https://internal/v1/cluster/internal/secrets", nil)
	addVerifiedClientCertificate(peerReq, &x509.Certificate{DNSNames: []string{"aerolvm-cluster-node"}})
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
	guarded := withInternalMTLS(false, next)

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

	t.Run("legacy_san_increments_metric", func(t *testing.T) {
		before := readExpvarIntValue(t, "aerolvm_cluster_mtls_legacy_identity_total")
		req := httptest.NewRequest(http.MethodGet, "https://internal/v1/cluster/internal/secrets", nil)
		addVerifiedClientCertificate(req, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "aerolvm-cluster-node"},
			DNSNames: []string{"aerolvm-cluster-node"},
		})
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status=%d, want 204", rec.Code)
		}
		if got := readExpvarIntValue(t, "aerolvm_cluster_mtls_legacy_identity_total") - before; got != 1 {
			t.Fatalf("legacy identity metric delta=%d, want 1", got)
		}
	})

	t.Run("enterprise_rejects_legacy_only", func(t *testing.T) {
		ent := withInternalMTLS(true, next)
		req := httptest.NewRequest(http.MethodGet, "https://internal/v1/cluster/internal/secrets", nil)
		addVerifiedClientCertificate(req, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "aerolvm-cluster-node"},
			DNSNames: []string{"aerolvm-cluster-node"},
		})
		rec := httptest.NewRecorder()
		ent.ServeHTTP(rec, req)
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

func readExpvarIntValue(t *testing.T, name string) int64 {
	t.Helper()
	v := expvar.Get(name)
	if v == nil {
		t.Fatalf("expvar %q not registered", name)
	}
	n, err := strconv.ParseInt(v.String(), 10, 64)
	if err != nil {
		t.Fatalf("expvar %q value %q parse: %v", name, v.String(), err)
	}
	return n
}
