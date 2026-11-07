package api

import (
	"errors"
	"net/http"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// The issuer's public documents (plans/sandbox-cloud-identity.md D1.1,
// security point 4). Both are on the public route allowlist
// (route_registry_test.go): AWS, GCP and Azure fetch them anonymously over
// HTTPS. They are read-only and hold public keys only; with
// SB_IDENTITY_ISSUER_URL unset they 404, so a deployment that is not an
// issuer looks like one that never heard of OIDC.

// identityDocumentMaxAge lets clouds and proxies cache the documents for
// five minutes: a rotated key is in the JWKS two hours before its tokens
// stop verifying, and the new key signs only tokens fetched after it.
const identityDocumentMaxAge = "public, max-age=300"

func (s *Server) handleIdentityDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc, err := s.service.IdentityDiscovery()
	if err != nil {
		writeIdentityDocumentError(w, err)
		return
	}
	writeIdentityDocument(w, doc)
}

func (s *Server) handleIdentityJWKS(w http.ResponseWriter, r *http.Request) {
	if !s.service.IdentityEnabled() {
		writeIdentityDocumentError(w, service.ErrIdentityDisabled)
		return
	}
	doc, err := s.service.IdentityJWKS(r.Context())
	if err != nil {
		// The cause (no leader, an unreachable store) is for the log; the
		// public answer never says more than "try again".
		s.logger.Warn("identity: JWKS unavailable", "error", err)
		writeIdentityDocumentError(w, err)
		return
	}
	writeIdentityDocument(w, doc)
}

func writeIdentityDocument(w http.ResponseWriter, doc []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", identityDocumentMaxAge)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc)
}

func writeIdentityDocumentError(w http.ResponseWriter, err error) {
	if errors.Is(err, service.ErrIdentityDisabled) {
		apihttp.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Retry-After", "5")
	apihttp.WriteError(w, http.StatusServiceUnavailable, "identity keys are unavailable; retry shortly")
}
