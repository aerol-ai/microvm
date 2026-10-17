package api

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// WithAuthDiscovery supplies the issuers GET /.well-known/aerolvm-auth
// publishes, read at each request so a reloaded identity file shows at
// once. The daemon passes the identity-file watcher's issuers; without it
// (or with identity off) the document lists none.
func WithAuthDiscovery(issuers func() []identitywire.DiscoveryIssuer) ServerOption {
	return func(o *serverOptions) { o.discovery = issuers }
}

// handleAuthDiscovery serves the sign-in discovery document (§5.6, DR3,
// DR9). It is public by design (route_registry_test.go's allowlist): a
// person needs it before they hold any credential, and it carries only
// what a sign-in page shows anyway, public client ids and issuer URLs.
func (s *Server) handleAuthDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := identitywire.AuthDiscovery{
		Version:         identitywire.AuthDiscoveryVersion,
		IdentityEnabled: s.identityEnabled,
		Issuers:         []identitywire.DiscoveryIssuer{},
		UIURL:           identitywire.UIURL(s.domain),
	}
	if s.identityEnabled && s.discovery != nil {
		if issuers := s.discovery(); issuers != nil {
			doc.Issuers = issuers
		}
	}
	// A reload must show at once, and the body is a few hundred bytes.
	w.Header().Set("Cache-Control", "no-store")
	apihttp.WriteJSON(w, http.StatusOK, doc)
}
