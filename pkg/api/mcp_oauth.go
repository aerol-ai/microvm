package api

import (
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/remotemcp"
)

// OAuth for remote MCP (plans/identity-and-access.md §5.14, CEO review D10):
// the two public RFC 9728 metadata routes and the /mcp 401 challenge. The
// rest of the feature sits where each credential is decided: the verifier
// marks an mcp_audiences token MCPOnly (internal/identity), the surface rule
// refuses it off /mcp (auth.go enforceSurface), and the Access hand-off lets
// /mcp's tools call the API without checking it again (remotemcp).

// MCPResource is what the identity file says about /mcp: its protected-
// resource URL (mcp.resource), the issuers that set mcp: true, and the
// scopes a connector should ask for. A zero Resource means none is
// configured: no metadata, no challenge.
type MCPResource struct {
	Resource             string
	AuthorizationServers []string
	Scopes               []string
}

// WithMCPResource supplies the identity file's /mcp resource, read at each
// request so a reloaded file shows at once. The daemon passes the identity-
// file watcher's; NewServer drops it with identity off (L8), and the
// metadata routes exist only with remote MCP on as well.
func WithMCPResource(resource func() MCPResource) ServerOption {
	return func(o *serverOptions) { o.mcpResource = resource }
}

// currentMCPResource is the resource in force, or the zero value when none
// is configured (identity off, no identity file, no mcp.resource).
func (s *Server) currentMCPResource() MCPResource {
	if s.mcpResource == nil {
		return MCPResource{}
	}
	return s.mcpResource()
}

// mcpChallengeParams are the auth-params a /mcp 401 leads its Bearer
// challenge with, or "" when no resource is configured, which keeps every
// 401 byte for byte as before (L8).
func (s *Server) mcpChallengeParams() string {
	res := s.currentMCPResource()
	if res.Resource == "" {
		return ""
	}
	return remotemcp.ChallengeParams(res.Resource, res.Scopes)
}

// registerMCPMetadata mounts the RFC 9728 document at its root form and at
// its path form for /mcp. Both are public by design (route_registry_test.go's
// allowlist): a connector reads them before it holds any credential, and
// they carry only what a sign-in page shows anyway, the resource URL and the
// issuer URLs.
func (s *Server) registerMCPMetadata(mux apihttp.Mux) {
	h := http.HandlerFunc(s.handleMCPResourceMetadata)
	mux.Handle("GET "+remotemcp.MetadataPath, h)
	mux.Handle("GET "+remotemcp.MetadataPath+remotemcp.Path, h)
}

// handleMCPResourceMetadata serves the protected-resource metadata, or the
// mux's own 404 while no mcp.resource is configured (no good identity file
// yet, or a file without one).
func (s *Server) handleMCPResourceMetadata(w http.ResponseWriter, r *http.Request) {
	res := s.currentMCPResource()
	if res.Resource == "" {
		http.NotFound(w, r)
		return
	}
	doc := remotemcp.ResourceMetadata{
		Resource:               res.Resource,
		AuthorizationServers:   res.AuthorizationServers,
		ScopesSupported:        res.Scopes,
		BearerMethodsSupported: []string{remotemcp.BearerMethodHeader},
	}
	if doc.AuthorizationServers == nil {
		doc.AuthorizationServers = []string{}
	}
	// A reload must show at once, and the body is a few hundred bytes.
	w.Header().Set("Cache-Control", "no-store")
	apihttp.WriteJSON(w, http.StatusOK, doc)
}
