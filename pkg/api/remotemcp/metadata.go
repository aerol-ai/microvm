package remotemcp

import (
	"net/url"
	"strings"
)

// OAuth discovery for /mcp (plans/identity-and-access.md §5.14): RFC 9728
// protected-resource metadata and the 401 challenge that points at it. A
// connector such as claude.ai's starts with no token, gets the 401, reads
// resource_metadata, fetches this document, and signs the person in at one
// of the listed authorization servers (the company's identity provider).
// sandboxd stays a resource server: it hosts no authorization or
// registration endpoint and proxies none.

// MetadataPath is RFC 9728's well-known path. sandboxd serves it, and the
// path form for /mcp (MetadataPath + Path), only with identity on, remote MCP
// on and mcp.resource set in the identity file. Caddy's @api matcher forwards
// both (scripts/install.sh, packaging/Caddyfile.template).
const MetadataPath = "/.well-known/oauth-protected-resource"

// BearerMethodHeader is the only bearer method /mcp accepts for an OAuth
// token: the Authorization header (RFC 6750 §2.1).
const BearerMethodHeader = "header"

// ResourceMetadata is the body of GET MetadataPath (RFC 9728 §2).
type ResourceMetadata struct {
	// Resource is the identity file's mcp.resource, the /mcp URL.
	Resource string `json:"resource"`
	// AuthorizationServers are the issuers that set mcp: true.
	AuthorizationServers []string `json:"authorization_servers"`
	// ScopesSupported are the identity file's mcp.scopes, the scopes a
	// connector asks its provider for (Entra needs one naming the API app).
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

// MetadataURL is where resource's metadata lives (RFC 9728 §3.1): the
// well-known path inserted between the host and the resource's path, so
// https://api.acme.dev/mcp → https://api.acme.dev/.well-known/oauth-protected-resource/mcp.
// "" for a resource that is not an absolute URL.
func MetadataURL(resource string) string {
	u, err := url.Parse(resource)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + MetadataPath + strings.TrimSuffix(u.EscapedPath(), "/")
}

// ChallengeParams are the auth-params a /mcp 401 adds to its Bearer
// challenge (RFC 9728 §5.1): resource_metadata, and scope when the identity
// file lists scopes, so the connector asks for them (the MCP authorization
// spec reads the challenge's scope first). "" for a resource with no URL.
// Scopes are RFC 6749 scope-tokens (no space, quote or backslash, checked
// at identity-file load), so quoting them needs no escaping.
func ChallengeParams(resource string, scopes []string) string {
	meta := MetadataURL(resource)
	if meta == "" {
		return ""
	}
	params := `resource_metadata="` + meta + `"`
	if len(scopes) > 0 {
		params += `, scope="` + strings.Join(scopes, " ") + `"`
	}
	return params
}
