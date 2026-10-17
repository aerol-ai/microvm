package identitywire

import "strings"

// The sign-in discovery document (plans/identity-and-access.md §5.6, design
// review DR3 and DR9). sandboxd serves it unauthenticated at
// AuthDiscoveryPath so the CLI (`aerolvm login`) and the dashboard can find
// the identity providers people sign in with before they hold any
// credential. It lives here, not in the server, because the CLI decodes it
// and must not import server packages.

// AuthDiscoveryPath is where sandboxd serves AuthDiscovery. Caddy's @api
// matcher forwards it (scripts/install.sh, packaging/Caddyfile.template).
const AuthDiscoveryPath = "/.well-known/aerolvm-auth"

// AuthDiscoveryVersion is the document shape this build writes.
const AuthDiscoveryVersion = 1

// Issuer kinds. IssuerKindGoogle switches the dashboard to Google Identity
// Services (§5.7); every other provider is a generic OIDC issuer.
const (
	IssuerKindOIDC   = "oidc"
	IssuerKindGoogle = "google"
)

// AuthDiscovery is the body of GET /.well-known/aerolvm-auth.
type AuthDiscovery struct {
	Version int `json:"version"`
	// IdentityEnabled reports whether this server accepts named
	// credentials (avm_ tokens, SSO) at all (SB_IDENTITY_ENABLED). With it
	// off the operator token is the only credential and Issuers is empty.
	IdentityEnabled bool `json:"identity_enabled"`
	// Issuers lists the providers a person can sign in with, in
	// identity-file order. Only issuers with a CLI or dashboard client id
	// are listed: a workload issuer (GitHub Actions, a Kubernetes cluster)
	// has no browser or CLI sign-in, and its URL is nobody's business.
	Issuers []DiscoveryIssuer `json:"issuers"`
	// UIURL is the dashboard's HTTPS address, https://<SB_DOMAIN>/ui (DR9).
	// The dashboard points a plain-HTTP visitor at it, since providers only
	// accept sign-in redirects to HTTPS or localhost. Omitted when the
	// server has no domain.
	UIURL string `json:"ui_url,omitempty"`
}

// DiscoveryIssuer is one identity provider.
type DiscoveryIssuer struct {
	// Name is the issuer's stable identity-file name. It is the <issuer>
	// in oidc:<issuer>:<sub> principal ids and the `issuer` field of a
	// "no binding" 403.
	Name string `json:"name"`
	// DisplayName labels the sign-in button ("Sign in with Acme Okta").
	// It falls back to Name, so it is never empty.
	DisplayName string `json:"display_name"`
	// Kind is IssuerKindOIDC or IssuerKindGoogle.
	Kind string `json:"kind"`
	// URL is the issuer URL: the token's `iss`, and the base of the
	// provider's own OIDC discovery.
	URL string `json:"url"`
	// Clients holds the public client ids the CLI and the dashboard sign
	// in with. Neither is a secret (both are PKCE public clients).
	Clients DiscoveryClients `json:"clients"`
}

// DiscoveryClients are an issuer's public client ids.
type DiscoveryClients struct {
	CLI       string `json:"cli,omitempty"`
	Dashboard string `json:"dashboard,omitempty"`
}

// UIURL returns the dashboard URL for domain, or "" when there is none.
func UIURL(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	return "https://" + domain + "/ui"
}
