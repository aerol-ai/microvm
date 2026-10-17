// Package identity is sandboxd's own named-credential layer
// (plans/identity-and-access.md §5.4, §5.5): the server-side half of
// identity that the CLI never imports.
//
// Task T3 puts the scoped API token (avm_…) here:
//
//   - TokenRecord, the replicated row: id, name, role, team, creator,
//     expiry and SHA-256 of the secret. Never the secret itself.
//   - TokenLookup, the one question the request path asks ("is this id a
//     live token, and can I vouch for my answer?"), answered from memory
//     only: TokenSet on a single node, the Raft FSM on a server, and
//     TokenMirror on every other cluster node.
//   - TokenAuthenticator, the apiToken link in pkg/api's authenticator
//     chain: checksum, local lookup, constant-time hash compare, expiry, and
//     the stale-mirror rule (CEO review D16).
//
// Task T6 puts SSO through OIDC here. sandboxd is a resource server, the
// same model as the Kubernetes API server with --oidc-issuer-url (§5.0,
// L1–L8): the company's identity provider logs the person in, and every
// node verifies the provider's token itself from the provider's published
// keys. There is no login service and no session.
//
//   - Config and Watcher: the identity file (SB_IDENTITY_FILE) with its
//     issuers, bindings and deny list, strictly loaded and hot-reloaded.
//   - Verifier, the jwt link in the same chain: offline signature and claim
//     checks, the bindings a token matches, and a verified-token cache that
//     holds the binding set, never a selected team (eng review E7).
//   - Summary and Diff: the identity_config evidence a file change writes
//     (CEO review D20).
//
// Task T13 adds OAuth for remote MCP (§5.14). An issuer's mcp_audiences are
// OAuth access-token audiences: the Verifier accepts such a token offline
// like an ID token and marks its Access MCPOnly, and the API edge accepts
// it only on /mcp and on a peer's forward marked X-Cluster-Surface: mcp.
// The file's mcp: section (resource, scopes) and its mcp: true issuers are
// what /mcp publishes as RFC 9728 metadata. An Entra v1 access token for a
// trusted tenant is refused with a hint naming the manifest setting.
//
// Nothing on the request path makes a network call or touches SQLite (L2,
// D21): an unknown or malformed token is a local miss. The verifier's only
// traffic is the issuer's JWKS, fetched at start, hourly, and at most once a
// minute per issuer on an unknown key id.
//
// The package is a leaf of the server tree. internal/cluster and
// internal/store import it for the record type; it imports neither.
package identity
