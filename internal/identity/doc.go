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
// Nothing on the request path makes a network call or touches SQLite (L2,
// D21): an unknown or malformed token is a local miss.
//
// The package is a leaf of the server tree. internal/cluster and
// internal/store import it for the record type; it imports neither.
package identity
