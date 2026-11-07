// Package cloudidentity makes sandboxd an OIDC issuer for its sandboxes
// (plans/sandbox-cloud-identity.md). Code inside a sandbox gets a short-lived
// token signed by the deployment's key; the customer's cloud (AWS IAM, Azure
// federated credentials, GCP workload identity federation) trusts the
// published public keys and swaps the token for its own short-lived
// credentials. This is the IRSA / Workload Identity model without
// Kubernetes.
//
// The package is a leaf: key generation, the key set and its rotation
// rules, the JWKS and discovery documents, the claim set and signing. It
// never seals, stores or replicates anything (internal/service does, through
// the store or the Raft FSM) and it never logs. The verifying half of OIDC,
// for other issuers' tokens, is internal/identity.
//
// Security invariants this package carries (design section 7):
//
//   - RS256 with RSA-2048 only (D1.2): the one algorithm AWS, GCP and Azure
//     all accept. A key under 2048 bits is refused when parsed.
//   - The private key is never serialised except by MarshalPrivateKey, whose
//     only caller seals the result. KeyRecord holds the sealed bytes.
//   - The subject is built only by Subject, from an owner ref and a role
//     tag that ValidateRoleTag accepted; neither can carry ':' unescaped,
//     so one owner's subject can never be read as another's (point 6).
//   - Lifetime is fixed: nbf = issue - 60 s, exp = issue + 1 h (point 7).
package cloudidentity
