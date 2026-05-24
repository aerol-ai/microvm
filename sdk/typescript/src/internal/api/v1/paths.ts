// v1 path-prefix constant. The TypeScript SDK uses this to build URLs against
// the v1 surface of the sandbox daemon. When a new wire version lands, a
// sibling internal/api/vN/paths.ts will export its own PATH_PREFIX, and the
// client constructor's apiVersion option selects which one to use.
//
// Keep this in sync with pkg/api/v1/dto.go::PathPrefix on the server.
export const PATH_PREFIX = "/v1";

/**
 * Collection URL for a sandbox's custom-domain bindings. Used for both POST
 * (add) and GET (list). The DELETE variant lives at
 * {@link sandboxCustomDomainPath}.
 *
 * `id` is interpolated verbatim — sandbox IDs are server-generated opaque
 * tokens and already URL-safe.
 */
export function sandboxCustomDomainsPath(prefix: string, id: string): string {
  return `${prefix}/sandboxes/${id}/custom-domains`;
}

/**
 * URL for a single custom-domain binding. The hostname is percent-encoded so
 * IDN punycode (`xn--...`) and wildcard labels round-trip safely through
 * `DELETE /v1/sandboxes/{id}/custom-domains/{hostname}`.
 */
export function sandboxCustomDomainPath(prefix: string, id: string, hostname: string): string {
  return `${prefix}/sandboxes/${id}/custom-domains/${encodeURIComponent(hostname)}`;
}
