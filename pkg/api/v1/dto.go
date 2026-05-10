// Package v1 implements the v1 HTTP API for the sandbox daemon.
//
// All v1 routes are registered under PathPrefix ("/v1") via RegisterRoutes.
// The package owns its wire contract: handlers in this package are the only
// code allowed to decode request bodies or shape response bodies for v1.
//
// Versioning rules (soft freeze, see pr-review.md):
//   - Behavioral changes to v1 wire bodies, status codes, or paths are
//     forbidden once shipped. Add a new version package (pkg/api/v2) instead.
//   - Bug and security fixes that preserve wire compatibility are allowed.
//
// The service layer (internal/service) stays version-agnostic. v1 handlers
// translate v1 DTOs ↔ models.* and call into the shared service.
package v1

// PathPrefix is the URL prefix every v1 route is registered under.
// Keep this in sync with the v1 SDK clients (each SDK pins the same prefix
// in its internal/api/v1 module).
const PathPrefix = "/v1"

// Wire DTOs are currently shared with internal/service via pkg/models. As the
// surface evolves, v1-owned request/response types should move into this file
// so v2 can diverge without touching v1. Today this file intentionally holds
// only the path constant; the boundary is enforced by package-locality of
// handlers, not by separate types.
