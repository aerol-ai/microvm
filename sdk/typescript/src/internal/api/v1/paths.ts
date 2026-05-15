// v1 path-prefix constant. The TypeScript SDK uses this to build URLs against
// the v1 surface of the sandbox daemon. When a new wire version lands, a
// sibling internal/api/vN/paths.ts will export its own PATH_PREFIX, and the
// client constructor's apiVersion option selects which one to use.
//
// Keep this in sync with pkg/api/v1/dto.go::PathPrefix on the server.
export const PATH_PREFIX = "/v1";
