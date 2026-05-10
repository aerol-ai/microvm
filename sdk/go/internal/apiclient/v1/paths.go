// Package v1 holds wire-version-1 constants for the Go SDK.
//
// PathPrefix is the URL prefix every v1 route is published under on the
// sandbox daemon. When v2 lands, a sibling sdk/go/internal/apiclient/v2
// package will export its own PathPrefix, and the public Client config's
// APIVersion field selects which one to use.
//
// Keep this in sync with pkg/api/v1/dto.go::PathPrefix on the server.
package v1

const PathPrefix = "/v1"
