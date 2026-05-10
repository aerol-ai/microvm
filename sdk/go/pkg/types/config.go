package types

import "net/http"

type MicroVMConfig struct {
	PATToken   string
	APIUrl     string
	HTTPClient *http.Client
	// APIVersion pins which wire version of the sandbox daemon API the
	// client speaks. Empty defaults to the SDK's pinned default ("v1"
	// today). The Go SDK's package version and the wire version evolve
	// independently — bumping the SDK doesn't move the wire version.
	APIVersion string
}
