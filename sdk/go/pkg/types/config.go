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
	// Retry configures the policy for transient transport errors and retryable
	// HTTP status codes (421, 429, 502, 503, 504). Exec is narrower: it is
	// re-sent only when the connection never opened or on 429/503, because a
	// re-sent exec runs the command again.
	Retry *RetryConfig
}

// RetryConfig specifies how the SDK should retry transient errors.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts after the initial
	// request fails. Set to a negative number to disable retry entirely.
	// Defaults to 3.
	MaxRetries *int
	// BaseDelayMs is the initial backoff delay in milliseconds. Defaults to 200.
	BaseDelayMs *int
	// MaxDelayMs is the hard ceiling on the computed delay. Defaults to 5000.
	MaxDelayMs *int
}
