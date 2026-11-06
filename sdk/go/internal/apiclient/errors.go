package apiclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Sentinels matched by errors.Is against an *APIError (by HTTP status) or a
// wrapped client-side error. Callers branch on them instead of parsing text.
var (
	// ErrNotFound matches a 404 and a by-name lookup that found nothing.
	ErrNotFound = errors.New("not found")
	// ErrConflict matches a 409, e.g. a create whose name the caller holds.
	ErrConflict = errors.New("conflict")
	// ErrNameLookupUnsupported means the server ignored ?name= (it predates
	// name lookup), so its reply can't identify a sandbox.
	ErrNameLookupUnsupported = errors.New("sandbox name lookup not supported by this server")
	// ErrUnsupportedFeature means the sandbox's agent (toolboxd) is older
	// than an option the call needs. An older agent would silently ignore
	// the option, so the SDK refuses instead of sending it. Match the
	// details with errors.As on *UnsupportedFeatureError.
	ErrUnsupportedFeature = errors.New("sandbox agent does not support this feature")
	// ErrFileTooLarge means a download was larger than its MaxBytes.
	ErrFileTooLarge = errors.New("file is larger than the download limit")
)

// UnsupportedFeatureError names the sandbox and the features its agent did
// not list on /version. errors.Is(err, ErrUnsupportedFeature) matches it.
type UnsupportedFeatureError struct {
	SandboxID    string
	Features     []string
	AgentVersion string
	// Runtime is set (for example "wasm") when the sandbox's runtime cannot
	// offer the features at all; a restart does not help there.
	Runtime string
}

func (e *UnsupportedFeatureError) Error() string {
	if e.Runtime != "" {
		return fmt.Sprintf("sandbox %s is a %s sandbox, which does not support %s",
			e.SandboxID, runtimeDisplayName(e.Runtime), strings.Join(e.Features, ", "))
	}
	agent := "an older toolboxd"
	if e.AgentVersion != "" {
		agent = "toolboxd " + e.AgentVersion
	}
	return fmt.Sprintf("sandbox %s runs %s, which does not support %s; restart the sandbox, or re-create its Firecracker template, to get the current agent",
		e.SandboxID, agent, strings.Join(e.Features, ", "))
}

func (e *UnsupportedFeatureError) Unwrap() error { return ErrUnsupportedFeature }

func runtimeDisplayName(runtime string) string {
	switch runtime {
	case "wasm":
		return "WebAssembly"
	case "isolate":
		return "V8 isolate"
	}
	return runtime
}

// StreamError is a failure the toolbox reported on an exec or session
// stream (an "error" frame: the command could not start, say), as opposed
// to the stream itself dropping. Error() returns the toolbox's message
// unchanged.
type StreamError struct {
	Message string
}

func (e *StreamError) Error() string { return e.Message }

// APIError is an HTTP error response from sandboxd. Error() returns the
// server's message unchanged, so callers that printed or matched the plain
// error text before this type existed see the same string.
type APIError struct {
	// StatusCode is the HTTP status of the final attempt.
	StatusCode int
	// Code is models.ErrorResponse.Code when the server sent one.
	Code string
	// Message is models.ErrorResponse.Error, or a status-based fallback.
	Message string
	// RetryAfter is how long the server's Retry-After asked the caller to
	// wait (delta-seconds or HTTP-date form), or zero without one.
	RetryAfter time.Duration
	// Reason says why the server refused an avm_ API token or an OIDC
	// token. On a 401: expired, not_yet_valid, unknown_issuer,
	// wrong_audience, too_long_lived, invalid_signature, malformed or
	// unknown_or_revoked. On a 403 for an OIDC token no role binding
	// matched: no_binding or group_overage. Empty for every other error,
	// the operator token's 401 included.
	Reason string
	// RequiredPermission and Role are set on a 403 for an API token or an
	// OIDC caller: the permission the route needs and the role the caller
	// holds. Message then carries the hint naming the role that would allow
	// it.
	RequiredPermission string
	Role               string
	// Issuer, Name and Groups are set on the 403 an OIDC caller gets when
	// no binding matches its token: the issuer it signed in through, its
	// display name and its groups (none on group_overage). All three are
	// the caller's own claims, so it can ask an admin for the right binding.
	Issuer string
	Name   string
	Groups []string
}

func (e *APIError) Error() string { return e.Message }

// Is maps HTTP statuses onto the package sentinels.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound
	case ErrConflict:
		return e.StatusCode == http.StatusConflict
	}
	return false
}

// Retryable reports whether the request may succeed if sent again unchanged:
// the statuses the client's own retry loop treats as transient.
func (e *APIError) Retryable() bool { return isRetryableStatusCode(e.StatusCode) }

func decodeError(response *http.Response) error {
	apiErr := &APIError{
		StatusCode: response.StatusCode,
		Message:    fmt.Sprintf("request failed with status %d", response.StatusCode),
	}
	if after, ok := parseRetryAfter(response.Header.Get("Retry-After"), time.Now()); ok {
		apiErr.RetryAfter = after
	}
	var payload models.ErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err == nil && payload.Error != "" {
		apiErr.Message = payload.Error
		apiErr.Code = payload.Code
		apiErr.Reason = payload.Reason
		apiErr.RequiredPermission = payload.RequiredPermission
		apiErr.Role = payload.Role
		apiErr.Issuer = payload.Issuer
		apiErr.Name = payload.Name
		apiErr.Groups = payload.Groups
	}
	return apiErr
}
