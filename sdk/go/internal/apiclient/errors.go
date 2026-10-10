package apiclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
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
)

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
	// RetryAfter is the server's Retry-After hint in seconds form, if any.
	RetryAfter time.Duration
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
	if secs, err := strconv.Atoi(strings.TrimSpace(response.Header.Get("Retry-After"))); err == nil && secs > 0 {
		apiErr.RetryAfter = time.Duration(secs) * time.Second
	}
	var payload models.ErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err == nil && payload.Error != "" {
		apiErr.Message = payload.Error
		apiErr.Code = payload.Code
	}
	return apiErr
}
