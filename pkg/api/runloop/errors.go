package runloop

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// errorResponse is the error body the Runloop SDKs read: TS surfaces
// `message`, Python prints the whole body.
type errorResponse struct {
	Message string `json:"message"`
}

type requestError struct {
	status  int
	message string
}

func (e requestError) Error() string { return e.message }

func badRequest(message string) error {
	return requestError{status: http.StatusBadRequest, message: message}
}

func notFound(message string) error {
	return requestError{status: http.StatusNotFound, message: message}
}

func conflict(message string) error {
	return requestError{status: http.StatusConflict, message: message}
}

func notImplemented(message string) error {
	return requestError{status: http.StatusNotImplemented, message: message}
}

// WriteError writes the Runloop error body. Both SDKs retry 408, 409, 429
// and every 5xx up to five times with backoff, POSTs included, so a status
// in that set that retrying cannot fix carries x-should-retry: false.
// Without it a 501 or a permanent conflict costs the caller ~30s of
// pointless retries before the error surfaces.
func WriteError(w http.ResponseWriter, status int, message string) {
	if !retryable(status) {
		w.Header().Set("x-should-retry", "false")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Message: message})
}

// retryable reports whether a status the SDKs would retry is worth
// retrying. 503 and 429 are capacity/backpressure, 408 is a long-poll
// expiry, 502/504 are an unreachable owner or toolbox — all transient.
// 409 and 500/501 from this facade are not.
func retryable(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusMisdirectedRequest:
		return true
	}
	return status < http.StatusConflict
}

// writeErrorCode is the clustercreate.ErrorWriter for Runloop: the code is
// dropped (Runloop's envelope has none) and WriteError adds x-should-retry.
func writeErrorCode(w http.ResponseWriter, status int, _, message string) {
	WriteError(w, status, message)
}

func writeKnownError(w http.ResponseWriter, err error) bool {
	var reqErr requestError
	if errors.As(err, &reqErr) {
		WriteError(w, reqErr.status, reqErr.message)
		return true
	}
	return false
}

// writeStoreAwareError maps service errors onto statuses the SDK handles,
// through the one shared classifier (apihttp.Classify). The facade keeps its
// own WriteError for the error-body shape and the x-should-retry header.
func writeStoreAwareError(logger *slog.Logger, w http.ResponseWriter, err error) {
	if writeKnownError(w, err) {
		return
	}
	c := apihttp.Classify(err)
	c.Apply(logger, err)
	c.SetRetryAfter(w)
	WriteError(w, c.Status, runloopMessage(c))
}

// runloopMessage keeps the Runloop SDK's wording for the few errors it words
// differently; everything else uses the shared classification message.
func runloopMessage(c apihttp.Classification) string {
	switch c.Kind {
	case apihttp.ErrKindNotFound:
		return "not found"
	case apihttp.ErrKindSandboxExists:
		return "devbox already exists"
	case apihttp.ErrKindSandboxNotRunning:
		return "devbox is not running"
	case apihttp.ErrKindSandboxNotResumable:
		return "devbox is not suspended"
	default:
		return c.Message
	}
}

func truncateMessage(message string) string {
	if len(message) > 200 {
		return message[:200]
	}
	return message
}

// writeJSON always sets the JSON content type: the TS SDK only parses a
// body whose media type is application/json and otherwise hands the caller
// a raw string, so a missing header reads as every field being undefined.
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
