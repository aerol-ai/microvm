package e2b

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

type errorResponse struct {
	Code    int    `json:"code"`
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

func conflict(message string) error {
	return requestError{status: http.StatusConflict, message: message}
}

func serviceUnavailable(message string) error {
	return requestError{status: http.StatusServiceUnavailable, message: message}
}

func notImplemented(message string) error {
	return requestError{status: http.StatusNotImplemented, message: message}
}

// WriteError writes the E2B error envelope shape expected by the SDK.
func WriteError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Code: status, Message: message})
}

// writeErrorCode is the clustercreate.ErrorWriter for E2B: its envelope has
// no code field, so the code is dropped and only status + message are written.
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

func writeStoreAwareError(logger *slog.Logger, w http.ResponseWriter, err error) {
	if writeKnownError(w, err) {
		return
	}
	c := apihttp.Classify(err)
	c.Apply(logger, err)
	c.SetRetryAfter(w)
	WriteError(w, c.Status, e2bMessage(c))
}

// e2bMessage keeps the E2B SDK's wording for the few errors it words
// differently; everything else uses the shared classification message.
func e2bMessage(c apihttp.Classification) string {
	switch c.Kind {
	case apihttp.ErrKindNotFound:
		return "Not found"
	case apihttp.ErrKindSnapshotNameConflict:
		return "Snapshot name already in use"
	case apihttp.ErrKindSandboxExists:
		return "Sandbox already exists"
	case apihttp.ErrKindSandboxNotRunning:
		return "Sandbox is not running"
	case apihttp.ErrKindSandboxNotResumable:
		return "Sandbox is not available for connect"
	default:
		return c.Message
	}
}
