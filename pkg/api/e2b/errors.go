package e2b

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
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
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "Not found")
		return
	}
	if errors.Is(err, store.ErrSnapshotNameConflict) {
		WriteError(w, http.StatusConflict, "Snapshot name already in use")
		return
	}
	if errors.Is(err, capacity.ErrCapacityExceeded) {
		if logger != nil {
			logger.Info("capacity rejected", "error", err)
		}
		w.Header().Set("Retry-After", "30")
		message := err.Error()
		if len(message) > 200 {
			message = message[:200]
		}
		WriteError(w, http.StatusServiceUnavailable, message)
		return
	}
	if errors.Is(err, cluster.ErrNoPlacementTarget) || errors.Is(err, cluster.ErrInvalidTopology) {
		if errors.Is(err, cluster.ErrInvalidTopology) {
			w.Header().Set("Retry-After", "300")
		}
		WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if logger != nil {
		logger.Warn("e2b request failed", "error", err)
	}
	message := err.Error()
	if len(message) > 200 {
		message = message[:200]
	}
	WriteError(w, http.StatusBadRequest, message)
}
