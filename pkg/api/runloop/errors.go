package runloop

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
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

func writeKnownError(w http.ResponseWriter, err error) bool {
	var reqErr requestError
	if errors.As(err, &reqErr) {
		WriteError(w, reqErr.status, reqErr.message)
		return true
	}
	return false
}

// writeStoreAwareError maps service errors onto statuses the SDK handles.
// It mirrors apihttp.WriteStoreAwareError; the facade keeps its own writer
// for the error body shape and the retry header.
func writeStoreAwareError(logger *slog.Logger, w http.ResponseWriter, err error) {
	if writeKnownError(w, err) {
		return
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		WriteError(w, http.StatusNotFound, "not found")
	case errors.Is(err, service.ErrSandboxManuallyStopped), errors.Is(err, service.ErrPublicTrafficDisabled):
		WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, service.ErrWakeCircuitOpen):
		w.Header().Set("Retry-After", "60")
		WriteError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, service.ErrEgressOperatorConfigInvalid):
		WriteError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, service.ErrEgressGatewayUnavailable), errors.Is(err, cluster.ErrNoEgressGatewayTarget):
		w.Header().Set("Retry-After", "5")
		WriteError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, models.ErrRuntimeNotImplemented):
		WriteError(w, http.StatusNotImplemented, err.Error())
	case errors.Is(err, store.ErrSnapshotNameConflict):
		WriteError(w, http.StatusConflict, "snapshot name already in use")
	case errors.Is(err, models.ErrSandboxExists):
		WriteError(w, http.StatusConflict, "devbox already exists")
	case errors.Is(err, capacity.ErrCapacityExceeded), errors.Is(err, cluster.ErrCapacityExceeded):
		if logger != nil {
			logger.Info("capacity rejected", "error", err)
		}
		w.Header().Set("Retry-After", strconv.Itoa(cluster.CapacityRetryAfterSeconds))
		WriteError(w, http.StatusServiceUnavailable, truncateMessage(err.Error()))
	case errors.Is(err, cluster.ErrCreateBackpressure):
		w.Header().Set("Retry-After", strconv.Itoa(cluster.CreateBackpressureRetryAfterSeconds))
		WriteError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, cluster.ErrNoPlacementTarget):
		w.Header().Set("Retry-After", strconv.Itoa(cluster.CapacityRetryAfterSeconds))
		WriteError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, cluster.ErrInvalidTopology):
		w.Header().Set("Retry-After", "300")
		WriteError(w, http.StatusServiceUnavailable, err.Error())
	default:
		if logger != nil {
			logger.Warn("runloop request failed", "error", err)
		}
		WriteError(w, http.StatusBadRequest, truncateMessage(err.Error()))
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
