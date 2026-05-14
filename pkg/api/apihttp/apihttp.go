// Package apihttp holds HTTP helpers shared by every version of the public
// API (pkg/api/v1, pkg/api/v2, ...). It is intentionally a leaf package with
// no dependencies on pkg/api so version subpackages can import it without
// creating an import cycle through the top-level router.
package apihttp

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// WriteJSON serializes value as JSON and writes it with the given status.
func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// WriteError writes an error envelope using models.ErrorResponse so all API
// versions return errors in the same shape.
func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, models.ErrorResponse{Error: message})
}

// WriteStoreAwareError maps the small set of well-known service-layer error
// kinds to HTTP responses. The mapping (404 for missing sandboxes, 503 +
// Retry-After for capacity, 400 for everything else) is a contract clients
// depend on regardless of API version, so it lives here in the shared helper
// package.
func WriteStoreAwareError(logger *slog.Logger, w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	if errors.Is(err, store.ErrSnapshotNameConflict) {
		WriteError(w, http.StatusConflict, "snapshot name already in use")
		return
	}
	// Capacity rejections are 503 with a Retry-After hint so well-behaved
	// clients (and load balancers) back off instead of treating it as a
	// permanent 4xx. The error string already carries human-readable
	// reasons from the admitter.
	if errors.Is(err, capacity.ErrCapacityExceeded) {
		logger.Info("capacity rejected", "error", err)
		w.Header().Set("Retry-After", "30")
		msg := err.Error()
		if len(msg) > 200 {
			msg = msg[:200]
		}
		WriteError(w, http.StatusServiceUnavailable, msg)
		return
	}
	// Surface only the top-level error message; underlying causes (Docker
	// daemon strings, file paths) stay in the server log.
	logger.Warn("request failed", "error", err)
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	WriteError(w, http.StatusBadRequest, msg)
}
