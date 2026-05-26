// Package apihttp holds HTTP helpers shared by every version of the public
// API (pkg/api/v1, ...). It is intentionally a leaf package with no
// dependencies on pkg/api so version subpackages can import it without
// creating an import cycle through the top-level router.
package apihttp

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
// kinds to HTTP responses. The mapping (404 for missing sandboxes, 503 for
// capacity/topology admission failures, 400 for everything else) is a contract
// clients depend on regardless of API version, so it lives here in the shared
// helper package.
func WriteStoreAwareError(logger *slog.Logger, w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	// Wake-aware proxy sentinels (plans/serverless-sandbox-http-wake.md).
	// 409 for manual-stop: the operator explicitly stopped the sandbox
	// and the wake helper refused to auto-resume; the caller must
	// StartSandbox first. 503+Retry-After:60 for circuit-open: the
	// per-sandbox breaker has tripped after consecutive wake failures
	// (D3); back off the full open window before retrying.
	if errors.Is(err, service.ErrSandboxManuallyStopped) {
		WriteError(w, http.StatusConflict, err.Error())
		return
	}
	if errors.Is(err, service.ErrWakeCircuitOpen) {
		w.Header().Set("Retry-After", "60")
		WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if errors.Is(err, store.ErrSnapshotNameConflict) {
		WriteError(w, http.StatusConflict, "snapshot name already in use")
		return
	}
	// Firecracker template sentinels (plans/snapshot-clone-fast-boot.md
	// Phase 2). 409 on both: ErrTemplateIDConflict surfaces a PK collision
	// when an operator POSTs the same explicit id twice (idempotency
	// signal — the row already exists), and ErrTemplateInUse blocks a
	// DELETE while a sandbox still references the template (forces the
	// operator to destroy the sandbox first rather than yank rootfs out
	// from under a live Firecracker guest).
	if errors.Is(err, store.ErrTemplateIDConflict) || errors.Is(err, store.ErrTemplateInUse) {
		WriteError(w, http.StatusConflict, err.Error())
		return
	}
	// Custom-domain sentinels (plans/custom-domains.md). 412 distinguishes
	// "this deployment can't do custom domains at all" (feature flag off /
	// IP mode) from "your input is malformed" (400). 409 covers both the
	// cross-sandbox hostname conflict and the IRON RULE (tcp/tls + custom
	// domain on the same sandbox) and the per-sandbox cap.
	if errors.Is(err, models.ErrCustomDomainNotSupported) {
		WriteError(w, http.StatusPreconditionFailed, err.Error())
		return
	}
	if errors.Is(err, models.ErrCustomDomainProtocolConflict) ||
		errors.Is(err, models.ErrCustomDomainPerSandboxCap) ||
		errors.Is(err, store.ErrCustomDomainConflict) {
		WriteError(w, http.StatusConflict, err.Error())
		return
	}
	// Capacity rejections are 503 with a Retry-After hint so well-behaved
	// clients (and load balancers) back off instead of treating it as a
	// permanent 4xx. The error string already carries human-readable
	// reasons from the admitter.
	if errors.Is(err, capacity.ErrCapacityExceeded) || errors.Is(err, cluster.ErrCapacityExceeded) {
		logger.Info("capacity rejected", "error", err)
		w.Header().Set("Retry-After", strconv.Itoa(cluster.CapacityRetryAfterSeconds))
		msg := err.Error()
		if len(msg) > 200 {
			msg = msg[:200]
		}
		WriteError(w, http.StatusServiceUnavailable, msg)
		return
	}
	if errors.Is(err, cluster.ErrCreateBackpressure) {
		w.Header().Set("Retry-After", strconv.Itoa(cluster.CreateBackpressureRetryAfterSeconds))
		WriteError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	if errors.Is(err, cluster.ErrNoPlacementTarget) || errors.Is(err, cluster.ErrInvalidTopology) {
		if errors.Is(err, cluster.ErrInvalidTopology) {
			w.Header().Set("Retry-After", strconv.Itoa(cluster.InvalidTopologyRetryAfterSeconds))
		}
		WriteError(w, http.StatusServiceUnavailable, err.Error())
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
