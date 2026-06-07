package toolhost

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/statekv"
)

// StateKV exposes durable host-KV over toolbox HTTP for wasm runtime=durable workloads.
type StateKV interface {
	Get(ctx context.Context, sandboxID, key string) ([]byte, bool, error)
	Set(ctx context.Context, sandboxID, key string, value []byte) error
	Delete(ctx context.Context, sandboxID, key string) error
	ListKeys(ctx context.Context, sandboxID string) ([]string, error)
}

func (h *Host) handleStateKV(w http.ResponseWriter, r *http.Request) {
	if h.stateKV == nil {
		writeError(w, http.StatusNotImplemented, "statekv not configured")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/state/kv")
	path = strings.TrimPrefix(path, "/")
	key := strings.TrimSpace(path)
	switch r.Method {
	case http.MethodGet:
		if key == "" {
			keys, err := h.stateKV.ListKeys(r.Context(), h.sandboxID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
			return
		}
		if err := statekv.ValidateKey(key); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		value, ok, err := h.stateKV.Get(r.Context(), h.sandboxID, key)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, "key not found")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(value)
	case http.MethodPut:
		if key == "" {
			writeError(w, http.StatusBadRequest, "key required in path")
			return
		}
		if err := statekv.ValidateKey(key); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20+1))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := statekv.ValidateValue(body); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := h.stateKV.Set(r.Context(), h.sandboxID, key, body); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case http.MethodDelete:
		if key == "" {
			writeError(w, http.StatusBadRequest, "key required in path")
			return
		}
		if err := statekv.ValidateKey(key); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := h.stateKV.Delete(r.Context(), h.sandboxID, key); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
