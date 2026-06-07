package toolhost

import (
	"net/http"
	"strings"
)

func (h *Host) handleSessionsRoute(w http.ResponseWriter, r *http.Request) bool {
	path := strings.TrimPrefix(r.URL.Path, "/sessions")
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		switch r.Method {
		case http.MethodPost:
			writeError(w, http.StatusNotImplemented, "wasm sessions are not implemented yet")
			return true
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]any{"sessions": []any{}})
			return true
		}
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return true
	}
	writeError(w, http.StatusNotImplemented, "wasm sessions are not implemented yet")
	return true
}
