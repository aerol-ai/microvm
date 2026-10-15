// Package apihttp holds HTTP helpers shared by every version of the public
// API (pkg/api/v1, ...). It is intentionally a leaf package with no
// dependencies on pkg/api so version subpackages can import it without
// creating an import cycle through the top-level router.
package apihttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// admissionRetryAfterSeconds is the Retry-After hint sent with a 503 when the
// fleet admitter cannot vouch for a caller yet (standing not known). Short, so
// a client retries promptly once the control plane's first standing poll lands.
const admissionRetryAfterSeconds = 15

// MaxJSONBodyBytes caps JSON request bodies decoded via DecodeJSON. Control
// requests are small (a create payload with env vars is well under 64 KiB);
// the cap exists so an authed caller can't balloon daemon memory with a
// multi-GiB body. Bulk payloads (file uploads, build contexts) stream through
// dedicated handlers and don't go through DecodeJSON.
const MaxJSONBodyBytes = 1 << 20 // 1 MiB

// DecodeJSON decodes a JSON request body into dst with the body capped at
// MaxJSONBodyBytes. All versioned handlers must use this instead of
// json.NewDecoder(r.Body) directly so the size cap is uniform across v1 and
// the facades. The caller writes its own error envelope on failure.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	return DecodeJSONLimit(w, r, dst, MaxJSONBodyBytes)
}

// DecodeJSONLimit decodes a JSON request using an endpoint-specific maximum.
// Keep exceptional limits at the handler so the shared public API default does
// not grow merely because one internal wire format contains base64 expansion.
func DecodeJSONLimit(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = MaxJSONBodyBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

// ReadJSONBody applies the same cap for cluster wrappers that must buffer and
// replay a request before choosing a local or peer handler.
func ReadJSONBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxJSONBodyBytes)
	return io.ReadAll(r.Body)
}

// DecodeAndBufferJSON reads the request body (bounded), decodes it into dst
// with the same single-value strictness as DecodeJSON, and restores r.Body to
// the original bytes. A create handler uses it so that when clustercreate
// forwards the request to the placement target, the target re-reads the full
// body instead of an empty one (plan B2). Returns the raw bytes.
func DecodeAndBufferJSON(w http.ResponseWriter, r *http.Request, dst any) ([]byte, error) {
	raw, err := ReadJSONBody(w, r)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dst); err != nil {
		return raw, err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return raw, errors.New("request body must contain exactly one JSON value")
		}
		return raw, err
	}
	return raw, nil
}

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

// WriteErrorCode is WriteError with a stable machine-readable code for
// errors a client is expected to act on (see models.ErrorCode*).
func WriteErrorCode(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, models.ErrorResponse{Error: message, Code: code})
}

// WriteStoreAwareError maps the small set of well-known service-layer error
// kinds to HTTP responses. The mapping (404 for missing sandboxes, 503 for
// capacity/topology admission failures, 400 for everything else) is a contract
// clients depend on regardless of API version, so it lives here in the shared
// helper package.
func WriteStoreAwareError(logger *slog.Logger, w http.ResponseWriter, err error) {
	c := Classify(err)
	c.Apply(logger, err)
	c.SetRetryAfter(w)
	WriteErrorCode(w, c.Status, c.Code, c.Message)
}

// RequireOperator rejects a caller that is not an operator with 403. It sits
// inside an auth middleware, which marks PAT and cluster-peer calls as the
// operator; a user token authenticates but is scoped to its account, so it
// never reaches what this wraps: fleet-wide and cluster-internal routes.
func RequireOperator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if access, ok := controlplane.AccessFromContext(r.Context()); !ok || !access.Operator {
			WriteError(w, http.StatusForbidden, "operator authorization required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
