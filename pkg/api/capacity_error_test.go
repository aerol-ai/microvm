package api

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/capacity"
)

// TestWriteStoreAwareErrorMapsCapacityTo503 covers the HTTP contract that
// admission rejections produce 503 Service Unavailable with a Retry-After
// header. Clients and load balancers depend on this — a 4xx would be treated
// as a permanent failure, which is wrong for a transient capacity event.
func TestWriteStoreAwareErrorMapsCapacityTo503(t *testing.T) {
	server := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rec := httptest.NewRecorder()

	err := fmt.Errorf("%w: [cpu reservation exceeded (8+1 > 8 budget)]", capacity.ErrCapacityExceeded)
	server.writeStoreAwareError(rec, err)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Fatalf("Retry-After = %q, want 30", got)
	}
	if !strings.Contains(rec.Body.String(), "cpu reservation exceeded") {
		t.Fatalf("body should include reasons, got %q", rec.Body.String())
	}
}
