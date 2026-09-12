package daytona

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDaytonaPaginatedListEmptyCoverage95(t *testing.T) {
	_, _, _, handler := newHandlerExtraTestEnv(t)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated?page=1&limit=10", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var page paginatedSandboxesResponse
	if err := json.NewDecoder(rr.Body).Decode(&page); err != nil {
		t.Fatalf("decode: %v", err)
	}
}
