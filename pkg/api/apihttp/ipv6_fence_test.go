package apihttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestWriteStoreAwareError_IPv6FenceNotReady: a create refused because the
// node's IPv6 fence is not installed is a 503 with a retry and its own
// code, and the netlink detail stays in the node's log.
func TestWriteStoreAwareError_IPv6FenceNotReady(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteStoreAwareError(discardLogger(), rr, fmt.Errorf("%w (runtime containerd: netlink: secret detail)", service.ErrIPv6FenceNotReady))
	var body models.ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != http.StatusServiceUnavailable || body.Code != models.ErrorCodeIPv6FenceNotReady || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("status=%d code=%q retry=%q", rr.Code, body.Code, rr.Header().Get("Retry-After"))
	}
	if strings.Contains(rr.Body.String(), "secret detail") {
		t.Fatalf("the cause leaked to the caller: %s", rr.Body.String())
	}
}
