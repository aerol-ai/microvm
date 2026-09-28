package e2b

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWriteStoreAwareErrorCoverage95(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "public_traffic_disabled", err: service.ErrPublicTrafficDisabled, wantStatus: http.StatusConflict},
		{name: "platform_volumes_disabled", err: models.ErrPlatformVolumesDisabled, wantStatus: http.StatusPreconditionFailed},
		{name: "platform_volumes_unsupported_runtime", err: models.ErrPlatformVolumesUnsupportedRuntime, wantStatus: http.StatusBadRequest},
		{name: "platform_volume_quota", err: models.ErrPlatformVolumeQuota, wantStatus: http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeStoreAwareError(nil, rr, tc.err)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tc.wantStatus)
			}
		})
	}

	rr := httptest.NewRecorder()
	longCap := fmt.Errorf("%w: %s", capacity.ErrCapacityExceeded, strings.Repeat("x", 250))
	writeStoreAwareError(slog.Default(), rr, longCap)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	body := rr.Body.String()
	if len(body) > 400 {
		t.Fatalf("expected trimmed error body, got len=%d", len(body))
	}
}

func TestCreateSandboxWaitForReplayServiceUnavailable(t *testing.T) {
	runtime := newFakeE2BRuntime()
	runtime.blockCreate = make(chan struct{})
	runtime.onCreateChan = make(chan struct{}, 1)

	_, _, handler := newE2BHandlerTestEnvWithRuntime(t, runtime, config.Config{
		PublicHost:  "sandbox.test",
		EnableCaddy: false,
		ToolboxPort: 2280,
	})

	body := `{"templateID":"base","timeout":120,"metadata":{"wait":"timeout"}}`
	go func() {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body)))
	}()

	select {
	case <-runtime.onCreateChan:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for blocked create")
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("wait replay timeout status = %d, body=%s", rr.Code, rr.Body.String())
	}

	close(runtime.blockCreate)
}
