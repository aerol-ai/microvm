package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// wireIsolateRuntime must register the driver so an isolate create clears the
// service's driver-not-registered gate and reaches the Phase-1 skeleton
// (which rejects with ErrRuntimeNotImplemented — that error proves the
// dispatch chain, not a wiring hole).
func TestWireIsolateRuntime(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{EnableIsolate: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	driver := wireIsolateRuntime(config.Config{
		IsolateWorkerdPath:      "/usr/local/bin/workerd",
		IsolateRunDir:           t.TempDir(),
		IsolateGroupGranularity: config.IsolateGroupPerTenant,
	}, testLogger(), svc)
	if driver == nil {
		t.Fatal("wireIsolateRuntime returned nil driver")
	}

	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Runtime:   models.RuntimeIsolate,
		ModuleRef: "handler.js",
	})
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("create = %v, want ErrRuntimeNotImplemented from the Phase-1 skeleton", err)
	}
	// The distinct wiring-bug message must NOT appear — the driver is registered.
	if strings.Contains(err.Error(), "SetIsolateRuntime") {
		t.Fatalf("create hit the driver-not-registered gate despite wiring: %v", err)
	}
}
