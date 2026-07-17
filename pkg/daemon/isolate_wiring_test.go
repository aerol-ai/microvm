package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// wireIsolateRuntime must register the driver AND its bundle resolver +
// supervisor so an isolate create clears the service's driver-not-registered
// gate and reaches the real cold path. Here the bundle ref names a file that
// does not exist, so create fails at bundle resolution — proving the dispatch
// chain reached the driver's resolver, not a wiring hole.
func TestWireIsolateRuntime(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{EnableIsolate: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	driver, err := wireIsolateRuntime(config.Config{
		IsolateWorkerdPath:      "/usr/local/bin/workerd",
		IsolateRunDir:           t.TempDir(),
		IsolateGroupGranularity: config.IsolateGroupPerTenant,
	}, testLogger(), svc)
	if err != nil {
		t.Fatalf("wireIsolateRuntime: %v", err)
	}
	if driver == nil {
		t.Fatal("wireIsolateRuntime returned nil driver")
	}

	_, err = svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Runtime:   models.RuntimeIsolate,
		ModuleRef: "/nonexistent/handler.js",
	})
	if err == nil {
		t.Fatal("create with a missing bundle should fail")
	}
	// The wiring-hole messages must NOT appear — the driver + resolver are wired,
	// so the failure is a bundle-resolution error, not a missing dependency.
	for _, hole := range []string{"SetIsolateRuntime", "driver not registered", "resolver not registered", "supervisor not registered"} {
		if strings.Contains(err.Error(), hole) {
			t.Fatalf("create hit a wiring gate despite wiring (%q): %v", hole, err)
		}
	}
	if !strings.Contains(err.Error(), "resolve bundle") {
		t.Fatalf("create error = %v, want a bundle-resolution failure", err)
	}
}
