package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeWasmBootAdopter struct {
	report wasmruntime.AdoptReport
	calls  int
}

func (f *fakeWasmBootAdopter) AdoptWorkers(context.Context) wasmruntime.AdoptReport {
	f.calls++
	return f.report
}

// TestWireIsolateRuntimeKeepsAStartedRow: a started isolate row waiting at
// boot is registered by the wiring (for a reload here, since no group host
// survived in a test) instead of being left for reconcile to delete.
func TestWireIsolateRuntimeKeepsAStartedRow(t *testing.T) {
	st := openTestStore(t)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{ID: "sb-iso-boot", Runtime: models.RuntimeIsolate,
		Status: models.SandboxStatusStarted, ModuleRef: "sha256:abc", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{EnableIsolate: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	var logged bytes.Buffer
	driver, err := wireIsolateRuntime(context.Background(), config.Config{
		IsolateWorkerdPath:      "/usr/local/bin/workerd",
		IsolateRunDir:           t.TempDir(),
		IsolateGroupGranularity: config.IsolateGroupPerTenant,
	}, slog.New(slog.NewTextHandler(&logged, nil)), svc)
	if err != nil {
		t.Fatal(err)
	}
	if state, _ := driver.Inspect(context.Background(), "sb-iso-boot"); state == nil {
		t.Fatal("the started isolate row was not registered at boot")
	}
	if !strings.Contains(logged.String(), "reloading=1") {
		t.Fatalf("log = %q", logged.String())
	}
}

// TestAdoptRunningWasmLogsWhatItTookOver: boot adoption runs the driver's
// worker pass, then the service's sandbox pass, and logs only when there
// was something to take over.
func TestAdoptRunningWasmLogsWhatItTookOver(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))

	quiet := &fakeWasmBootAdopter{}
	adoptRunningWasm(context.Background(), quiet, svc, logger)
	if quiet.calls != 1 || logged.Len() != 0 {
		t.Fatalf("nothing to adopt: calls %d, log %q", quiet.calls, logged.String())
	}
	busy := &fakeWasmBootAdopter{report: wasmruntime.AdoptReport{ResidentHosts: 1, Workers: 2}}
	adoptRunningWasm(context.Background(), busy, svc, logger)
	if !strings.Contains(logged.String(), "running sandboxes taken over") || !strings.Contains(logged.String(), "resident_hosts=1") {
		t.Fatalf("log = %q", logged.String())
	}
}
