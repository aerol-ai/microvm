package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/service"
)

type fakeWasmBootAdopter struct {
	report wasmruntime.AdoptReport
	calls  int
}

func (f *fakeWasmBootAdopter) AdoptWorkers(context.Context) wasmruntime.AdoptReport {
	f.calls++
	return f.report
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
