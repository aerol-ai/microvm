package wasm

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ToolboxHost serves toolbox HTTP in-process for WASM sandboxes.
type ToolboxHost interface {
	ServeToolbox(ctx context.Context, sandboxID, token string, w http.ResponseWriter, r *http.Request)
}

// ServeToolbox implements ToolboxHost.
func (d *Driver) ServeToolbox(_ context.Context, sandboxID, token string, w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	inst := d.byID[sandboxID]
	d.mu.Unlock()
	if inst == nil {
		writeToolboxError(w, http.StatusNotFound, "wasm sandbox not found")
		return
	}
	// Exec is the only command path, and it runs inside the wasm engine (the
	// sandbox's worker). Nothing here may start a host process: this handler
	// runs in sandboxd, so a host shell would run as the daemon, not in the
	// sandbox. That is why there is no sessions Manager (toolhost/sessions.go).
	cfg := toolhost.Config{
		SandboxID: sandboxID,
		WorkDir:   inst.workDir,
		AuthToken: token,
		Exec:      sandboxExecutor{driver: d, id: sandboxID},
	}
	if inst.durability == models.DurabilityDurable && d.stateKV != nil {
		cfg.StateKV = d.stateKV
	}
	host := toolhost.New(cfg)
	host.Handler().ServeHTTP(w, r)
}

func writeToolboxError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, msg)
}
