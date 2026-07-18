package isolate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// ToolboxHost is the in-process toolbox surface for isolate sandboxes. Isolates
// have no POSIX process, so only invoke-handler is supported; everything else
// is 501 (plans/isolate-runtime.md §3 / Phase 3).
type ToolboxHost interface {
	ServeToolbox(ctx context.Context, sandboxID, token string, w http.ResponseWriter, r *http.Request)
}

// AsToolboxHost returns the toolbox surface when rt implements it.
func AsToolboxHost(rt any) (ToolboxHost, bool) {
	th, ok := rt.(ToolboxHost)
	return th, ok
}

// ServeToolbox implements ToolboxHost for the isolate driver.
func (d *Driver) ServeToolbox(ctx context.Context, sandboxID, token string, w http.ResponseWriter, r *http.Request) {
	_ = token
	path := r.URL.Path
	switch {
	case strings.Contains(path, "/exec") || strings.Contains(path, "/process"):
		d.serveExec(ctx, sandboxID, w, r)
	default:
		http.Error(w, "isolate runtime does not support this toolbox endpoint (no shell/filesystem; use exec as invoke-handler)", http.StatusNotImplemented)
	}
}

// serveExec treats exec as "invoke the sandbox's fetch handler". The command
// string is the URL path (default "/"); optional method via env METHOD=.
func (d *Driver) serveExec(ctx context.Context, sandboxID string, w http.ResponseWriter, r *http.Request) {
	var req models.ExecRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	urlPath := strings.TrimSpace(req.Command)
	if urlPath == "" {
		urlPath = "/"
	}
	method := http.MethodGet
	if req.Env != nil {
		if m := strings.ToUpper(strings.TrimSpace(req.Env["METHOD"])); m != "" {
			method = m
		}
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, "http://isolate"+urlPath, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	start := time.Now()
	resp, err := d.InvokeHTTP(ctx, sandboxID, httpReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	result := models.ExecResult{
		ExitCode:   0,
		Stdout:     string(out),
		DurationMS: time.Since(start).Milliseconds(),
	}
	if resp.StatusCode >= 400 {
		result.ExitCode = 1
		result.Stderr = fmt.Sprintf("fetch handler returned %d", resp.StatusCode)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// InvokeHTTP calls the sandbox's fetch handler directly (tests + P0 gate).
func (d *Driver) InvokeHTTP(ctx context.Context, sandboxID string, r *http.Request) (*http.Response, error) {
	if err := d.ensureLoaded(ctx, sandboxID); err != nil {
		return nil, err
	}
	d.mu.Lock()
	rec := d.byID[sandboxID]
	d.mu.Unlock()
	if rec == nil || rec.groupKey == "" {
		return nil, fmt.Errorf("isolate: sandbox %q not loaded", sandboxID)
	}
	d.groupsMu.Lock()
	g := d.groups[rec.groupKey]
	d.groupsMu.Unlock()
	if g == nil {
		return nil, fmt.Errorf("isolate: group %q gone", rec.groupKey)
	}
	d.touchGroup(rec.groupKey)
	return g.host.Invoke(ctx, sandboxID, r)
}
