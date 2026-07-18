package isolate

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/models"
)

// guestHTTPProxy is the Phase-3 inbound bridge: the loopback mediator calls
// this, and we Invoke the sandbox's fetch handler on its group host. Routing
// is by sandbox id (driver-set x-sb-id inside Host.Invoke) — never by
// client-controlled Host header (plans/isolate-runtime.md §4).
//
// guestPort is the Caddy routing key only; isolates have a single fetch
// entrypoint, so the port is not forwarded into the worker.
func (d *Driver) guestHTTPProxy(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) error {
	_ = guestPort
	if err := d.ensureLoaded(r.Context(), sandboxID); err != nil {
		return err
	}
	d.mu.Lock()
	rec := d.byID[sandboxID]
	d.mu.Unlock()
	if rec == nil || rec.groupKey == "" {
		return fmt.Errorf("isolate: sandbox %q not loaded", sandboxID)
	}
	d.touchGroup(rec.groupKey)

	d.groupsMu.Lock()
	g := d.groups[rec.groupKey]
	d.groupsMu.Unlock()
	if g == nil {
		return fmt.Errorf("isolate: group %q gone", rec.groupKey)
	}

	resp, err := g.host.Invoke(r.Context(), sandboxID, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return err
}

// ensureLoaded re-pins a sandbox onto a group host after an idle-TTL reap (or
// a Start on a stopped sandbox). No-op when the sandbox is already loaded.
func (d *Driver) ensureLoaded(ctx context.Context, sandboxID string) error {
	d.mu.Lock()
	rec := d.byID[sandboxID]
	needs := rec != nil && (rec.needsReload || rec.groupKey == "")
	d.mu.Unlock()
	if rec == nil || !needs {
		return nil
	}
	return d.reloadSandbox(ctx, sandboxID)
}

// reloadSandbox re-acquires the sandbox's group and re-loads its bundle +
// egress policy. Used after idle-TTL reap and by Start.
func (d *Driver) reloadSandbox(ctx context.Context, sandboxID string) error {
	d.mu.Lock()
	rec := d.byID[sandboxID]
	if rec == nil {
		d.mu.Unlock()
		return fmt.Errorf("isolate: unknown sandbox %q", sandboxID)
	}
	tenantID := rec.tenantID
	bundleRef := rec.bundleRef
	egress := rec.egress
	cpu := 0.0
	memMB := 0
	d.mu.Unlock()

	if d.resolver == nil {
		return fmt.Errorf("isolate: bundle resolver not registered")
	}
	bundle, err := d.resolver.Resolve(ctx, tenantID, bundleRef)
	if err != nil {
		return fmt.Errorf("isolate: resolve bundle for reload: %w", err)
	}
	groupKey, err := d.groupKeyForCreate(tenantID, sandboxID)
	if err != nil {
		return err
	}
	host, err := d.acquireGroup(ctx, groupKey, cpu, memMB)
	if err != nil {
		return err
	}
	if err := host.Load(sandboxID, bundle); err != nil {
		d.releaseFromGroup(groupKey, sandboxID)
		return err
	}
	if setter, ok := host.(EgressPolicySetter); ok {
		setter.SetEgressPolicy(sandboxID, egress)
	}
	d.mu.Lock()
	if rec := d.byID[sandboxID]; rec != nil {
		rec.groupKey = groupKey
		rec.needsReload = false
		rec.state.Status = models.SandboxStatusStarted
	}
	d.mu.Unlock()
	d.touchGroup(groupKey)
	return nil
}
