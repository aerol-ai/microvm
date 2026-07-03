package firecracker

// health.go is the Phase 6 PR-A seam the firecracker runtime uses to
// notify the service layer that a template's snapshot is corrupt at
// load time. The runtime cannot import internal/service (cycle through
// service.SetFirecrackerRuntime), so the notifier is declared here as
// a small interface and the service implements it.
//
// Why an interface, not a function callback: it parallels every other
// service-owned seam the runtime depends on (TapPool, TemplateResolver,
// WarmPool, RSSSource via capacity), keeps the test-side stub trivial
// (one method), and gives the call sites an obvious wiring point in
// main.go alongside SetRSSSampler / SetTemplateResolver.

import (
	"context"
)

// TemplateHealthNotifier is the runtime → service seam for "I just
// observed a corrupt snapshot for this template". The service-layer
// implementation transitions the template to
// models.TemplateStatusUnhealthy (idempotent UPDATE WHERE status='ready')
// and kicks an async snapshot rebuild on the first observer; later
// observers see no-op transitions and skip the rebuild kick.
//
// reason is a human-readable string for operator-facing log lines and
// (later) the LastError column — typically the wrapped error message
// produced at the verifySnapshotChecksum call site.
type TemplateHealthNotifier interface {
	MarkSnapshotCorrupt(ctx context.Context, templateID, reason string) error
}

// SetTemplateHealthNotifier wires the notifier. Called once from
// cmd/sandboxd/main.go after Service is constructed. Nil disables the
// notifier — the cold-load path's service-side intercept still works
// (it goes through service.createFirecrackerSandbox, which has direct
// access to Service methods), but the warm-spawn path becomes silent
// on corruption. Production deployments always wire it; the nil-safety
// exists for unit tests that exercise warmspawn lifecycle without
// pulling in service.
func (d *Driver) SetTemplateHealthNotifier(n TemplateHealthNotifier) {
	d.healthNotifier = n
}

// notifyCorrupt is the nil-safe helper called from the warm-spawn path
// when verifySnapshotChecksum returns an ErrSnapshotCorrupt-wrapping
// error. Centralised so the call site stays a one-liner and the
// logger.Warn idiom for "service-side ack failed" lives in one place.
// Returns nothing — the corruption is real regardless of whether the
// notifier was wired or whether the service-side update succeeded; the
// caller's own error propagation handles the immediate Create/Spawn
// failure. The notification is a best-effort hint that another path
// (the next Create going through service.createFirecrackerSandbox)
// would have produced anyway.
func (d *Driver) notifyCorrupt(ctx context.Context, templateID, reason string) {
	d.invalidateSnapshotVerifyCacheForTemplate(templateID)
	if d.healthNotifier == nil || templateID == "" {
		return
	}
	if err := d.healthNotifier.MarkSnapshotCorrupt(ctx, templateID, reason); err != nil {
		d.logger.Warn("firecracker: mark snapshot corrupt failed",
			"template_id", templateID, "error", err)
	}
}
