package service

import (
	"context"

	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/pkg/models"
)

// isolateAdopter is the isolate driver's boot surface
// (internal/runtime/isolate, adopt.go).
type isolateAdopter interface {
	AdoptSandboxes(ctx context.Context, rows []*models.Sandbox) isolateruntime.AdoptReport
}

// AdoptIsolateSandboxes keeps every started V8-isolate sandbox across a
// sandboxd restart. Call it once at boot, before the warm pool fills and
// before the first reconcile: with the driver empty, reconcile deleted
// every isolate row 1.4 s after boot (T14).
//
// The driver takes the surviving group hosts over and registers each
// started row, on its host or for a reload on next use. Then, per row, the
// full egress policy goes back (its secrets come from the sealed env, and
// a held sandbox stays shut), and its exposed ports get their host
// listeners and routes again: the listeners lived in the previous sandboxd.
func (s *Service) AdoptIsolateSandboxes(ctx context.Context) isolateruntime.AdoptReport {
	var report isolateruntime.AdoptReport
	if s.isolate == nil {
		return report
	}
	adopter, ok := s.isolate.(isolateAdopter)
	if !ok {
		return report
	}
	known, err := s.store.List(ctx)
	if err != nil {
		s.logger.Warn("isolate adopt: cannot list sandboxes; running isolates are not taken over", "error", err)
		return report
	}
	rows := make([]*models.Sandbox, 0, len(known))
	for _, sb := range known {
		if s.isIsolateSandbox(sb) && sb.Status == models.SandboxStatusStarted {
			rows = append(rows, sb)
		}
	}
	report = adopter.AdoptSandboxes(ctx, rows)
	for _, sb := range rows {
		if err := s.applyIsolatePolicy(ctx, sb); err != nil {
			s.logger.Warn("isolate adopt: egress policy not set again; the sandbox's egress stays denied", "sandbox_id", sb.ID, "error", err)
		}
		if !sandboxAllowsPublicTraffic(sb) {
			continue
		}
		for _, port := range sb.ExposedPorts {
			if err := s.syncExposedPortRoute(ctx, sb, port); err != nil {
				s.logger.Warn("isolate adopt: exposed port not routed again", "sandbox_id", sb.ID, "port", port.Port, "error", err)
			}
		}
		s.syncAllowedPorts(ctx, sb)
	}
	return report
}
