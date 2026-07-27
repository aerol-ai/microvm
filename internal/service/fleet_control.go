package service

import (
	"context"
	"errors"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// SetFleetAdmitter installs the managed create-gate. The managed daemon calls
// this once at boot from the control-plane provider; the open-source build
// never does, so fleetAdmitter stays nil and createSandbox skips the gate.
func (s *Service) SetFleetAdmitter(a controlplane.Admitter) {
	s.fleetAdmitter = a
}

// Service implements controlplane.FleetController so the managed enforcement
// loop can converge an owner's sandboxes to a standing directive without the
// control-plane client knowing any orchestration internals. Every method is
// idempotent and re-entrant: the loop only calls on a directive transition, but
// a missed or partially-failed transition self-heals on the next matching tick.
//
// These run from the background standing loop with no Access in context, so the
// service layer treats them as unscoped (fleet-wide) — exactly what fleet-level
// enforcement needs. The fleet_suspended marker distinguishes "stopped by the
// fleet" from "stopped by the user/operator" so recovery only restarts what the
// fleet itself suspended.
var _ controlplane.FleetController = (*Service)(nil)

// StopByOwner stops every currently-running sandbox owned by ownerRef, marking
// each one fleet-suspended first so RestoreByOwner knows to bring it back. A
// sandbox already stopped (by its user, or by a prior tick) is left untouched,
// so repeated calls do not thrash. Errors are collected and returned joined so
// the enforcement loop retries the whole owner next tick; the marker-then-stop
// order means a stop that fails still leaves the sandbox marked and running,
// and the retry re-attempts it.
func (s *Service) StopByOwner(ctx context.Context, ownerRef string) error {
	sandboxes, err := s.store.ListByOwner(ctx, ownerRef)
	if err != nil {
		return err
	}
	var errs []error
	stopped := 0
	for _, sb := range sandboxes {
		if sb == nil || sb.Status != models.SandboxStatusStarted {
			continue
		}
		err := s.store.SetFleetSuspended(ctx, sb.ID, true)
		if s.testForceFleetSuspendErr != nil {
			err = s.testForceFleetSuspendErr
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, err)
			continue
		}
		if _, err := s.StopSandbox(ctx, sb.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, err)
			continue
		}
		stopped++
	}
	if stopped > 0 {
		s.logger.Info("audit fleet suspend", "owner_ref", ownerRef, "stopped", stopped)
	}
	return errors.Join(errs...)
}

// RestoreByOwner restarts the owner's fleet-suspended sandboxes and clears the
// marker. Only sandboxes carrying the marker are touched — a user-initiated stop
// during suspension is respected. Start happens before the marker is cleared so
// a failed start retries next tick (marker preserved); an already-running marked
// sandbox just has its marker cleared. Idempotent.
func (s *Service) RestoreByOwner(ctx context.Context, ownerRef string) error {
	sandboxes, err := s.store.ListByOwner(ctx, ownerRef)
	if err != nil {
		return err
	}
	var errs []error
	restored := 0
	for _, sb := range sandboxes {
		if sb == nil || !sb.FleetSuspended {
			continue
		}
		if sb.Status != models.SandboxStatusStarted {
			if _, err := s.StartSandbox(ctx, sb.ID); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					continue // gone; nothing to restore
				}
				errs = append(errs, err)
				continue // keep the marker so the next tick retries the start
			}
			restored++
		}
		if err := s.store.SetFleetSuspended(ctx, sb.ID, false); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, err)
		}
	}
	if restored > 0 {
		s.logger.Info("audit fleet restore", "owner_ref", ownerRef, "restored", restored)
	}
	return errors.Join(errs...)
}

// DeleteByOwner destroys every sandbox owned by ownerRef. Terminal and
// idempotent: a sandbox already gone (ErrNotFound) counts as success, so a
// re-tick over a partially-deleted set converges. Errors on other sandboxes are
// collected and returned so the loop retries the remainder.
func (s *Service) DeleteByOwner(ctx context.Context, ownerRef string) error {
	sandboxes, err := s.store.ListByOwner(ctx, ownerRef)
	if err != nil {
		return err
	}
	var errs []error
	deleted := 0
	for _, sb := range sandboxes {
		if sb == nil {
			continue
		}
		if err := s.DestroySandbox(ctx, sb.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, err)
			continue
		}
		deleted++
	}
	if deleted > 0 {
		s.logger.Info("audit fleet terminate", "owner_ref", ownerRef, "deleted", deleted)
	}
	return errors.Join(errs...)
}

// FireWebhook records that an owner crossed a notify-level directive. The
// webhook URL and secret live entirely in the managed contract (never in the
// open-source build), so the host's part of the contract is just to surface the
// crossing in its audit log; the managed control plane owns any outbound
// notification. Called once per transition by the enforcement loop, so this is
// already idempotent per crossing.
func (s *Service) FireWebhook(_ context.Context, ownerRef, level string) error {
	s.logger.Info("audit fleet directive crossing", "owner_ref", ownerRef, "level", level)
	return nil
}
