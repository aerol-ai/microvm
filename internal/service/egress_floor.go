package service

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime"
)

// The egress deny floor on the host firewall: the cloud metadata endpoints
// and the operator file's deny_cidrs, dropped for every sandbox on each
// container engine's bridge and the Firecracker TAP subnet (netrules
// FloorChainFor, plans/egress-domain-filtering.md §5.10 PC-2).
//
// For a container, gVisor or Firecracker sandbox whose traffic does not pass
// the egress gateway (every sandbox without a hostname policy, and every
// sandbox on a node without the gateway) it is the only thing between the
// sandbox and the metadata service, which hands out the node's own cloud
// credentials. The gateway's deny_floor set filters only what the gateway
// carries, and the WASM and isolate dial guards cover only those runtimes;
// IMDSv2's hop limit is a second layer only where our Terraform set it. So
// the floor is not best-effort: like the node guard, a runtime without it
// refuses creates until a retry installs it.
//
// Ready means the latest apply of the floor this node must have now
// succeeded, or a re-assert since found it whole. An older floor does not
// count, although every floor holds the metadata endpoints: SetFloor
// flushes the chain and refills it, so a failed apply can leave it partly
// filled, metadata DROPs included; and an operator who adds a range to
// deny_cidrs means no new sandbox may reach it. Refusing creates while the
// new floor is not in costs at most a supervisor tick of 503s per transient
// failure; accepting them could start sandboxes with no floor at all.

// ErrEgressFloorNotReady refuses a container or Firecracker create while the
// egress deny floor is not installed for that runtime: the sandbox could
// reach the cloud metadata service and the node's credentials (503,
// egress_floor_not_ready; the supervisor retries every few seconds).
var ErrEgressFloorNotReady = errors.New("this node cannot keep sandboxes off the cloud metadata service right now; creates on this runtime are refused until it can")

// egressFloorReady is 1 per runtime whose floor is installed with the floor
// the node must have now, 0 otherwise.
var egressFloorReady = expvar.NewMap("aerolvm_egress_floor_ready")

type egressFloorState struct {
	// mu serializes syncs (boot, operator file changes, supervisor ticks).
	mu sync.Mutex
	// want is the floor this node must have: the operator file's deny_cidrs
	// plus the metadata endpoints, or the metadata endpoints alone. nil
	// until the daemon applies one.
	want []netip.Prefix
	// applied is the floor each runtime got (prefixesKey), by runtime name.
	applied   map[string]string
	checkedAt time.Time
	// status is each runtime's last result (nil: installed), read by the
	// create gate without the lock.
	status atomic.Pointer[map[string]error]
}

// SuperviseEgressFloor keeps the floor in place: it retries a runtime where
// installing it failed every interval, and every nodeGuardReassertInterval
// checks that it is still whole on the others and puts it back if a host
// firewall reload or a flush took it away.
func (s *Service) SuperviseEgressFloor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.syncEgressFloor(ctx, nil)
		}
	}
}

// syncEgressFloor brings every container and Firecracker runtime to floor,
// or, with floor nil (a supervisor tick), to the floor last applied. A
// runtime is written only when its floor differs or its last attempt
// failed; one already in place gets the cheap re-assert when it is due, so
// an unchanged floor is never flushed and refilled.
func (s *Service) syncEgressFloor(ctx context.Context, floor []netip.Prefix) {
	if s == nil {
		return
	}
	ef := &s.egressFloor
	ef.mu.Lock()
	defer ef.mu.Unlock()
	if floor != nil {
		ef.want = floor
	}
	if ef.want == nil {
		return
	}
	key := prefixesKey(ef.want)
	due := time.Since(ef.checkedAt) >= nodeGuardReassertInterval
	if ef.applied == nil {
		ef.applied = map[string]string{}
	}
	status := map[string]error{}
	if prev := ef.status.Load(); prev != nil {
		for k, v := range *prev {
			status[k] = v
		}
	}
	for _, nr := range s.nodeGuardRuntimes() {
		setter, ok := nr.rt.(runtime.EgressFloorSetter)
		if nr.rt == nil || !ok {
			continue
		}
		prev, seen := status[nr.name]
		var err error
		installed := false
		switch {
		case ef.applied[nr.name] != key || !seen || prev != nil:
			err = setter.SetEgressFloor(ctx, ef.want)
			if err == nil {
				installed = ef.applied[nr.name] != key
				ef.applied[nr.name] = key
			} else {
				// The chain may be half rewritten: nothing counts as
				// applied until a later attempt succeeds.
				delete(ef.applied, nr.name)
			}
		case due:
			var repaired bool
			repaired, err = setter.ReassertEgressFloor(ctx)
			if repaired && err == nil {
				s.logger.Warn("egress floor was missing and has been put back; something rewrote the host firewall", "runtime", nr.name)
			}
		default:
			continue
		}
		s.noteEgressFloor(nr.name, prev, seen, err, installed, key)
		status[nr.name] = err
	}
	ef.status.Store(&status)
	if due {
		ef.checkedAt = time.Now()
	}
}

// noteEgressFloor logs a runtime's floor result when it changes or a new
// floor went in, and publishes it.
func (s *Service) noteEgressFloor(name string, prev error, seen bool, err error, installed bool, floor string) {
	v := new(expvar.Int)
	if err == nil {
		v.Set(1)
	}
	egressFloorReady.Set(name, v)
	if seen && errText(prev) == errText(err) && !installed {
		return
	}
	switch {
	case err == nil:
		s.logger.Info("egress floor installed: sandboxes on this runtime cannot reach the cloud metadata endpoints or the operator's deny_cidrs", "runtime", name, "floor", floor)
	case errors.Is(err, runtime.ErrEgressFloorUnavailable) && !s.cfg.EnterpriseMode:
		s.logger.Warn("egress floor unavailable: network rules are off, so sandboxes on this runtime can reach the cloud metadata endpoints", "runtime", name)
	default:
		s.logger.Error("egress floor not installed: sandboxes on this runtime could reach the cloud metadata endpoints, so its creates are refused until it is", "runtime", name, "error", err)
	}
}

// requireEgressFloor is the create gate: a container or Firecracker sandbox
// is not created on a runtime whose floor is not installed. A runtime with
// network rules off is allowed outside enterprise mode, as for the node
// guard (local mode: the operator turned the host firewall off, and the boot
// log says what that costs). One map read; nothing until the daemon has
// applied a floor (tests, nodes that own no sandboxes), and nothing for a
// runtime that is not wired or has no host firewall to hold one.
func (s *Service) requireEgressFloor(chosenRuntime string) error {
	name := s.nodeGuardRuntimeName(chosenRuntime)
	st := s.egressFloor.status.Load()
	if name == "" || st == nil {
		return nil
	}
	err, seen := (*st)[name]
	if !seen || err == nil || (errors.Is(err, runtime.ErrEgressFloorUnavailable) && !s.cfg.EnterpriseMode) {
		return nil
	}
	return fmt.Errorf("%w (runtime %s: %v)", ErrEgressFloorNotReady, name, err)
}

// prefixesKey names a floor independently of its order, so a reordered
// operator file rewrites nothing.
func prefixesKey(p []netip.Prefix) string {
	parts := make([]string, 0, len(p))
	for _, x := range p {
		parts = append(parts, x.String())
	}
	slices.Sort(parts)
	return strings.Join(slices.Compact(parts), ",")
}
