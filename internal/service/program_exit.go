package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/toolboxhttp"
)

// Destroy after the main program exits (plans/agent-sandbox-feature-parity.md
// L5, owner row P2). toolboxd is the sandbox's PID 1 and keeps serving when
// the main program ends, so the sandbox never stops on its own. toolboxd's
// reaper sees the end and shows it on /health (main_program); the one-minute
// lifecycle sweep reads it, only for started sandboxes that set
// destroy_after_exit_for and have no exit recorded yet, and stores the exit
// time and code. The destroy then fires from the stored time, so a daemon
// restart keeps the timer, and status_reason program_exited and exit_code
// come from the same record (L2).
//
// The read is cheap and bounded: an unauthenticated GET to the sandbox's
// own toolboxd (no token to decrypt), at most programExitProbeConcurrency at
// once and programExitProbeTimeout each, inside the sweep's own deadline. A
// sandbox that does not answer (busy, or an older toolboxd without
// main_program) is asked again next minute.
const (
	programExitProbeConcurrency = 8
	programExitProbeTimeout     = 3 * time.Second
	// programExitProbeBudget is the probes' share of the sweep's deadline.
	// Without it, about 80 sandboxes whose agent does not answer (3 s each,
	// 8 at a time) use all of it, and that minute's stops and deletes then
	// run with an expired context. A sandbox left out is asked next minute.
	programExitProbeBudget = 10 * time.Second
)

// validateLifecycleExitRuntime refuses destroy_after_exit_for where there is
// no toolboxd main program to watch.
func validateLifecycleExitRuntime(l models.Lifecycle, runtime string) error {
	if l.DestroyAfterExitFor > 0 && (runtime == models.RuntimeWasm || runtime == models.RuntimeIsolate) {
		return fmt.Errorf("invalid lifecycle: destroy_after_exit_for is not supported on runtime %q; it needs a sandbox with a main program (docker, gvisor, containerd or firecracker)", runtime)
	}
	return nil
}

// toolboxMainProgram is the main_program object on toolboxd's /health,
// with when sandboxd read it and how far the host clock was ahead of the
// guest's then (programExitTime).
type toolboxMainProgram struct {
	State    string `json:"state"`
	ExitCode *int   `json:"exit_code"`
	EndedAt  string `json:"ended_at"`

	readAt    time.Time
	hostAhead time.Duration
	dated     bool
}

func (p toolboxMainProgram) ended() bool {
	return (p.State == "exited" || p.State == "killed") && p.ExitCode != nil
}

// wantsProgramExitProbe selects the sandboxes the sweep asks: started, set
// destroy_after_exit_for, no exit recorded yet, and a runtime with a
// toolboxd main program.
func wantsProgramExitProbe(sb *models.Sandbox) bool {
	return sb != nil && sb.Status == models.SandboxStatusStarted && sb.Lifecycle.DestroyAfterExitFor > 0 &&
		sb.ProgramExitedAt == nil && sb.ContainerIP != "" &&
		sb.Runtime != models.RuntimeWasm && sb.Runtime != models.RuntimeIsolate
}

// probeProgramExits asks each selected sandbox's toolboxd whether its main
// program has ended, records the ends it finds, and sets ProgramExitedAt on
// the listed rows so this same sweep can act on them.
func (s *Service) probeProgramExits(ctx context.Context, sandboxes []*models.Sandbox) {
	ctx, cancel := context.WithTimeout(ctx, programExitProbeBudget)
	defer cancel()
	var wg sync.WaitGroup
	sem := make(chan struct{}, programExitProbeConcurrency)
	for _, sb := range sandboxes {
		if !wantsProgramExitProbe(sb) {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func(sb *models.Sandbox) {
			defer wg.Done()
			defer func() { <-sem }()
			s.probeProgramExit(ctx, sb)
		}(sb)
	}
	wg.Wait()
}

func (s *Service) probeProgramExit(ctx context.Context, sb *models.Sandbox) {
	program, err := s.readMainProgram(ctx, sb)
	if err != nil {
		s.logger.Debug("program exit probe: no answer", "sandbox_id", sb.ID, "error", err)
		return
	}
	if !program.ended() {
		return
	}
	at := programExitTime(program, sb)
	recorded, err := s.store.RecordProgramExit(ctx, sb.ID, at, *program.ExitCode)
	if err != nil {
		s.logger.Warn("program exit not recorded", "sandbox_id", sb.ID, "error", err)
		return
	}
	if !recorded {
		return
	}
	sb.ProgramExitedAt = &at
	sb.StatusReason, sb.ExitCode = models.StatusReasonProgramExited, program.ExitCode
	recordSandboxFinished(*program.ExitCode)
	s.logger.Info("main program exited", "sandbox_id", sb.ID, "exit_code", *program.ExitCode,
		"state", program.State, "destroy_after", sb.Lifecycle.DestroyAfterExitFor.String())
}

// readMainProgram GETs the sandbox's toolboxd /health. It is unauthenticated,
// like the readiness poll, so no toolbox token is read or sent.
func (s *Service) readMainProgram(ctx context.Context, sb *models.Sandbox) (toolboxMainProgram, error) {
	addr, err := s.toolboxAddress(ctx, sb)
	if err != nil {
		return toolboxMainProgram{}, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, programExitProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://"+addr+"/health", nil)
	if err != nil {
		return toolboxMainProgram{}, err
	}
	resp, err := s.programExitClient().Do(req)
	if err != nil {
		return toolboxMainProgram{}, err
	}
	readAt := time.Now().UTC()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return toolboxMainProgram{}, fmt.Errorf("toolbox health: HTTP %d", resp.StatusCode)
	}
	var health struct {
		MainProgram *toolboxMainProgram `json:"main_program"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&health); err != nil {
		return toolboxMainProgram{}, fmt.Errorf("toolbox health: %w", err)
	}
	if health.MainProgram == nil {
		// An older toolboxd: it cannot say, so the option does nothing
		// until the sandbox runs a newer one.
		return toolboxMainProgram{}, fmt.Errorf("toolbox health has no main_program (older toolboxd)")
	}
	program := *health.MainProgram
	program.readAt = readAt
	// toolboxd's Date header is the guest's clock when it answered.
	if guest, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		program.hostAhead, program.dated = readAt.Sub(guest), true
	}
	return program, nil
}

func (s *Service) programExitClient() *http.Client {
	if s.programExitHTTP != nil {
		return s.programExitHTTP
	}
	return toolboxhttp.Client(programExitProbeTimeout)
}

// programExitTime is the end toolboxd reported, moved from the guest's
// clock onto the host's, so a destroy comes late, never early.
//
// ended_at is on the guest's clock, which can be behind the host's by any
// amount (a Firecracker VM restored from a template or after a pause).
// hostAhead is the read time minus the reply's Date header. Date is the
// guest clock cut to the second and the read comes after the reply was
// written, so hostAhead is never below the real gap: the moved time is at
// or after the real end, late by under a second plus the read's latency.
//
// With no usable Date or ended_at, or a moved time after the read or
// before the sandbox existed (the guest clock jumped in between), the read
// time is used: the program had ended by then.
func programExitTime(program toolboxMainProgram, sb *models.Sandbox) time.Time {
	seen := program.readAt
	at, err := time.Parse(time.RFC3339Nano, program.EndedAt)
	if err != nil || !program.dated {
		return seen
	}
	at = at.Add(program.hostAhead)
	if at.After(seen) || (sb != nil && at.Before(sb.CreatedAt)) {
		return seen
	}
	return at.UTC()
}
