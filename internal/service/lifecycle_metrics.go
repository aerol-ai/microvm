package service

import (
	"expvar"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/scaleobs"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Lifecycle counters (plans/agent-sandbox-feature-parity.md O1), through the
// expvar-to-Prometheus path like aerolvm_toolbox_calls_total. Every label is
// from a small fixed set, with no per-sandbox label:
//
//   - aerolvm_sandbox_stops_total{key=<status reason>}: a sandbox went from
//     started to stopped, by the L2 reason (user_stop, idle, max_age,
//     out_of_memory, disk_limit, crashed, program_exited, reconcile).
//   - aerolvm_sandbox_starts_total{key=requested|restarted|failover}: a
//     stopped sandbox started by a call (API, facade, wake, fleet restore),
//     by restart on failure, or recreated by failover.
//   - aerolvm_sandbox_expired_total{key=idle|max_age|program_exited}: a
//     lifecycle timer deleted a sandbox, by the timer (program_exited is
//     destroy_after_exit_for; destroy_at counts as max_age).
//   - aerolvm_sandbox_finished_total{key=success|failure}: a main program
//     ended, by whether its exit code was 0. A sandbox that goes down with
//     a non-zero code is a crashed stop instead, so failure only moves for
//     the programs toolboxd reports (destroy_after_exit_for).
//   - aerolvm_create_latency_by_start_seconds_bucket{key=warm|cold,key2=le}:
//     successful creates, split by whether a warm pool or a running group
//     served them. aerolvm_create_latency_seconds_bucket stays as it was.
var (
	sandboxStopsTotal    = expvar.NewMap("aerolvm_sandbox_stops_total")
	sandboxStartsTotal   = expvar.NewMap("aerolvm_sandbox_starts_total")
	sandboxExpiredTotal  = expvar.NewMap("aerolvm_sandbox_expired_total")
	sandboxFinishedTotal = expvar.NewMap("aerolvm_sandbox_finished_total")
	createLatencyByStart = scaleobs.NewNestedDurationBuckets("aerolvm_create_latency_by_start_seconds_bucket")
)

// Start kinds for aerolvm_sandbox_starts_total.
const (
	startKindRequested = "requested"
	startKindRestarted = "restarted"
	startKindFailover  = "failover"
)

// metricReason keeps a label inside the fixed reason set: anything else is
// "other", so a bug can never mint a new series per value.
func metricReason(reason string) string {
	for _, r := range models.StatusReasons {
		if r == reason {
			return reason
		}
	}
	return "other"
}

func recordSandboxStop(reason string) { sandboxStopsTotal.Add(metricReason(reason), 1) }

func recordSandboxStart(kind string) { sandboxStartsTotal.Add(kind, 1) }

func recordSandboxExpired(reason string) { sandboxExpiredTotal.Add(metricReason(reason), 1) }

func recordSandboxFinished(exitCode int) {
	if exitCode == 0 {
		sandboxFinishedTotal.Add("success", 1)
		return
	}
	sandboxFinishedTotal.Add("failure", 1)
}

// observeCreateStart records a successful create's latency as warm or cold.
func observeCreateStart(warm *atomic.Bool, elapsed time.Duration) {
	label := "cold"
	if warm != nil && warm.Load() {
		label = "warm"
	}
	createLatencyByStart.Observe(label, elapsed)
}
