package netstats

import (
	"expvar"
	"time"

	"github.com/aerol-ai/microvm/internal/scaleobs"
)

var (
	pollTotal        = expvar.NewInt("aerolvm_netstats_poll_total")
	pollLastNanos    = expvar.NewInt("aerolvm_netstats_poll_last_nanos")
	pollLatency      = scaleobs.NewDurationBuckets("aerolvm_netstats_poll_latency_seconds_bucket")
	pollTargetsLast  = expvar.NewInt("aerolvm_netstats_targets_last")
	pollSamplesLast  = expvar.NewInt("aerolvm_netstats_samples_last")
	pollSamplesTotal = expvar.NewInt("aerolvm_netstats_samples_total")
	pollDroppedTotal = expvar.NewMap("aerolvm_netstats_dropped_samples_total")
)

func recordPoll(elapsed time.Duration, targets int, samples int, dropped map[string]int64) {
	pollTotal.Add(1)
	pollLastNanos.Set(elapsed.Nanoseconds())
	pollLatency.Observe(elapsed)
	pollTargetsLast.Set(int64(targets))
	pollSamplesLast.Set(int64(samples))
	pollSamplesTotal.Add(int64(samples))
	for reason, count := range dropped {
		if count > 0 {
			scaleobs.Add(pollDroppedTotal, reason, count)
		}
	}
}
