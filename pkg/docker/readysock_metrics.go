package docker

import (
	"expvar"
	"sync/atomic"
)

var (
	readySocketHit             = expvar.NewInt("docker_ready_socket_hit")
	readySocketFallbackHealth  = expvar.NewInt("docker_ready_socket_fallback_health")
	readySocketTimeout         = expvar.NewInt("docker_ready_socket_timeout")
	readySocketInvalidAttempts = expvar.NewInt("docker_ready_socket_invalid_attempts")
)

// readyWaitMS tracks the last successful readiness wait in milliseconds.
// A histogram would be nicer but expvar has no built-in one; this matches
// the pool-metrics simplicity bar for the first cut.
var readyWaitMS atomic.Int64

func recordReadySocketHit(waitMS int64) {
	readySocketHit.Add(1)
	readyWaitMS.Store(waitMS)
}

func recordReadySocketFallback(waitMS int64) {
	readySocketFallbackHealth.Add(1)
	readyWaitMS.Store(waitMS)
}

func recordReadySocketTimeout() {
	readySocketTimeout.Add(1)
}

func recordReadySocketInvalid() {
	readySocketInvalidAttempts.Add(1)
}

// ReadyWaitMS returns the most recent successful readiness wait (ms). Exported
// for tests; production dashboards read the expvar counters above.
func ReadyWaitMS() int64 {
	return readyWaitMS.Load()
}
