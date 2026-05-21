package docker

import (
	"context"
	"errors"
	"expvar"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/scaleobs"
)

var (
	imagePullRequestsTotal     = expvar.NewInt("aerolvm_image_pull_requests_total")
	imagePullDedupWaitersTotal = expvar.NewInt("aerolvm_image_pull_dedup_waiters_total")
	imagePullInflight          = expvar.NewInt("aerolvm_image_pull_inflight")
	imagePullQueued            = expvar.NewInt("aerolvm_image_pull_queued")
	imagePullBackoffRejects    = expvar.NewInt("aerolvm_image_pull_backoff_rejects_total")
	imagePullErrors            = expvar.NewMap("aerolvm_image_pull_errors_total")
	imagePullLastNanos         = expvar.NewInt("aerolvm_image_pull_last_nanos")
	imagePullLatency           = scaleobs.NewDurationBuckets("aerolvm_image_pull_latency_seconds_bucket")
)

func beginImagePullMetric() func(error) {
	imagePullRequestsTotal.Add(1)
	start := time.Now()
	return func(err error) {
		elapsed := time.Since(start)
		imagePullLastNanos.Set(elapsed.Nanoseconds())
		imagePullLatency.Observe(elapsed)
		if err != nil {
			scaleobs.Add(imagePullErrors, classifyImagePullError(err), 1)
		}
	}
}

func recordImagePullDedupWaiter() {
	imagePullDedupWaitersTotal.Add(1)
}

func recordImagePullBackoffReject() {
	imagePullBackoffRejects.Add(1)
}

func classifyImagePullError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "context canceled"):
		return "canceled"
	case strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "timeout"), strings.Contains(msg, "timed out"):
		return "timeout"
	case strings.Contains(msg, "unauthorized"), strings.Contains(msg, "authentication required"), strings.Contains(msg, "denied"):
		return "auth"
	case strings.Contains(msg, "manifest unknown"), strings.Contains(msg, "not found"), strings.Contains(msg, "no such image"):
		return "not_found"
	case strings.Contains(msg, "too many requests"), strings.Contains(msg, "rate limit"):
		return "rate_limited"
	case strings.Contains(msg, "backoff"):
		return "backoff"
	default:
		return "error"
	}
}
