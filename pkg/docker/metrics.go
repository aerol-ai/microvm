package docker

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	remoteerrors "github.com/containerd/containerd/v2/core/remotes/errors"
	"github.com/containerd/errdefs"

	"github.com/aerol-ai/microvm/internal/scaleobs"
	"github.com/aerol-ai/microvm/pkg/models"
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

	// Pause-netns pool observability (see netns_pool.go). Hits/misses tell
	// operators whether cold creates are actually landing on prepaid netns
	// slots; refill errors + orphans reaped are the leak-watch signals.
	netnsPoolHits          = expvar.NewInt("aerolvm_docker_netns_pool_hits_total")
	netnsPoolMisses        = expvar.NewInt("aerolvm_docker_netns_pool_misses_total")
	netnsPoolRefillErrors  = expvar.NewInt("aerolvm_docker_netns_pool_refill_errors_total")
	netnsPoolOrphansReaped = expvar.NewInt("aerolvm_docker_netns_pool_orphans_reaped_total")
	netnsPoolSize          = expvar.NewInt("aerolvm_docker_netns_pool_size")
	// Creates that left the pool alone because another create was running
	// (netnsPoolBusy): not misses, the pool had a slot to give.
	netnsPoolBusySkips = expvar.NewInt("aerolvm_docker_netns_pool_busy_skips_total")

	// Warm-adopt image-ID cache (see image_cache.go). The hit ratio tells
	// operators how often warm creates skip the per-create image inspect;
	// a low ratio under steady traffic means the TTL is being outrun.
	imageCacheHits   = expvar.NewInt("aerolvm_docker_image_cache_hits_total")
	imageCacheMisses = expvar.NewInt("aerolvm_docker_image_cache_misses_total")
)

func recordImageCacheHit()  { imageCacheHits.Add(1) }
func recordImageCacheMiss() { imageCacheMisses.Add(1) }

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

// PullBackoffError is a create the per-image failure backoff refused: the
// same image failed moments ago, Cause says how (flattened and capped, as
// it is kept per failing image until the backoff ends), and Until is when
// the node asks the registry again. It is registry trouble that passes, the
// API's 503, only when that failure was (Transient); a backoff of a missing
// tag or a refused login stays a 400.
type PullBackoffError struct {
	Image     string
	Until     time.Time
	Cause     string
	Transient bool
}

func (e *PullBackoffError) Error() string {
	return fmt.Sprintf("image pull for %q backing off after recent failure: %s", e.Image, e.Cause)
}

// Is makes a refusal of trouble that passes an ErrImagePullUnavailable.
func (e *PullBackoffError) Is(target error) bool {
	return e.Transient && target == models.ErrImagePullUnavailable
}

// PullRetryAfter is what is left of the backoff.
func (e *PullBackoffError) PullRetryAfter() time.Duration { return time.Until(e.Until) }

// maxPullCauseBytes caps a backoff's kept cause: it lives per failing image
// for the whole backoff, and a registry's error (containerd's
// ErrUnexpectedStatus) can hold up to 64 KB of response body.
const maxPullCauseBytes = 512

// FlattenPullCause is err as the short text a backoff keeps.
func FlattenPullCause(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) <= maxPullCauseBytes {
		return msg
	}
	cut := maxPullCauseBytes
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut] + "..."
}

// TransientPullFailure reports whether a pull failed for a reason that
// passes: the registry rate-limited it, failed (5xx, refused or reset the
// connection), or did not answer in time. Only the failure's cause is
// judged, typed where it can be, never text that carries the image name.
func TransientPullFailure(err error) bool {
	switch classifyImagePullError(err) {
	case "rate_limited", "timeout", "unavailable":
		return true
	case "backoff":
		var b *PullBackoffError
		return errors.As(err, &b) && b.Transient
	}
	return false
}

// TransientPullError marks err for the API's 503 with Retry-After when the
// pull failed for a reason that passes (TransientPullFailure), and returns
// it as it is otherwise: a missing image, a refused login, a cancelled
// create, a refusal of a backoff whose cause was any of those. backoff is
// the node's SB_IMAGE_PULL_FAILURE_BACKOFF, the Retry-After.
func TransientPullError(err error, backoff time.Duration) error {
	if err == nil || errors.Is(err, models.ErrImagePullUnavailable) {
		// A backoff refusal of transient trouble is one already.
		return err
	}
	var refusal *PullBackoffError
	if errors.As(err, &refusal) || !TransientPullFailure(err) {
		return err
	}
	return &models.ImagePullUnavailableError{Err: err, RetryAfter: backoff}
}

func recordImagePullDedupWaiter() {
	imagePullDedupWaitersTotal.Add(1)
}

func recordImagePullBackoffReject() {
	imagePullBackoffRejects.Add(1)
}

// The image-pull metrics belong to every engine, not only dockerd: the
// SandboxdImagePull* alerts and the image-pull-storm runbook read these
// names whatever engine pulled. The containerd engine (the Kubernetes
// worker's, and the default on VMs) has its own dedup, slot cap and backoff,
// and reports them through the hooks below; expvar allows one owner per
// name, so the names stay here.

// BeginImagePullMetric counts one registry pull request; call the returned
// func with the request's outcome. A request a dedup waiter or the failure
// backoff answered is still a request, as on the dockerd path.
func BeginImagePullMetric() func(error) { return beginImagePullMetric() }

// RecordImagePullDedupWaiter counts a request answered by another request's
// pull of the same image.
func RecordImagePullDedupWaiter() { recordImagePullDedupWaiter() }

// RecordImagePullBackoffReject counts a request refused by the per-image
// failure backoff.
func RecordImagePullBackoffReject() { recordImagePullBackoffReject() }

// BeginImagePullQueued counts a pull waiting for a free pull slot until the
// returned func runs.
func BeginImagePullQueued() func() {
	imagePullQueued.Add(1)
	return func() { imagePullQueued.Add(-1) }
}

// BeginImagePullInflight counts a pull holding a pull slot until the
// returned func runs.
func BeginImagePullInflight() func() {
	imagePullInflight.Add(1)
	return func() { imagePullInflight.Add(-1) }
}

// classifyImagePullError is a failed pull's reason (the metric's label, and
// TransientPullFailure's input). It judges the cause only: typed errors
// first (a backoff refusal, the context, the registry's HTTP status, a
// network timeout, a refused or reset connection), then the text of the
// innermost error with every image reference, URL and address taken out, so
// a ref named "timeout-proxy" or a "linux/arm64" platform cannot pick the
// class. Permanent classes win over transient ones on text.
func classifyImagePullError(err error) string {
	if err == nil {
		return ""
	}
	var refusal *PullBackoffError
	if errors.As(err, &refusal) {
		return "backoff"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var status remoteerrors.ErrUnexpectedStatus
	if errors.As(err, &status) {
		switch {
		case status.StatusCode == http.StatusUnauthorized || status.StatusCode == http.StatusForbidden:
			return "auth"
		case status.StatusCode == http.StatusNotFound:
			return "not_found"
		case status.StatusCode == http.StatusTooManyRequests:
			return "rate_limited"
		case status.StatusCode == http.StatusRequestTimeout:
			return "timeout"
		case status.StatusCode >= 500:
			return "unavailable"
		default:
			return "error"
		}
	}
	if errdefs.IsNotFound(err) {
		return "not_found"
	}
	if errdefs.IsUnauthorized(err) || errdefs.IsPermissionDenied(err) {
		return "auth"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "unavailable"
	}
	msg := strings.ToLower(withoutImageNames(innermostError(err).Error()))
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(msg, w) {
				return true
			}
		}
		return false
	}
	switch {
	case has("context canceled"):
		return "canceled"
	case has("unauthorized", "authentication required", "denied", "forbidden"):
		return "auth"
	case has("manifest unknown", "not found", "no such image", "does not exist"):
		return "not_found"
	case has("too many requests", "toomanyrequests", "rate limit"):
		return "rate_limited"
	case has("deadline exceeded", "timeout", "timed out"):
		return "timeout"
	case has("500 internal server error", "502 bad gateway", "503 service unavailable",
		"connection refused", "connection reset", "unexpected eof"):
		return "unavailable"
	default:
		return "error"
	}
}

// innermostError is the error at the bottom of err's chain (the first
// branch of a join): the failure itself, without the wrappers that name
// the image or the step.
func innermostError(err error) error {
	for {
		switch u := err.(type) {
		case interface{ Unwrap() error }:
			next := u.Unwrap()
			if next == nil {
				return err
			}
			err = next
		case interface{ Unwrap() []error }:
			errs := u.Unwrap()
			if len(errs) == 0 || errs[0] == nil {
				return err
			}
			err = errs[0]
		default:
			return err
		}
	}
}

// withoutImageNames drops every word of msg that can name an image, a
// registry or an address: anything with a slash, an @, or a colon before
// its end ("docker.io/acme/timeout-proxy:v9", "alpine:3.20",
// "10.0.0.9:5000:", "https://r/v2/"). What is left is the error's own
// wording.
func withoutImageNames(msg string) string {
	words := strings.Fields(msg)
	kept := words[:0]
	for _, w := range words {
		body := strings.TrimRight(w, ":,")
		if strings.ContainsAny(body, "/@") || strings.Contains(body, ":") {
			continue
		}
		kept = append(kept, w)
	}
	return strings.Join(kept, " ")
}
