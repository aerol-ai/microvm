package apiclient

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// defaultMaxRetryAfterMs caps how long one retry waits on the server's
// Retry-After. An overloaded node asks for about a second, so the cap only
// bites on a long ask (maintenance, a misconfigured proxy), which should not
// hold a call for minutes per retry.
const defaultMaxRetryAfterMs = 30_000

// maxRetryAfterSeconds is the largest delta-seconds value that fits in a
// time.Duration. Anything above it is clamped: no cap is that long anyway.
const maxRetryAfterSeconds = int64(math.MaxInt64 / int64(time.Second))

// retryAfterHint returns the response's Retry-After header when the status
// is one the server sends it with to pace clients: 429 (this caller is over
// its share) and 503 (the node is shedding load). A 421, 502 or 504 comes
// from a routing or proxy hop, so any Retry-After on it is not the server's
// pacing and the normal backoff applies.
func retryAfterHint(response *http.Response) string {
	switch response.StatusCode {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return response.Header.Get("Retry-After")
	}
	return ""
}

// parseRetryAfter reads a Retry-After value in either form RFC 9110 allows:
// delta-seconds ("120") or an HTTP-date. A date already past is a zero wait.
// ok is false for an empty or malformed value, so the caller falls back to
// its own backoff.
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if isASCIIDigits(value) {
		// ParseInt alone would also take "+5" and "-5", which the header
		// grammar does not allow. Out of range means absurdly long.
		secs, err := strconv.ParseInt(value, 10, 64)
		if err != nil || secs > maxRetryAfterSeconds {
			secs = maxRetryAfterSeconds
		}
		return time.Duration(secs) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	return max(when.Sub(now), 0), true
}

func isASCIIDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// retryWait is how long doWithRetry sleeps before re-sending. attempt counts
// from 0, retryAfter is retryAfterHint's result ("" for a transport error)
// and r is uniform in [0, 1).
func (c *Client) retryWait(attempt int, retryAfter string, now time.Time, r float64) time.Duration {
	delayMs := *c.retryConfig.BaseDelayMs * (1 << attempt)
	if delayMs > *c.retryConfig.MaxDelayMs {
		delayMs = *c.retryConfig.MaxDelayMs
	}
	backoff := time.Duration(delayMs) * time.Millisecond
	limitMs := *c.retryConfig.MaxRetryAfterMs
	if hint, ok := parseRetryAfter(retryAfter, now); ok && limitMs > 0 {
		return waitForHint(hint, backoff, time.Duration(limitMs)*time.Millisecond, r)
	}
	// ±25% so concurrent callers don't retry in lockstep.
	return time.Duration(float64(backoff) * (0.75 + 0.5*r))
}

// waitForHint turns the server's Retry-After into a wait. It never retries
// sooner than the server asked (nor sooner than the client's own backoff),
// and adds up to a fifth on top so clients told the same value spread out.
// limit is a hard ceiling: when the server asks for at least that long, the
// client is early anyway, so the spread goes below the limit instead.
func waitForHint(hint, backoff, limit time.Duration, r float64) time.Duration {
	target := max(hint, backoff)
	if target >= limit {
		return limit - time.Duration(float64(limit/5)*r)
	}
	upper := min(target+target/5, limit)
	return target + time.Duration(float64(upper-target)*r)
}

// sleepCtx waits for d or until ctx ends, whichever is first, so a cancelled
// call or an expired deadline never sits out a long Retry-After.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
