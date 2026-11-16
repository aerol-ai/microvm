package docker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	remoteerrors "github.com/containerd/containerd/v2/core/remotes/errors"
	"github.com/containerd/errdefs"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A pull failure that passes is marked for the API's 503 + Retry-After;
// one the caller must fix (a missing tag, refused credentials) or a
// cancelled create stays as it is, the 400 or nothing (issue #1343).
func TestTransientPullError(t *testing.T) {
	const backoff = 2 * time.Minute
	status := func(code int, text string) error {
		return fmt.Errorf("failed to resolve reference %q: %w", "r.example/a:1", remoteerrors.ErrUnexpectedStatus{
			Status: text, StatusCode: code, RequestURL: "https://r.example/v2/a/manifests/1", RequestMethod: "HEAD"})
	}
	for _, tc := range []struct {
		name      string
		err       error
		transient bool
	}{
		{"nil", nil, false},
		{"rate limited", errors.New(`unexpected status from HEAD request to http://r/v2/a/manifests/1: 429 Too Many Requests`), true},
		{"rate limited, typed", status(429, "429 Too Many Requests"), true},
		{"registry 500, typed", status(500, "500 Internal Server Error"), true},
		{"missing tag, typed", status(404, "404 Not Found"), false},
		{"refused login, typed", status(401, "401 Unauthorized"), false},
		{"no answer in time", errors.New(`failed to do request: Head "http://r/v2/a/manifests/1": net/http: timeout awaiting response headers`), true},
		{"network timeout, typed", fmt.Errorf("pull: %w", &net.OpError{Op: "dial", Err: timeoutError{}}), true},
		{"create deadline", fmt.Errorf("pull: %w", context.DeadlineExceeded), true},
		{"registry 503", errors.New(`unexpected status from GET request to http://r/v2/: 503 Service Unavailable`), true},
		// containerd's AOCR join (ensureImage): the PAT read's "denied"
		// is not the pull's class; the first branch, the pull, is.
		{"rate limited, pulled anonymously", fmt.Errorf("%w (AOCR cluster pull auth unavailable, pulled anonymously: %w)",
			errors.New(`unexpected status from HEAD request to http://r/v2/a/manifests/1: 429 Too Many Requests`),
			errors.New(`read AOCR cluster PAT file /run/aerolvm/pat: open /run/aerolvm/pat: permission denied`)), true},
		{"registry down", errors.New(`dial tcp 10.0.0.9:5000: connect: connection refused`), true},
		{"missing tag", errors.New(`failed to resolve reference "r/a:1": r/a:1: not found`), false},
		{"refused credentials", errors.New(`pull access denied, repository does not exist or may require authorization: unauthorized`), false},
		{"caller left", fmt.Errorf("pull: %w", context.Canceled), false},
		{"something else", errors.New("invalid reference format"), false},
		{"backoff of a rate limit", &PullBackoffError{Image: "r/a:1", Until: time.Now().Add(time.Minute), Cause: "429", Transient: true}, true},
		{"backoff of a missing tag", &PullBackoffError{Image: "r/a:1", Until: time.Now().Add(time.Minute), Cause: "not found"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := TransientPullError(tc.err, backoff)
			if errors.Is(got, models.ErrImagePullUnavailable) != tc.transient {
				t.Fatalf("TransientPullError(%v) = %v; marked unavailable = %v, want %v", tc.err, got, !tc.transient, tc.transient)
			}
			if tc.err != nil && !errors.Is(got, tc.err) {
				t.Fatalf("the cause is lost: %v", got)
			}
			if tc.err != nil && classifyImagePullError(got) != classifyImagePullError(tc.err) {
				t.Fatalf("a marked failure keeps its class: %q, want %q", classifyImagePullError(got), classifyImagePullError(tc.err))
			}
			if again := TransientPullError(got, backoff); again != got {
				t.Fatalf("marked twice: %v", again)
			}
			var marked *models.ImagePullUnavailableError
			if errors.As(got, &marked) && marked.RetryAfter != backoff {
				t.Fatalf("Retry-After %v, want the backoff %v", marked.RetryAfter, backoff)
			}
		})
	}
}

// Only the failure's cause decides, never words of the wrapper or the
// image's name (issue #1343 review): a refusal's own "backing off" or
// "suppressed by failure backoff" wording made a backoff of a permanent
// failure a 503 for its whole window, re-armed by steady traffic, though
// the failure itself was a 400; and a missing tag on a ref named
// "timeout-proxy" read as a timeout.
func TestTransientPullErrorKeepsPermanentCauses(t *testing.T) {
	// Permanent, and neither auth nor not-found: the image has no manifest
	// for this node's platform (dockerd's wording).
	permanent := errors.New("no matching manifest for linux/arm64/v8 in the manifest list entries")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"first failure", permanent},
		{"dockerd's old backoff wording around it", fmt.Errorf("pull image %s suppressed by failure backoff until %s: %w",
			"docker.io/acme/app:v1", "2026-11-17T10:00:00Z", permanent)},
		{"containerd's backoff wording around it", fmt.Errorf("image pull for %q backing off after recent failure: %w",
			"docker.io/acme/app:v1", permanent)},
		{"missing tag on a ref named timeout", errors.New(
			`failed to resolve reference "docker.io/acme/timeout-proxy:v9": docker.io/acme/timeout-proxy:v9: not found`)},
		{"missing tag on a bare ref named timeout", errors.New(`pull access denied for timeout, repository does not exist`)},
		{"schema 1 manifest on containerd 2", errors.New(
			"failed to pull: converting from schema 1 manifests is not supported (media type application/vnd.docker.distribution.manifest.v1+prettyjws)")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := TransientPullError(tc.err, time.Minute); errors.Is(got, models.ErrImagePullUnavailable) {
				t.Errorf("%v\n  -> 503 image_pull_unavailable; a permanent failure stays 400 (class %q)",
					tc.err, classifyImagePullError(tc.err))
			}
		})
	}
}

// The cause a backoff keeps is short: it stays for the whole backoff.
func TestFlattenPullCauseIsCapped(t *testing.T) {
	long := errors.New(strings.Repeat("é", 4096))
	got := FlattenPullCause(long)
	if len(got) > maxPullCauseBytes+3 || !utf8.ValidString(got) {
		t.Fatalf("flattened cause: %d bytes, valid UTF-8 %v; want at most %d", len(got), utf8.ValidString(got), maxPullCauseBytes+3)
	}
	if FlattenPullCause(errors.New("short")) != "short" || FlattenPullCause(nil) != "" {
		t.Fatal("a short cause is kept as it is")
	}
}

// timeoutError is a net.Error that timed out.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassifyImagePullError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: ""},
		{name: "context_canceled_sentinel", err: context.Canceled, want: "canceled"},
		{name: "context_deadline_exceeded_sentinel", err: context.DeadlineExceeded, want: "timeout"},
		{name: "wrapped_context_canceled", err: fmt.Errorf("op failed: %w", context.Canceled), want: "canceled"},
		{name: "string_context_canceled", err: errors.New("context canceled"), want: "canceled"},
		{name: "string_deadline_exceeded", err: errors.New("deadline exceeded"), want: "timeout"},
		{name: "string_timeout", err: errors.New("i/o timeout"), want: "timeout"},
		{name: "string_timed_out", err: errors.New("connection timed out"), want: "timeout"},
		{name: "string_unauthorized", err: errors.New("unauthorized"), want: "auth"},
		{name: "string_authentication_required", err: errors.New("authentication required"), want: "auth"},
		{name: "string_denied", err: errors.New("access denied"), want: "auth"},
		{name: "string_manifest_unknown", err: errors.New("manifest unknown"), want: "not_found"},
		{name: "string_not_found", err: errors.New("image not found"), want: "not_found"},
		{name: "string_no_such_image", err: errors.New("no such image"), want: "not_found"},
		{name: "string_too_many_requests", err: errors.New("too many requests"), want: "rate_limited"},
		{name: "string_rate_limit", err: errors.New("rate limit exceeded"), want: "rate_limited"},
		{name: "backoff_refusal", err: fmt.Errorf("create: %w", &PullBackoffError{Image: "r/a:1", Cause: "boom"}), want: "backoff"},
		{name: "refusal_wording_is_not_a_class", err: errors.New(`image pull for "localhost:5000/drill/app:v1" backing off after recent failure`), want: "error"},
		{name: "status_404", err: remoteerrors.ErrUnexpectedStatus{StatusCode: 404, Status: "404 Not Found"}, want: "not_found"},
		{name: "status_403", err: remoteerrors.ErrUnexpectedStatus{StatusCode: 403, Status: "403 Forbidden"}, want: "auth"},
		{name: "status_502", err: remoteerrors.ErrUnexpectedStatus{StatusCode: 502, Status: "502 Bad Gateway"}, want: "unavailable"},
		{name: "errdefs_not_found", err: fmt.Errorf("r/a:1: %w", errdefs.ErrNotFound), want: "not_found"},
		{name: "image_name_is_not_a_class", err: errors.New(`docker.io/acme/ratelimit-timeout:v1: some unexpected failure`), want: "error"},
		{name: "unknown_error", err: errors.New("some unexpected failure"), want: "error"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyImagePullError(tc.err)
			if got != tc.want {
				t.Fatalf("classifyImagePullError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
