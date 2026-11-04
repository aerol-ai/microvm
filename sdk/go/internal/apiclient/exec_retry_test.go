package apiclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

const execPath = "/v1/sandboxes/sb-1/toolbox/process/execute"

// fastRetryClient returns a client that would re-send up to three times with
// millisecond backoff, so a retry regression shows up as extra requests
// instead of a slow test.
func fastRetryClient(baseURL string, httpClient *http.Client) *Client {
	maxRetries, delay := 3, 1
	return NewClient(baseURL, ClientOptions{
		PATToken:   "pat",
		HTTPClient: httpClient,
		Retry:      &RetryConfig{MaxRetries: &maxRetries, BaseDelayMs: &delay, MaxDelayMs: &delay},
	})
}

// dropConnection hijacks the connection and closes it without writing a
// response: the server has the request, the client sees EOF.
func dropConnection(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Errorf("Hijack() error = %v", err)
		return
	}
	_ = conn.Close()
}

// countingTransport counts round trips so a test can see retries that never
// reach a server (the connection-refused case has no handler to count them).
type countingTransport struct {
	next  http.RoundTripper
	calls atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return c.next.RoundTrip(r)
}

// TestExecNotResentAfterAmbiguousFailure is the regression test for exec
// re-running the user's command: once the server may have received the
// request, a failure must surface after exactly one exec request.
func TestExecNotResentAfterAmbiguousFailure(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		respond func(t *testing.T, w http.ResponseWriter, r *http.Request)
		status  int
	}{
		{
			name:    "connection_closed_after_request",
			respond: func(t *testing.T, w http.ResponseWriter, _ *http.Request) { dropConnection(t, w) },
		},
		{
			name:    "response_timeout",
			timeout: 100 * time.Millisecond,
			respond: func(_ *testing.T, _ http.ResponseWriter, r *http.Request) {
				// Hold the request until the client gives up and hangs up.
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
			},
		},
		{name: "bad_gateway", status: http.StatusBadGateway},
		{name: "gateway_timeout", status: http.StatusGatewayTimeout},
		{name: "misdirected_request", status: http.StatusMisdirectedRequest},
		{name: "internal_server_error", status: http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var execs atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != execPath {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					return
				}
				_, _ = io.ReadAll(r.Body)
				execs.Add(1)
				if tc.respond != nil {
					tc.respond(t, w, r)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":"refused"}`))
			}))
			defer server.Close()

			httpClient := server.Client()
			httpClient.Timeout = tc.timeout
			client := fastRetryClient(server.URL, httpClient)

			_, err := client.Exec(context.Background(), "sb-1", ExecRequest{Command: "sleep 40"})
			if err == nil {
				t.Fatal("Exec() succeeded, want the failure surfaced")
			}
			if tc.status != 0 {
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status {
					t.Fatalf("Exec() error = %v, want APIError %d", err, tc.status)
				}
			}
			if got := execs.Load(); got != 1 {
				t.Fatalf("server saw %d exec requests, want 1", got)
			}
		})
	}
}

// TestSandboxExecNotResentAfterDroppedConnection covers the sandbox-level
// wrapper, which reaches the same Client.Exec.
func TestSandboxExecNotResentAfterDroppedConnection(t *testing.T) {
	var execs atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		execs.Add(1)
		dropConnection(t, w)
	}))
	defer server.Close()

	sb := &Sandbox{Sandbox: models.Sandbox{ID: "sb-1"}, client: fastRetryClient(server.URL, server.Client())}
	if _, err := sb.Exec(context.Background(), "sleep 40"); err == nil {
		t.Fatal("Sandbox.Exec() succeeded, want the failure surfaced")
	}
	if got := execs.Load(); got != 1 {
		t.Fatalf("server saw %d exec requests, want 1", got)
	}
}

// TestExecRetriesWhenRequestNeverSent proves exec still recovers from the
// failures that cannot have run the command.
func TestExecRetriesWhenRequestNeverSent(t *testing.T) {
	t.Run("connection_refused", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen() error = %v", err)
		}
		closedURL := "http://" + listener.Addr().String()
		_ = listener.Close()

		transport := &countingTransport{next: &http.Transport{}}
		client := fastRetryClient(closedURL, &http.Client{Transport: transport})

		_, err = client.Exec(context.Background(), "sb-1", ExecRequest{Command: "true"})
		if err == nil {
			t.Fatal("Exec() against a closed port succeeded")
		}
		if !isUnsentTransportError(err) {
			t.Fatalf("Exec() error = %v, want a dial error", err)
		}
		if got := transport.calls.Load(); got != 4 {
			t.Fatalf("Exec() made %d attempts, want 4 (1 + 3 retries)", got)
		}
	})

	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			var execs atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if execs.Add(1) == 1 {
					w.WriteHeader(status)
					return
				}
				_, _ = w.Write([]byte(`{"exit_code":0,"stdout":"ok"}`))
			}))
			defer server.Close()

			result, err := fastRetryClient(server.URL, server.Client()).Exec(context.Background(), "sb-1", ExecRequest{Command: "true"})
			if err != nil {
				t.Fatalf("Exec() error = %v", err)
			}
			if result.Stdout != "ok" || execs.Load() != 2 {
				t.Fatalf("Exec() = %+v after %d requests, want ok after 2", result, execs.Load())
			}
		})
	}
}

// TestNonExecRequestStillRetriesDroppedConnection pins that narrowing exec
// left every other endpoint's retry behavior alone.
func TestNonExecRequestStillRetriesDroppedConnection(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			dropConnection(t, w)
			return
		}
		_, _ = w.Write([]byte(`{"id":"sb-1","status":"started"}`))
	}))
	defer server.Close()

	sandbox, err := fastRetryClient(server.URL, server.Client()).Get(context.Background(), "sb-1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if sandbox.ID != "sb-1" || calls.Load() != 2 {
		t.Fatalf("Get() = %q after %d requests, want sb-1 after 2", sandbox.ID, calls.Load())
	}
}

func TestIsUnsentTransportError(t *testing.T) {
	dial := func(inner error) error {
		return &url.Error{Op: "Post", URL: "http://h", Err: &net.OpError{Op: "dial", Net: "tcp", Err: inner}}
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"connection_refused", dial(os.NewSyscallError("connect", syscall.ECONNREFUSED)), true},
		{"connect_timeout", dial(os.ErrDeadlineExceeded), true},
		{"dns_failure", dial(&net.DNSError{Err: "no such host", Name: "h", IsNotFound: true}), true},
		{"bare_dns_error", &net.DNSError{Err: "no such host", Name: "h"}, true},
		{"dial_through_proxy", &url.Error{Op: "Post", URL: "http://h", Err: &net.OpError{Op: "proxyconnect", Net: "tcp", Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}}, true},
		{"caller_canceled_dial", dial(context.Canceled), false},
		{"proxyconnect_eof", &net.OpError{Op: "proxyconnect", Net: "tcp", Err: io.EOF}, false},
		{"read_reset", &url.Error{Op: "Post", URL: "http://h", Err: &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}}, false},
		{"write_broken_pipe", &net.OpError{Op: "write", Net: "tcp", Err: syscall.EPIPE}, false},
		{"eof", &url.Error{Op: "Post", URL: "http://h", Err: io.EOF}, false},
		{"unexpected_eof", io.ErrUnexpectedEOF, false},
		{"deadline_exceeded", context.DeadlineExceeded, false},
		// A message is not proof the request was unsent; only typed errors are.
		{"refused_message_only", errors.New("connection refused"), false},
		{"timeout_message_only", errors.New("i/o timeout"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUnsentTransportError(tc.err); got != tc.want {
				t.Fatalf("isUnsentTransportError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRetryPolicyStatuses(t *testing.T) {
	for _, code := range []int{200, 400, 404, 421, 429, 500, 502, 503, 504} {
		if got, want := retryIdempotent.retriesStatus(code), isRetryableStatusCode(code); got != want {
			t.Fatalf("retryIdempotent.retriesStatus(%d) = %v, want %v", code, got, want)
		}
		want := code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable
		if got := retryUnsentOnly.retriesStatus(code); got != want {
			t.Fatalf("retryUnsentOnly.retriesStatus(%d) = %v, want %v", code, got, want)
		}
	}
	reset := errors.New("connection reset by peer")
	if !retryIdempotent.retriesError(reset) || retryUnsentOnly.retriesError(reset) {
		t.Fatal("a reset must be retried for idempotent requests only")
	}
}
