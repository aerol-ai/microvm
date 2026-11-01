package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		value string
		want  time.Duration
		ok    bool
	}{
		{name: "empty", value: ""},
		{name: "blank", value: "   "},
		{name: "seconds", value: "3", want: 3 * time.Second, ok: true},
		{name: "seconds with spaces", value: " 3 ", want: 3 * time.Second, ok: true},
		{name: "zero", value: "0", ok: true},
		{name: "negative", value: "-1"},
		{name: "plus sign", value: "+3"},
		{name: "fraction", value: "1.5"},
		{name: "word", value: "soon"},
		{name: "too large clamps", value: "99999999999999999999", want: time.Duration(maxRetryAfterSeconds) * time.Second, ok: true},
		{name: "IMF-fixdate", value: "Mon, 02 Nov 2026 12:00:07 GMT", want: 7 * time.Second, ok: true},
		{name: "RFC 850 date", value: "Monday, 02-Nov-26 12:00:07 GMT", want: 7 * time.Second, ok: true},
		{name: "asctime date", value: "Mon Nov  2 12:00:07 2026", want: 7 * time.Second, ok: true},
		{name: "past date is zero", value: "Mon, 02 Nov 2026 11:59:00 GMT", ok: true},
		{name: "bad date", value: "Mon, 32 Nov 2026 12:00:07 GMT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tt.value, now)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("parseRetryAfter(%q) = %v, %v; want %v, %v", tt.value, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestRetryWait(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	ms := time.Millisecond
	tests := []struct {
		name       string
		limitMs    int
		attempt    int
		retryAfter string
		r          float64
		want       time.Duration
	}{
		{name: "no header: backoff minus a quarter", limitMs: 2000, retryAfter: "", r: 0, want: 75 * ms},
		{name: "no header: backoff plus a quarter", limitMs: 2000, retryAfter: "", r: 1, want: 125 * ms},
		{name: "no header: doubles per attempt", limitMs: 2000, attempt: 2, r: 0.5, want: 400 * ms},
		{name: "no header: backoff capped by MaxDelayMs", limitMs: 2000, attempt: 5, r: 0.5, want: 1000 * ms},
		{name: "malformed header falls back", limitMs: 2000, retryAfter: "soon", r: 0, want: 75 * ms},
		{name: "seconds: never sooner than asked", limitMs: 2000, retryAfter: "1", r: 0, want: time.Second},
		{name: "seconds: at most a fifth later", limitMs: 2000, retryAfter: "1", r: 1, want: 1200 * ms},
		{name: "HTTP date", limitMs: 2000, retryAfter: "Mon, 02 Nov 2026 12:00:01 GMT", r: 0, want: time.Second},
		{name: "backoff is the floor", limitMs: 2000, attempt: 2, retryAfter: "0", r: 0, want: 400 * ms},
		{name: "spread stops at the cap", limitMs: 1100, retryAfter: "1", r: 1, want: 1100 * ms},
		{name: "long ask is cut to the cap", limitMs: 2000, retryAfter: "120", r: 0, want: 2000 * ms},
		{name: "long ask spreads below the cap", limitMs: 2000, retryAfter: "120", r: 1, want: 1600 * ms},
		{name: "cap 0 ignores the header", limitMs: 0, retryAfter: "120", r: 0, want: 75 * ms},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, maxDelay, limit := 100, 1000, tt.limitMs
			client := NewClient("http://unused", ClientOptions{
				PATToken: "pat",
				Retry:    &RetryConfig{BaseDelayMs: &base, MaxDelayMs: &maxDelay, MaxRetryAfterMs: &limit},
			})
			if got := client.retryWait(tt.attempt, tt.retryAfter, now, tt.r); got != tt.want {
				t.Fatalf("retryWait() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewClientDefaultsMaxRetryAfter(t *testing.T) {
	client := NewClient("http://unused", ClientOptions{PATToken: "pat"})
	if got := *client.retryConfig.MaxRetryAfterMs; got != defaultMaxRetryAfterMs {
		t.Fatalf("MaxRetryAfterMs = %d, want %d", got, defaultMaxRetryAfterMs)
	}
}

// pacedServer answers the first `refusals` requests with status and the
// Retry-After header retryAfter() returns, then 200 with a sandbox. It
// records when each request arrived.
type pacedServer struct {
	*httptest.Server
	mu       sync.Mutex
	arrivals []time.Time
}

func newPacedServer(t *testing.T, status, refusals int, retryAfter func() string) *pacedServer {
	t.Helper()
	s := &pacedServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		s.mu.Lock()
		s.arrivals = append(s.arrivals, time.Now())
		n := len(s.arrivals)
		s.mu.Unlock()
		if n <= refusals {
			if v := retryAfter(); v != "" {
				w.Header().Set("Retry-After", v)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"busy","code":"overloaded"}`))
			return
		}
		if r.URL.Path == execPath {
			_ = json.NewEncoder(w).Encode(models.ExecResult{ExitCode: 0})
			return
		}
		_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb-1", Status: models.SandboxStatusStarted})
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *pacedServer) requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.arrivals)
}

// gap is the time between the first two requests: the client's wait plus one
// round trip.
func (s *pacedServer) gap(t *testing.T) time.Duration {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.arrivals) < 2 {
		t.Fatalf("server saw %d requests, want a retry", len(s.arrivals))
	}
	return s.arrivals[1].Sub(s.arrivals[0])
}

func fixed(v string) func() string { return func() string { return v } }

// getOrExec runs one call through each retry policy: Get is idempotent, exec
// is re-sent only after a refusal.
var getOrExec = map[string]func(ctx context.Context, c *Client) error{
	"get": func(ctx context.Context, c *Client) error {
		_, err := c.Get(ctx, "sb-1")
		return err
	},
	"exec": func(ctx context.Context, c *Client) error {
		_, err := c.Exec(ctx, "sb-1", ExecRequest{Command: "true"})
		return err
	},
}

// TestRetryHonoursRetryAfter: with a 1 ms backoff, only the server's
// Retry-After can explain a second-long gap between the two requests.
func TestRetryHonoursRetryAfter(t *testing.T) {
	inTwoSeconds := func() string { return time.Now().Add(2 * time.Second).UTC().Format(http.TimeFormat) }
	tests := []struct {
		name       string
		status     int
		retryAfter func() string
		min, max   time.Duration
	}{
		{name: "429 seconds", status: http.StatusTooManyRequests, retryAfter: fixed("1"), min: time.Second, max: 2 * time.Second},
		{name: "503 seconds", status: http.StatusServiceUnavailable, retryAfter: fixed("1"), min: time.Second, max: 2 * time.Second},
		// The date has whole-second precision, so it asks for 1-2 s.
		{name: "503 HTTP date", status: http.StatusServiceUnavailable, retryAfter: inTwoSeconds, min: time.Second, max: 3 * time.Second},
	}
	for _, tt := range tests {
		for callName, call := range getOrExec {
			t.Run(tt.name+"/"+callName, func(t *testing.T) {
				t.Parallel()
				server := newPacedServer(t, tt.status, 1, tt.retryAfter)
				if err := call(context.Background(), fastRetryClient(server.URL, server.Client())); err != nil {
					t.Fatalf("call after Retry-After: %v", err)
				}
				if gap := server.gap(t); gap < tt.min || gap > tt.max {
					t.Fatalf("retry came %v after the refusal, want %v-%v", gap, tt.min, tt.max)
				}
			})
		}
	}
}

func TestRetryAfterIsCapped(t *testing.T) {
	server := newPacedServer(t, http.StatusServiceUnavailable, 1, fixed("120"))
	maxRetries, delay, limit := 3, 1, 100
	client := NewClient(server.URL, ClientOptions{
		PATToken:   "pat",
		HTTPClient: server.Client(),
		Retry:      &RetryConfig{MaxRetries: &maxRetries, BaseDelayMs: &delay, MaxDelayMs: &delay, MaxRetryAfterMs: &limit},
	})
	if _, err := client.Get(context.Background(), "sb-1"); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if gap := server.gap(t); gap < 80*time.Millisecond || gap > time.Second {
		t.Fatalf("retry came %v after Retry-After: 120 with a 100 ms cap", gap)
	}
}

// TestRetryWithoutUsableRetryAfterUsesBackoff covers a missing or malformed
// header on a paced status, and a header on a status that is not the
// server's pacing (421/502/504 come from routing and proxy hops).
func TestRetryWithoutUsableRetryAfterUsesBackoff(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		retryAfter string
	}{
		{name: "503 without header", status: http.StatusServiceUnavailable},
		{name: "429 malformed", status: http.StatusTooManyRequests, retryAfter: "soon"},
		{name: "503 negative", status: http.StatusServiceUnavailable, retryAfter: "-1"},
		{name: "421 ignores header", status: http.StatusMisdirectedRequest, retryAfter: "120"},
		{name: "502 ignores header", status: http.StatusBadGateway, retryAfter: "120"},
		{name: "504 ignores header", status: http.StatusGatewayTimeout, retryAfter: "120"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newPacedServer(t, tt.status, 1, fixed(tt.retryAfter))
			if _, err := fastRetryClient(server.URL, server.Client()).Get(context.Background(), "sb-1"); err != nil {
				t.Fatalf("Get() error = %v", err)
			}
			if gap := server.gap(t); gap > 500*time.Millisecond {
				t.Fatalf("retry came %v later; want the 1 ms backoff", gap)
			}
		})
	}
}

func TestRetryAfterKeepsRetryBudgetAndStatuses(t *testing.T) {
	t.Run("budget unchanged", func(t *testing.T) {
		server := newPacedServer(t, http.StatusServiceUnavailable, 100, fixed("0"))
		_, err := fastRetryClient(server.URL, server.Client()).Get(context.Background(), "sb-1")
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable || apiErr.Code != "overloaded" {
			t.Fatalf("Get() error = %v, want the final 503", err)
		}
		if got := server.requests(); got != 4 {
			t.Fatalf("server saw %d requests, want 1 + 3 retries", got)
		}
	})
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status)+" not retried", func(t *testing.T) {
			server := newPacedServer(t, status, 100, fixed("1"))
			start := time.Now()
			if _, err := fastRetryClient(server.URL, server.Client()).Get(context.Background(), "sb-1"); err == nil {
				t.Fatal("Get() succeeded")
			}
			if got := server.requests(); got != 1 {
				t.Fatalf("server saw %d requests, want 1", got)
			}
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Fatalf("non-retryable status waited %v", elapsed)
			}
		})
	}
	t.Run("exec does not retry 502 even with Retry-After", func(t *testing.T) {
		server := newPacedServer(t, http.StatusBadGateway, 100, fixed("1"))
		if _, err := fastRetryClient(server.URL, server.Client()).Exec(context.Background(), "sb-1", ExecRequest{Command: "true"}); err == nil {
			t.Fatal("Exec() succeeded")
		}
		if got := server.requests(); got != 1 {
			t.Fatalf("server saw %d exec requests, want 1", got)
		}
	})
}

// TestRetryAfterWaitEndsWithContext: a cancelled call or an expired deadline
// returns at once instead of sitting out a 30 s Retry-After.
func TestRetryAfterWaitEndsWithContext(t *testing.T) {
	tests := []struct {
		name    string
		ctx     func() (context.Context, context.CancelFunc)
		wantErr error
	}{
		{
			name: "cancel",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(100*time.Millisecond, cancel)
				return ctx, cancel
			},
			wantErr: context.Canceled,
		},
		{
			name: "deadline",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 100*time.Millisecond)
			},
			wantErr: context.DeadlineExceeded,
		},
	}
	for _, tt := range tests {
		for callName, call := range getOrExec {
			t.Run(tt.name+"/"+callName, func(t *testing.T) {
				t.Parallel()
				server := newPacedServer(t, http.StatusServiceUnavailable, 100, fixed("30"))
				ctx, cancel := tt.ctx()
				defer cancel()
				start := time.Now()
				err := call(ctx, fastRetryClient(server.URL, server.Client()))
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				if elapsed := time.Since(start); elapsed > 2*time.Second {
					t.Fatalf("call returned after %v; the wait ignored ctx", elapsed)
				}
				if got := server.requests(); got != 1 {
					t.Fatalf("server saw %d requests, want 1", got)
				}
			})
		}
	}
}

// TestAPIErrorRetryAfterAcceptsHTTPDate: once retries run out, the error
// carries the server's ask in either header form.
func TestAPIErrorRetryAfterAcceptsHTTPDate(t *testing.T) {
	inAMinute := func() string { return time.Now().Add(time.Minute).UTC().Format(http.TimeFormat) }
	server := newPacedServer(t, http.StatusTooManyRequests, 100, inAMinute)
	zero := 0
	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client(), Retry: &RetryConfig{MaxRetries: &zero}})
	_, err := client.Get(context.Background(), "sb-1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %T %v is not *APIError", err, err)
	}
	if apiErr.RetryAfter < 58*time.Second || apiErr.RetryAfter > time.Minute {
		t.Fatalf("RetryAfter = %v, want about a minute", apiErr.RetryAfter)
	}
}
