package docker

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSandboxIDFromContainerNameCases(t *testing.T) {
	tests := []struct {
		name          string
		containerName string
		want          string
	}{
		{name: "strips_leading_slash", containerName: "/sandbox-abc123def456", want: "sandbox-abc123def456"},
		{name: "trims_whitespace", containerName: "  /sandbox-abc123  ", want: "sandbox-abc123"},
		{name: "no_slash_returns_as_is", containerName: "sandbox-abc123", want: "sandbox-abc123"},
		{name: "returns_empty_for_blank", containerName: "", want: ""},
		{name: "returns_empty_for_only_slash", containerName: "/", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sandboxIDFromContainerName(tc.containerName); got != tc.want {
				t.Fatalf("sandboxIDFromContainerName(%q) = %q, want %q", tc.containerName, got, tc.want)
			}
		})
	}
}

func TestSplitSnapshotImageRefCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantRepo string
		wantTag  string
		wantErr  bool
	}{
		{name: "repo only", input: "snapshot-alpha", wantRepo: "snapshot-alpha"},
		{name: "repo with tag", input: "snapshot-alpha:v1", wantRepo: "snapshot-alpha", wantTag: "v1"},
		{name: "registry port without tag", input: "localhost:5000/snapshot-alpha", wantRepo: "localhost:5000/snapshot-alpha"},
		{name: "registry port with tag", input: "localhost:5000/snapshot-alpha:v2", wantRepo: "localhost:5000/snapshot-alpha", wantTag: "v2"},
		{name: "reject digest", input: "snapshot@sha256:abc", wantErr: true},
		{name: "reject blank", input: " ", wantErr: true},
		{name: "reject trailing colon", input: "snapshot:", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo, tag, err := splitSnapshotImageRef(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("splitSnapshotImageRef(%q) expected error", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitSnapshotImageRef(%q) error = %v", tc.input, err)
			}
			if repo != tc.wantRepo || tag != tc.wantTag {
				t.Fatalf("splitSnapshotImageRef(%q) = (%q, %q), want (%q, %q)", tc.input, repo, tag, tc.wantRepo, tc.wantTag)
			}
		})
	}
}

func TestPullImageDedupSharesInflightPull(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	client := &Client{
		logger: slog.Default(),
		streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			<-release
			return pullResponse(`{"status":"done"}`), nil
		})},
		pulls:        make(map[string]*imagePull),
		pullFailures: make(map[string]imagePullFailure),
		pullBackoff:  time.Minute,
	}

	errs := make(chan error, 2)
	go func() { errs <- client.pullImageDedup(context.Background(), "busybox:latest", nil) }()
	for deadline := time.Now().Add(time.Second); calls.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	go func() { errs <- client.pullImageDedup(context.Background(), "busybox:latest", nil) }()

	time.Sleep(25 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("pull calls while first in-flight = %d, want 1", got)
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("pullImageDedup error = %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("pull calls after waiters completed = %d, want 1", got)
	}
}

func TestPullImageDedupBacksOffAfterFailure(t *testing.T) {
	var calls atomic.Int64
	client := &Client{
		logger: slog.Default(),
		streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return pullResponse(`{"error":"too many requests"}`), nil
		})},
		pulls:        make(map[string]*imagePull),
		pullFailures: make(map[string]imagePullFailure),
		pullBackoff:  time.Minute,
	}

	if err := client.pullImageDedup(context.Background(), "registry.example/app:bad", nil); err == nil {
		t.Fatalf("first pull expected error")
	}
	if err := client.pullImageDedup(context.Background(), "registry.example/app:bad", nil); err == nil || !strings.Contains(err.Error(), "backoff") {
		t.Fatalf("second pull expected backoff error, got %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("pull calls = %d, want 1 while backoff is active", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func pullResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
