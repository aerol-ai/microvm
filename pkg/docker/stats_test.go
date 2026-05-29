package docker

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestContainerStatsParsesWorkingSet(t *testing.T) {
	const body = `{
		"cpu_stats": {"cpu_usage": {"total_usage": 12345678901}},
		"memory_stats": {"usage": 536870912, "stats": {"inactive_file": 134217728}}
	}`
	var gotPath, gotQuery string
	c := &Client{
		logger: slog.Default(),
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			gotPath = r.URL.Path
			gotQuery = r.URL.RawQuery
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		})},
	}

	stat, err := c.ContainerStats(context.Background(), "sb-1")
	if err != nil {
		t.Fatalf("ContainerStats: %v", err)
	}
	if !strings.Contains(gotPath, "/containers/sb-1/stats") {
		t.Fatalf("path = %q, want .../containers/sb-1/stats", gotPath)
	}
	if !strings.Contains(gotQuery, "stream=false") {
		t.Fatalf("query = %q, want stream=false (one-shot)", gotQuery)
	}
	if stat.CPUTotalNanos != 12345678901 {
		t.Fatalf("CPUTotalNanos = %d, want 12345678901", stat.CPUTotalNanos)
	}
	// working set = usage - inactive_file = 536870912 - 134217728 = 402653184
	if stat.MemBytes != 402653184 {
		t.Fatalf("MemBytes = %d, want 402653184 (usage - inactive_file)", stat.MemBytes)
	}
}
