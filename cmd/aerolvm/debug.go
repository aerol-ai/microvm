package main

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// debugTransport logs each API request and response line to stderr for
// --debug. The Authorization header is printed as [REDACTED]: debug output
// gets pasted into issues and chat, and the token must never land there.
type debugTransport struct {
	base http.RoundTripper
	out  io.Writer
	mu   sync.Mutex
}

func (d *debugTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	d.logf("> %s %s%s", r.Method, r.URL.Path, query(r))
	for _, line := range redactedHeaders(r.Header) {
		d.logf(">   %s", line)
	}
	resp, err := d.base.RoundTrip(r)
	if err != nil {
		d.logf("< error after %s: %v", time.Since(start).Round(time.Millisecond), err)
		return nil, err
	}
	d.logf("< %d %s in %s", resp.StatusCode, http.StatusText(resp.StatusCode), time.Since(start).Round(time.Millisecond))
	return resp, nil
}

func (d *debugTransport) logf(format string, args ...any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fmt.Fprintf(d.out, "aerolvm debug: "+format+"\n", args...)
}

func query(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	return "?" + r.URL.RawQuery
}

func redactedHeaders(h http.Header) []string {
	lines := make([]string, 0, len(h))
	for name, values := range h {
		value := strings.Join(values, ", ")
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Cookie") {
			value = "[REDACTED]"
		}
		lines = append(lines, name+": "+value)
	}
	sort.Strings(lines)
	return lines
}
