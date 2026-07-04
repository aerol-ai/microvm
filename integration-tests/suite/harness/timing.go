package harness

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// serverTimingTransport is a transparent http.RoundTripper that records the
// server-reported create duration from the Server-Timing response header of a
// create (POST .../sandboxes). It lets a benchmark read how long the server
// spent creating a sandbox, independent of the client<->cluster network time.
// It never alters the request or response — it only observes the header.
type serverTimingTransport struct {
	base http.RoundTripper

	mu            sync.Mutex
	lastMS        float64
	have          bool
	lastReadiness string
	haveReadiness bool
	lastStages    map[string]float64
	haveStages    bool
}

func (t *serverTimingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	// A create is the only POST whose path ends in "/sandboxes" (stop/start/etc.
	// have a longer suffix; list is a GET), so this uniquely tags create calls.
	if err == nil && resp != nil && req.Method == http.MethodPost &&
		strings.HasSuffix(req.URL.Path, "/sandboxes") && resp.StatusCode/100 == 2 {
		if ms, ok := parseServerTimingCreate(resp.Header.Get("Server-Timing")); ok {
			t.mu.Lock()
			t.lastMS, t.have = ms, true
			t.mu.Unlock()
		}
		if src, ok := parseServerTimingReadinessSource(resp.Header.Get("Server-Timing")); ok {
			t.mu.Lock()
			t.lastReadiness, t.haveReadiness = src, true
			t.mu.Unlock()
		}
		if stages := parseServerTimingStages(resp.Header.Get("Server-Timing")); len(stages) > 0 {
			t.mu.Lock()
			t.lastStages, t.haveStages = stages, true
			t.mu.Unlock()
		}
	}
	return resp, err
}

// takeCreateMS returns the most recent create duration (ms) and clears it, so a
// missing header on the next create reads as absent rather than reusing a stale
// value. Callers are serial (one create at a time), so last-write wins cleanly.
func (t *serverTimingTransport) takeCreateMS() (float64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ms, ok := t.lastMS, t.have
	t.have = false
	return ms, ok
}

// takeCreateReadinessSource returns the readiness source from the most recent
// create's Server-Timing header (readiness;desc=socket|health).
func (t *serverTimingTransport) takeCreateReadinessSource() (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	src, ok := t.lastReadiness, t.haveReadiness
	t.haveReadiness = false
	return src, ok
}

// takeCreateStages returns every <name>;dur= pair from the most recent
// create's Server-Timing header (create, runtime_wait, fc_* …) and clears
// it. The per-stage breakdown is Phase 0 of
// plans/firecracker-create-latency.md — the bench aggregates these into
// the latency[].stages block of the JSON artifact.
func (t *serverTimingTransport) takeCreateStages() (map[string]float64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	stages, ok := t.lastStages, t.haveStages
	t.lastStages, t.haveStages = nil, false
	return stages, ok
}

// parseServerTimingStages extracts every metric with a dur= attribute into
// a name→milliseconds map. Metrics without dur (e.g. readiness;desc=…)
// are skipped. Extra attributes on a dur-carrying metric are ignored —
// the presence of the fc_warm key alone marks a warm-pool hit, so the
// bench needs no desc parsing.
func parseServerTimingStages(header string) map[string]float64 {
	var stages map[string]float64
	for _, metric := range strings.Split(header, ",") {
		fields := strings.Split(metric, ";")
		name := strings.TrimSpace(fields[0])
		if name == "" {
			continue
		}
		for _, attr := range fields[1:] {
			if v, ok := strings.CutPrefix(strings.TrimSpace(attr), "dur="); ok {
				if ms, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					if stages == nil {
						stages = make(map[string]float64)
					}
					stages[name] = ms
				}
			}
		}
	}
	return stages
}

// parseServerTimingReadinessSource extracts readiness;desc=<source>.
func parseServerTimingReadinessSource(header string) (string, bool) {
	for _, metric := range strings.Split(header, ",") {
		fields := strings.Split(metric, ";")
		if strings.TrimSpace(fields[0]) != "readiness" {
			continue
		}
		for _, attr := range fields[1:] {
			if v, ok := strings.CutPrefix(strings.TrimSpace(attr), "desc="); ok {
				v = strings.TrimSpace(v)
				if v != "" {
					return v, true
				}
			}
		}
	}
	return "", false
}

// parseServerTimingCreate pulls the "create" metric's dur (milliseconds) out of
// a Server-Timing header value like "create;dur=1234.5".
func parseServerTimingCreate(header string) (float64, bool) {
	for _, metric := range strings.Split(header, ",") {
		fields := strings.Split(metric, ";")
		if strings.TrimSpace(fields[0]) != "create" {
			continue // a different Server-Timing metric (db, total, …)
		}
		for _, attr := range fields[1:] {
			if v, ok := strings.CutPrefix(strings.TrimSpace(attr), "dur="); ok {
				if ms, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					return ms, true
				}
			}
		}
	}
	return 0, false
}
