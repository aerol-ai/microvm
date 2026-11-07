package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// report is one run's result. The JSON field names are the contract the
// live use case and the docs page read.
type report struct {
	RunID          string  `json:"run_id"`
	Image          string  `json:"image"`
	Runtime        string  `json:"runtime"`
	Concurrency    int     `json:"concurrency"`
	Duration       string  `json:"duration"`
	Hold           bool    `json:"hold"`
	Interrupted    bool    `json:"interrupted"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
	// CreatesPerSecond is successful creates over ElapsedSeconds, the time
	// from the first create sent to the last one answered.
	CreatesPerSecond float64 `json:"creates_per_second"`
	Creates          counts  `json:"creates"`
	CreateLatencyMs  latency `json:"create_latency_ms"`
	DeleteLatencyMs  latency `json:"delete_latency_ms"`
	Errors           []kind  `json:"errors"`
	DeleteFailures   int     `json:"delete_failures"`
	// LeftBehind is how many of the run's sandboxes the API still lists
	// after cleanup: 0 is the goal, -1 means the check failed.
	LeftBehind int `json:"left_behind"`
	// Unsure counts creates whose answer never came (timed out or
	// abandoned): one may still finish on the server after the check.
	Unsure int `json:"unsure"`
}

type counts struct {
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	// NotStarted are successful creates whose answer said a status other
	// than started.
	NotStarted int `json:"not_started"`
	// Abandoned were in flight when a second interrupt stopped waiting.
	Abandoned int `json:"abandoned"`
}

type latency struct {
	Samples int     `json:"samples"`
	P50     float64 `json:"p50"`
	P90     float64 `json:"p90"`
	P99     float64 `json:"p99"`
	Max     float64 `json:"max"`
	Mean    float64 `json:"mean"`
}

type kind struct {
	Kind    string `json:"kind"`
	Count   int    `json:"count"`
	Example string `json:"example"`
}

func (b *bench) report(elapsed time.Duration, left int) *report {
	b.mu.Lock()
	defer b.mu.Unlock()
	rep := &report{
		RunID:           b.runID,
		Image:           b.cfg.image,
		Runtime:         b.cfg.runtime,
		Concurrency:     b.cfg.concurrency,
		Duration:        b.cfg.duration.String(),
		Hold:            b.cfg.hold,
		Interrupted:     b.interrupted.Load(),
		ElapsedSeconds:  round(elapsed.Seconds(), 3),
		CreateLatencyMs: summarize(b.createLat),
		DeleteLatencyMs: summarize(b.deleteLat),
		Errors:          []kind{},
		DeleteFailures:  b.deleteFailed,
		LeftBehind:      left,
		Unsure:          b.unsure,
	}
	rep.Creates = counts{Succeeded: len(b.createLat), NotStarted: b.notStarted, Abandoned: b.abandoned}
	for k, n := range b.failed {
		rep.Creates.Failed += n
		rep.Errors = append(rep.Errors, kind{Kind: k, Count: n, Example: truncate(b.example[k], 200)})
	}
	sort.Slice(rep.Errors, func(i, j int) bool {
		if rep.Errors[i].Count != rep.Errors[j].Count {
			return rep.Errors[i].Count > rep.Errors[j].Count
		}
		return rep.Errors[i].Kind < rep.Errors[j].Kind
	})
	if elapsed > 0 {
		rep.CreatesPerSecond = round(float64(rep.Creates.Succeeded)/elapsed.Seconds(), 2)
	}
	return rep
}

// exitCode fails a run that made nothing or left something behind.
func (r *report) exitCode() int {
	if r.Creates.Succeeded == 0 || r.LeftBehind != 0 {
		return exitFailed
	}
	return exitOK
}

func (r *report) write(w io.Writer, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	runtime := r.Runtime
	if runtime == "" {
		runtime = "the server's default"
	}
	deletes := "deleted as they were made"
	if r.Hold {
		deletes = "held to the end"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "run %s: image %s, runtime %s, concurrency %d, %s, sandboxes %s", r.RunID, r.Image, runtime, r.Concurrency, r.Duration, deletes)
	if r.Interrupted {
		b.WriteString(" (interrupted)")
	}
	fmt.Fprintf(&b, "\ncreates: %d succeeded, %d failed in %.1f s = %.2f per second\n", r.Creates.Succeeded, r.Creates.Failed, r.ElapsedSeconds, r.CreatesPerSecond)
	fmt.Fprintf(&b, "create latency: %s\n", r.CreateLatencyMs)
	fmt.Fprintf(&b, "delete latency: %s\n", r.DeleteLatencyMs)
	if r.Creates.NotStarted > 0 {
		fmt.Fprintf(&b, "not started when answered: %d\n", r.Creates.NotStarted)
	}
	if r.Creates.Abandoned > 0 {
		fmt.Fprintf(&b, "abandoned in flight: %d\n", r.Creates.Abandoned)
	}
	if len(r.Errors) == 0 {
		b.WriteString("errors: none\n")
	}
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "error %s x%d, e.g. %s\n", e.Kind, e.Count, e.Example)
	}
	if r.DeleteFailures > 0 {
		fmt.Fprintf(&b, "delete failures (retried in cleanup): %d\n", r.DeleteFailures)
	}
	switch {
	case r.LeftBehind < 0:
		fmt.Fprintf(&b, "left behind: unknown (the check failed); run: aerolvm-bench -cleanup %s\n", r.RunID)
	default:
		fmt.Fprintf(&b, "left behind: %d sandboxes\n", r.LeftBehind)
	}
	if r.Unsure > 0 {
		fmt.Fprintf(&b, "%d creates never answered and may still finish on the server; they delete themselves at -max-age, or run: aerolvm-bench -cleanup %s\n", r.Unsure, r.RunID)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func (l latency) String() string {
	if l.Samples == 0 {
		return "no samples"
	}
	return fmt.Sprintf("p50 %.1f ms, p90 %.1f ms, p99 %.1f ms, max %.1f ms (%d samples)", l.P50, l.P90, l.P99, l.Max, l.Samples)
}

// summarize takes nearest-rank percentiles: p99 of 100 samples is the
// 99th fastest, never a value between two samples.
func summarize(durs []time.Duration) latency {
	if len(durs) == 0 {
		return latency{}
	}
	sorted := append([]time.Duration(nil), durs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var sum time.Duration
	for _, d := range sorted {
		sum += d
	}
	return latency{
		Samples: len(sorted),
		P50:     ms(percentile(sorted, 50)),
		P90:     ms(percentile(sorted, 90)),
		P99:     ms(percentile(sorted, 99)),
		Max:     ms(sorted[len(sorted)-1]),
		Mean:    ms(sum / time.Duration(len(sorted))),
	}
}

// percentile is the nearest-rank p-th percentile of sorted.
func percentile(sorted []time.Duration, p float64) time.Duration {
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	return sorted[rank-1]
}

func ms(d time.Duration) float64 { return round(float64(d)/float64(time.Millisecond), 1) }

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

// errorKind groups a failed create: by HTTP status (and error code) when
// the server answered, else timeout or network.
func errorKind(err error) string {
	var apiErr *microvm.APIError
	switch {
	case errors.As(err, &apiErr):
		k := "HTTP " + strconv.Itoa(apiErr.StatusCode)
		if apiErr.Code != "" {
			k += " " + apiErr.Code
		}
		return k
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "network"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
