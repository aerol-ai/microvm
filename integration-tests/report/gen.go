// Command gen turns `go test -json` output into the use-case coverage report:
// a per-scenario JSON + Markdown file and an aggregate matrix. It deliberately
// reuses harness.Registry as the source of truth for rows, so "pending" (a use
// case with no test yet) is distinguishable from "skipped" (a test that ran but
// the scenario didn't satisfy its capabilities) — the distinction the plan
// promised, without a real code-coverage engine.
//
//	go test -tags=integration -json ./suite/... | \
//	  go run ./report -scenario single-node -out reports
//
// On spot reclaim the run is inconclusive, not failed:
//
//	go run ./report -scenario cluster-hetero -inconclusive -out reports
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// Status is the per-cell verdict in the matrix.
type Status string

const (
	StatusPass         Status = "pass"
	StatusFail         Status = "fail"
	StatusSkip         Status = "skip"         // ran, scenario lacked capabilities
	StatusPending      Status = "pending"      // no test implemented yet
	StatusInconclusive Status = "inconclusive" // infra event (spot reclaim), not a verdict
	StatusMissing      Status = "missing"      // implemented but no result observed -> treat as fail
)

// testEvent is one line of `go test -json`.
type testEvent struct {
	Action string `json:"Action"` // run|pass|fail|skip|output|...
	Test   string `json:"Test"`
	Output string `json:"Output"`
}

// Result is one matrix row for one scenario.
type Result struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status Status `json:"status"`
	// Reason explains a non-pass status: the capability-skip message for skips,
	// the assertion/error output for fails, a fixed note for missing. Empty for
	// passes. Surfaced in the JSON and the markdown "Detail" column so a red run
	// is debuggable without re-reading the raw test.json.
	Reason string `json:"reason,omitempty"`
}

// Report is the serialized per-scenario artifact.
type Report struct {
	Scenario string   `json:"scenario"`
	Results  []Result `json:"results"`
	Summary  Summary  `json:"summary"`
}

type Summary struct {
	Pass, Fail, Skip, Pending, Inconclusive, Missing, Total int
}

var ucRE = regexp.MustCompile(`UC-[0-9]+[a-z]?`)

// ucMarkerRE matches the `ucid=UC-NN` line harness.Require logs for every test.
// The suite tests are flat-named (TestSnapshotCreate), not TestX/UC-NN
// subtests, so the UC id never appears in the test-event name — this marker in
// the test's output is the only place it surfaces for a passing test.
var ucMarkerRE = regexp.MustCompile(`ucid=(UC-[0-9]+[a-z]?)`)

// classify joins observed test events with the registry. Pure: no I/O, golden-
// tested in gen_test.go. forceInconclusive marks every implemented row
// inconclusive (used when provisioning reported a spot reclaim mid-run).
func classify(events []testEvent, reg []harness.UseCase, forceInconclusive bool) []Result {
	// First pass: per test name, collect (a) every UC id it claims via the
	// `ucid=...` markers harness.Require logs — a parent fanning out into
	// subtests claims several — and (b) its non-boilerplate output lines, which
	// carry the skip/fail reason. Flat-named tests (TestSnapshotCreate) surface
	// the id only through the marker, not the test name.
	testToUC := map[string][]string{}
	testOut := map[string][]string{}
	for _, ev := range events {
		if ev.Action != "output" || ev.Test == "" {
			continue
		}
		if m := ucMarkerRE.FindStringSubmatch(ev.Output); m != nil {
			testToUC[ev.Test] = appendUnique(testToUC[ev.Test], m[1])
			continue // the marker line itself is not a reason
		}
		if line := meaningfulLine(ev.Output); line != "" {
			testOut[ev.Test] = append(testOut[ev.Test], line)
		}
	}

	// Last terminal action per UC id (pass/fail/skip), with the reason captured
	// from the same test's output. A UC can surface via the test name (golden
	// TestX/UC-NN form) or the logged marker(s). fail wins over pass/skip.
	type outcome struct {
		st     Status
		reason string
	}
	got := map[string]outcome{}
	for _, ev := range events {
		switch ev.Action {
		case "pass", "fail", "skip":
		default:
			continue
		}
		var ids []string
		if id := ucRE.FindString(ev.Test); id != "" {
			ids = []string{id}
		} else {
			ids = testToUC[ev.Test]
		}
		st := Status(ev.Action) // "pass"|"fail"|"skip" line up with Status values
		reason := reasonFor(st, testOut[ev.Test])
		for _, id := range ids {
			if prev, ok := got[id]; ok && prev.st == StatusFail {
				continue // fail is sticky
			}
			got[id] = outcome{st: st, reason: reason}
		}
	}

	results := make([]Result, 0, len(reg))
	for _, uc := range reg {
		r := Result{ID: uc.ID, Title: uc.Title}
		switch {
		case !uc.Implemented:
			r.Status = StatusPending
		case forceInconclusive:
			r.Status = StatusInconclusive
		default:
			if o, ok := got[uc.ID]; ok {
				r.Status = o.st
				r.Reason = o.reason
			} else {
				// Implemented but produced no terminal event — surface as
				// missing (counts against the run) rather than silently green.
				r.Status = StatusMissing
				r.Reason = "implemented but no test event observed (test never ran or crashed before reporting)"
			}
		}
		results = append(results, r)
	}
	return results
}

// appendUnique adds id to ids if not already present (markers can repeat).
func appendUnique(ids []string, id string) []string {
	if slices.Contains(ids, id) {
		return ids
	}
	return append(ids, id)
}

// meaningfulLine trims a raw output line and drops go-test boilerplate
// (=== RUN, --- PASS/FAIL/SKIP, bare PASS/FAIL/ok) so only assertion/skip
// messages remain as candidate reasons.
func meaningfulLine(raw string) string {
	s := strings.TrimSpace(raw)
	switch {
	case s == "", s == "PASS", s == "FAIL":
		return ""
	case strings.HasPrefix(s, "=== "), strings.HasPrefix(s, "--- "), strings.HasPrefix(s, "ok "):
		return ""
	}
	return s
}

// reasonFor distills a one-line explanation for a non-pass status from a test's
// collected output. Skips surface the capability-gate message; fails surface
// the assertion text; passes need no reason.
func reasonFor(st Status, lines []string) string {
	switch st {
	case StatusSkip:
		for _, l := range lines {
			if strings.Contains(l, "lacks capabilities") || strings.Contains(strings.ToLower(l), "skip") {
				return l
			}
		}
		if len(lines) > 0 {
			return lines[len(lines)-1]
		}
	case StatusFail:
		if len(lines) > 0 {
			return strings.Join(lines, " | ")
		}
		return "failed (no output captured)"
	}
	return ""
}

func summarize(rs []Result) Summary {
	var s Summary
	for _, r := range rs {
		s.Total++
		switch r.Status {
		case StatusPass:
			s.Pass++
		case StatusFail:
			s.Fail++
		case StatusSkip:
			s.Skip++
		case StatusPending:
			s.Pending++
		case StatusInconclusive:
			s.Inconclusive++
		case StatusMissing:
			s.Missing++
		}
	}
	return s
}

func parseEvents(r io.Reader) ([]testEvent, error) {
	dec := json.NewDecoder(r)
	var events []testEvent
	for dec.More() {
		var ev testEvent
		if err := dec.Decode(&ev); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, nil
}

func icon(s Status) string {
	switch s {
	case StatusPass:
		return "✅"
	case StatusFail, StatusMissing:
		return "❌"
	case StatusSkip:
		return "⚪"
	case StatusPending:
		return "🟡"
	case StatusInconclusive:
		return "🟤"
	}
	return "?"
}

// mdCell makes a reason safe for a markdown table cell: escape pipes (column
// separators), collapse newlines, and cap the length so one verbose failure
// doesn't blow out the table. The full text is always in the JSON report.
func mdCell(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	const max = 200
	if len(s) > max {
		s = s[:max-1] + "…"
	}
	return s
}

func renderMarkdown(rep Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Integration report — %s\n\n", rep.Scenario)
	s := rep.Summary
	fmt.Fprintf(&b, "pass %d · fail %d · skip %d · pending %d · inconclusive %d · missing %d · total %d\n\n",
		s.Pass, s.Fail, s.Skip, s.Pending, s.Inconclusive, s.Missing, s.Total)
	b.WriteString("| UC | Title | Status | Detail |\n|----|-------|--------|--------|\n")
	for _, r := range rep.Results {
		fmt.Fprintf(&b, "| %s | %s | %s %s | %s |\n",
			r.ID, r.Title, icon(r.Status), r.Status, mdCell(r.Reason))
	}
	return b.String()
}

func main() {
	var (
		scenario      = flag.String("scenario", "", "scenario name (required)")
		out           = flag.String("out", "reports", "output directory")
		inconclusive  = flag.Bool("inconclusive", false, "mark all implemented UCs inconclusive (spot reclaim)")
		jsonInputPath = flag.String("json", "", "path to go test -json output; empty reads stdin")
	)
	flag.Parse()
	if *scenario == "" {
		fmt.Fprintln(os.Stderr, "error: -scenario is required")
		os.Exit(2)
	}

	var in io.Reader = os.Stdin
	if *jsonInputPath != "" {
		f, err := os.Open(*jsonInputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open json: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		in = f
	}

	events, err := parseEvents(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse events: %v\n", err)
		os.Exit(1)
	}

	results := classify(events, harness.Registry, *inconclusive)
	rep := Report{Scenario: *scenario, Results: results, Summary: summarize(results)}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	jsonPath := filepath.Join(*out, *scenario+".json")
	mdPath := filepath.Join(*out, *scenario+".md")
	jb, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(jsonPath, jb, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write json: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(mdPath, []byte(renderMarkdown(rep)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write md: %v\n", err)
		os.Exit(1)
	}

	if err := writeIndex(*out); err != nil {
		fmt.Fprintf(os.Stderr, "write index: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("wrote %s and %s (pass %d/%d, fail %d, pending %d)\n",
		jsonPath, mdPath, rep.Summary.Pass, rep.Summary.Total, rep.Summary.Fail, rep.Summary.Pending)

	// Exit non-zero if anything actually failed (fail or missing). Inconclusive
	// and pending do NOT fail the gate — they're "not run", not "broken".
	if rep.Summary.Fail > 0 || rep.Summary.Missing > 0 {
		os.Exit(1)
	}
}

// writeIndex rebuilds reports/index.md as the UC×scenario matrix from every
// <scenario>.json present in the output dir, so `run.sh all` accumulates one
// grid regardless of run order.
func writeIndex(dir string) error {
	entries, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	sort.Strings(entries)

	scenarios := make([]string, 0, len(entries))
	cell := map[string]map[string]Status{} // ucID -> scenario -> status
	for _, e := range entries {
		raw, err := os.ReadFile(e)
		if err != nil {
			return err
		}
		var rep Report
		if err := json.Unmarshal(raw, &rep); err != nil {
			return err
		}
		scenarios = append(scenarios, rep.Scenario)
		for _, r := range rep.Results {
			if cell[r.ID] == nil {
				cell[r.ID] = map[string]Status{}
			}
			cell[r.ID][rep.Scenario] = r.Status
		}
	}

	var b strings.Builder
	b.WriteString("# Integration coverage matrix\n\n")
	b.WriteString("Legend: ✅ pass · ❌ fail · ⚪ skip(n/a) · 🟡 pending · 🟤 inconclusive\n\n")
	b.WriteString("| UC | Title |")
	for _, s := range scenarios {
		fmt.Fprintf(&b, " %s |", s)
	}
	b.WriteString("\n|----|-------|")
	for range scenarios {
		b.WriteString("------|")
	}
	b.WriteString("\n")
	for _, uc := range harness.Registry {
		fmt.Fprintf(&b, "| %s | %s |", uc.ID, uc.Title)
		for _, s := range scenarios {
			st, ok := cell[uc.ID][s]
			if !ok {
				b.WriteString("  |")
				continue
			}
			fmt.Fprintf(&b, " %s |", icon(st))
		}
		b.WriteString("\n")
	}
	return os.WriteFile(filepath.Join(dir, "index.md"), []byte(b.String()), 0o644)
}
