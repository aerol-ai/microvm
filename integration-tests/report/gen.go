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
	"bufio"
	"bytes"
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
	// Invariants are the cluster-correctness verdicts (I1..I8) the use case's
	// test recorded with harness.TrackInvariants, one per invariant it checks.
	// A pass row carries them too: "held, over 61 samples" is the evidence
	// that the case injected its fault, which a bare pass does not show.
	Invariants []harness.InvariantResult `json:"invariants,omitempty"`
	// Detail is what the case measured (harness.ReportDetail), whatever its
	// verdict: UC-171's latency is read across the passing flag-on runs and
	// the failing flag-off runs of the routing A/B alike.
	Detail string `json:"detail,omitempty"`
}

// Report is the serialized per-scenario artifact.
type Report struct {
	Scenario string   `json:"scenario"`
	Build    *Build   `json:"build,omitempty"`
	Results  []Result `json:"results"`
	Summary  Summary  `json:"summary"`
}

// Build records WHICH TREE produced the artifacts the scenario ran against.
//
// Without it a reports/*.json is unattributable: once the harness can provision
// from a locally cross-compiled branch (plans/integration-test-security.md §4),
// "pass 57/fail 0" no longer implies a released version, and a latency number
// compared against the wrong arm is worse than no number. Dirty is the field
// that matters most — it means the numbers came from a tree that exists on
// exactly one laptop and cannot be reproduced from git.
//
// Populated from the environment because gen runs after teardown, in a separate
// process from the build, and has no other channel. Nil when the scenario used
// a published release, where the release tag already answers the question.
type Build struct {
	ID      string `json:"id,omitempty"`
	Mode    string `json:"mode,omitempty"` // local | released | version
	GitSHA  string `json:"git_sha,omitempty"`
	Dirty   bool   `json:"dirty,omitempty"`
	Version string `json:"version,omitempty"` // pinned release tag when mode=version
}

// buildFromEnv reads the AEROL_BUILD_* variables run.sh exports. Returns nil
// when none is set, so a released-artifact run serializes no build block at all
// rather than a misleading empty one.
func buildFromEnv() *Build {
	b := Build{
		ID:      os.Getenv("AEROL_BUILD_ID"),
		Mode:    os.Getenv("AEROL_BUILD_MODE"),
		GitSHA:  os.Getenv("AEROL_BUILD_GIT_SHA"),
		Dirty:   os.Getenv("AEROL_BUILD_DIRTY") == "true",
		Version: os.Getenv("AEROL_BUILD_VERSION"),
	}
	if b.ID == "" && b.Mode == "" && b.GitSHA == "" && b.Version == "" {
		return nil
	}
	return &b
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
	testInv := map[string][]harness.InvariantResult{}
	testDetail := map[string][]string{}
	for _, ev := range events {
		if ev.Action != "output" || ev.Test == "" {
			continue
		}
		if m := ucMarkerRE.FindStringSubmatch(ev.Output); m != nil {
			testToUC[ev.Test] = appendUnique(testToUC[ev.Test], m[1])
			continue // the marker line itself is not a reason
		}
		if inv, ok := harness.ParseInvariantMarker(ev.Output); ok {
			testInv[ev.Test] = append(testInv[ev.Test], inv)
			continue // nor is an invariant verdict; it has its own field
		}
		if d, ok := harness.ParseDetailMarker(ev.Output); ok {
			testDetail[ev.Test] = append(testDetail[ev.Test], d)
			continue // nor a measurement
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
		invs   []harness.InvariantResult
		detail string
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
			got[id] = outcome{st: st, reason: reason, invs: testInv[ev.Test], detail: strings.Join(testDetail[ev.Test], "; ")}
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
				r.Invariants = o.invs
				r.Detail = o.detail
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

// focusSkipReason is the reason a focused scenario gives the use cases it
// does not run. Exported in the JSON, so keep it stable.
const focusSkipReason = "not in this focused scenario (it runs only the %s use cases)"

// validateFocus refuses a focus capability that would turn the whole matrix
// into skips. An unknown or unused capability is required by no use case, so
// applyFocus would downgrade EVERY missing row, the focused cases included,
// and a scenario whose cases all crashed would report green.
func validateFocus(focus harness.Capability, reg []harness.UseCase) error {
	if !harness.KnownCapabilities[focus] {
		return fmt.Errorf("focus capability %q is not a known capability", focus)
	}
	for _, uc := range reg {
		if uc.Implemented && slices.Contains(uc.Requires, focus) {
			return nil
		}
	}
	return fmt.Errorf("no implemented use case requires the focus capability %q, so a focused run would test nothing", focus)
}

// applyFocus is classify's companion for a focused scenario (a caps file
// with a `focus:` block): the scenario runs only the tests claiming use
// cases that require focus, so a use case that does not require it and has
// no result is "not run here" (skip), not "crashed before reporting"
// (missing). A focused use case with no result stays missing: that is still
// a test that never reported, and the gate must stay red for it. Pure.
func applyFocus(results []Result, reg []harness.UseCase, focus harness.Capability) []Result {
	needsFocus := map[string]bool{}
	for _, uc := range reg {
		needsFocus[uc.ID] = slices.Contains(uc.Requires, focus)
	}
	out := make([]Result, len(results))
	for i, r := range results {
		if r.Status == StatusMissing && !needsFocus[r.ID] {
			r.Status = StatusSkip
			r.Reason = fmt.Sprintf(focusSkipReason, focus)
		}
		out[i] = r
	}
	return out
}

// invariantSummary is the short form of a row's invariant verdicts for the
// markdown cell ("I1 held · I7 violated"); the details are in the JSON.
func invariantSummary(invs []harness.InvariantResult) string {
	parts := make([]string, 0, len(invs))
	for _, inv := range invs {
		parts = append(parts, inv.ID+" "+inv.Result)
	}
	return strings.Join(parts, " · ")
}

// detailCell is a row's Detail column: its invariant verdicts first (they
// are the point of a chaos row, and the length cap must not cut them off),
// then what the case measured, then the reason.
func detailCell(r Result) string {
	var parts []string
	if inv := invariantSummary(r.Invariants); inv != "" {
		parts = append(parts, inv)
	}
	if r.Detail != "" {
		parts = append(parts, r.Detail)
	}
	if r.Reason != "" {
		parts = append(parts, r.Reason)
	}
	return strings.Join(parts, " — ")
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
	// `go test -json` is line-delimited JSON. Parse line-by-line and skip a
	// torn line rather than aborting the whole report: when a test writes to
	// os.Stdout concurrently with the test framework, the -json stream can
	// splice two records and corrupt one line. A streaming json.Decoder cannot
	// resync past that; a Scanner just drops the bad line and keeps going.
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024) // test output lines can be large
	var events []testEvent
	skipped := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			skipped++
			continue
		}
		var ev testEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			skipped++
			continue
		}
		events = append(events, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "parseEvents: skipped %d malformed line(s) in the go test -json stream\n", skipped)
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

// buildLabel is the one-line human form of a Build for the markdown header.
func buildLabel(b *Build) string {
	switch {
	case b.Version != "":
		return b.Mode + " " + b.Version
	case b.ID != "":
		return b.Mode + " " + b.ID
	default:
		return b.Mode
	}
}

func renderMarkdown(rep Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Integration report — %s\n\n", rep.Scenario)
	s := rep.Summary
	fmt.Fprintf(&b, "pass %d · fail %d · skip %d · pending %d · inconclusive %d · missing %d · total %d\n\n",
		s.Pass, s.Fail, s.Skip, s.Pending, s.Inconclusive, s.Missing, s.Total)
	if bi := rep.Build; bi != nil {
		fmt.Fprintf(&b, "build: `%s`", buildLabel(bi))
		if bi.Dirty {
			// Called out inline, not buried in the JSON: a dirty tree makes the
			// run irreproducible, and that has to be visible to whoever reads
			// the matrix rather than the artifact.
			b.WriteString(" **(dirty tree — not reproducible from git)**")
		}
		b.WriteString("\n\n")
	}
	b.WriteString("| UC | Title | Status | Detail |\n|----|-------|--------|--------|\n")
	for _, r := range rep.Results {
		fmt.Fprintf(&b, "| %s | %s | %s %s | %s |\n",
			r.ID, r.Title, icon(r.Status), r.Status, mdCell(detailCell(r)))
	}
	return b.String()
}

func main() {
	var (
		scenario      = flag.String("scenario", "", "scenario name (required)")
		out           = flag.String("out", "reports", "output directory")
		inconclusive  = flag.Bool("inconclusive", false, "mark all implemented UCs inconclusive (spot reclaim)")
		jsonInputPath = flag.String("json", "", "path to go test -json output; empty reads stdin")
		indexOnly     = flag.Bool("index-only", false, "rebuild reports/index.md from the existing *.json and exit")
		focusCap      = flag.String("focus-cap", "", "focused scenario: use cases that do not require this capability and have no result report as skip, not missing")
	)
	flag.Parse()

	// The matrix is built from whatever <scenario>.json files are present,
	// so pruning or renaming one has to be followed by a rebuild. Without
	// this the only way to refresh it is to re-run a scenario against live
	// AWS, which is an absurd price for correcting a file name.
	if *indexOnly {
		if err := writeIndex(*out); err != nil {
			fmt.Fprintf(os.Stderr, "write index: %v\n", err)
			os.Exit(1)
		}
		return
	}

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
	if *focusCap != "" {
		focus := harness.Capability(*focusCap)
		if err := validateFocus(focus, harness.Registry); err != nil {
			fmt.Fprintf(os.Stderr, "error: -focus-cap: %v\n", err)
			os.Exit(2)
		}
		results = applyFocus(results, harness.Registry, focus)
	}
	rep := Report{Scenario: *scenario, Build: buildFromEnv(), Results: results, Summary: summarize(results)}

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
	seen := map[string]bool{}
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
		// One column per SCENARIO, not per file. Bench and catalogue runs
		// write their own <scenario>-bench.json / -catalogue.json but record
		// the same rep.Scenario, and cell is keyed by that name — so every
		// extra file added an identical duplicate column. The matrix had
		// eight cluster-3-mixed-docker columns showing the same values,
		// which is the kind of unreadable that stops people reading it.
		if !seen[rep.Scenario] {
			seen[rep.Scenario] = true
			scenarios = append(scenarios, rep.Scenario)
		}
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
