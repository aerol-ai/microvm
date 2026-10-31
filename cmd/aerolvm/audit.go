package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/auditwitness"
)

// exitIncomplete is "audit verify" found no contradiction but could not
// check every head: some are newer than the evidence and have waited longer
// than --max-lag. Not 2, which every verb uses for a usage error.
const exitIncomplete = 3

// auditVerifyDefaultMaxLag is how long a head may wait for its records to be
// exported before the result is INCOMPLETE. The exporter flushes every
// second, so anything near this means the export has stopped.
const auditVerifyDefaultMaxLag = 15 * time.Minute

func runAudit(ctx context.Context, a *app, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, auditHelp)
		return exitUsage
	}
	switch args[0] {
	case "verify":
		return runAuditVerify(ctx, a, args[1:])
	case "search":
		return runAuditSearch(ctx, a, args[1:])
	default:
		return a.usageError(nil, "audit", "unknown audit command %q (want verify or search)", args[0])
	}
}

// auditVerifyOptions are the parsed flags.
type auditVerifyOptions struct {
	witness   s3Location
	export    *s3Location
	exportDir string
	local     map[string]string
	nodes     []string
	since     time.Time
	maxLag    time.Duration
	s3        auditexport.S3Config
	// fetchConcurrency is how many export batches one node's walk
	// downloads from S3 at once.
	fetchConcurrency int
}

type s3Location struct{ bucket, prefix string }

func parseS3URL(flagName, raw string) (s3Location, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "s3" || u.Host == "" {
		return s3Location{}, fmt.Errorf("--%s must be s3://<bucket>[/<prefix>], got %q", flagName, raw)
	}
	return s3Location{bucket: u.Host, prefix: strings.Trim(u.Path, "/")}, nil
}

// parseSince accepts an RFC3339 time, a Go duration ("720h") or whole days
// ("30d"), the last two counted back from now. The window is the auditor's
// to choose, so there is no default (D22).
func parseSince(raw string, now time.Time) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	if days, ok := strings.CutSuffix(raw, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n > 0 {
			return now.AddDate(0, 0, -n), nil
		}
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("--since must be an RFC3339 time, a duration such as 720h, or days such as 30d, got %q", raw)
}

func runAuditVerify(ctx context.Context, a *app, args []string) int {
	const verbName = "audit verify"
	fs, c := a.newFlagSet(verbName)
	var (
		witnessURL, exportURL, exportDir, sinceRaw string
		region, endpoint                           string
		pathStyle                                  bool
		maxLag                                     = auditVerifyDefaultMaxLag
		fetch                                      = auditFetchDefaultConcurrency
		locals, nodes                              stringList
	)
	fs.StringVar(&witnessURL, "witness", "", "")
	fs.StringVar(&exportURL, "export", "", "")
	fs.StringVar(&exportDir, "export-dir", "", "")
	fs.StringVar(&sinceRaw, "since", "", "")
	fs.DurationVar(&maxLag, "max-lag", maxLag, "")
	fs.IntVar(&fetch, "fetch-concurrency", fetch, "")
	fs.Var(&locals, "local", "")
	fs.Var(&nodes, "node", "")
	fs.StringVar(&region, "region", "", "")
	fs.StringVar(&endpoint, "endpoint", "", "")
	fs.BoolVar(&pathStyle, "path-style", false, "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, verbName, err)
	}
	if len(pos) > 0 {
		return a.usageError(c, verbName, "unexpected argument %q", pos[0])
	}
	now := time.Now().UTC()
	opts := auditVerifyOptions{nodes: nodes, maxLag: maxLag, exportDir: exportDir, fetchConcurrency: fetch}
	switch {
	case witnessURL == "":
		return a.usageError(c, verbName, "--witness is required")
	case sinceRaw == "":
		return a.usageError(c, verbName, "--since is required: the window to check is yours to choose, and an attacker who deletes old evidence must not choose it for you")
	case (exportURL == "") == (exportDir == ""):
		return a.usageError(c, verbName, "give exactly one of --export or --export-dir")
	case maxLag < 0:
		return a.usageError(c, verbName, "--max-lag must not be negative")
	case badFetchConcurrency(fetch):
		return a.usageError(c, verbName, "%s", fetchConcurrencyUsage)
	}
	if opts.witness, err = parseS3URL("witness", witnessURL); err != nil {
		return a.usageError(c, verbName, "%v", err)
	}
	if exportURL != "" {
		loc, err := parseS3URL("export", exportURL)
		if err != nil {
			return a.usageError(c, verbName, "%v", err)
		}
		opts.export = &loc
	}
	if opts.since, err = parseSince(sinceRaw, now); err != nil {
		return a.usageError(c, verbName, "%v", err)
	}
	if opts.local, err = parseLocals(locals, nodes); err != nil {
		return a.usageError(c, verbName, "%v", err)
	}
	opts.s3 = auditexport.S3Config{Region: region, Endpoint: endpoint, PathStyle: pathStyle}

	ctx, received, stop := a.notifySignals(ctx)
	defer stop()
	report, err := verifyAudit(ctx, opts, now)
	if err != nil {
		return a.fail(c, err, auditErrorExit(received))
	}
	if c.json {
		a.printJSON(report)
	} else {
		printAuditReport(a.stdout, report)
	}
	switch report.Result {
	case auditlog.ResultPass:
		return exitOK
	case auditlog.ResultIncomplete:
		return exitIncomplete
	default:
		return exitError
	}
}

// fetchConcurrencyUsage is the usage error for a --fetch-concurrency out of
// range, shared by every verb that reads the export.
var fetchConcurrencyUsage = fmt.Sprintf("--fetch-concurrency must be between 1 and %d", auditFetchMaxConcurrency)

func badFetchConcurrency(n int) bool { return n < 1 || n > auditFetchMaxConcurrency }

// auditErrorExit is the exit code for a walk that ended in an error: 128+n
// when Ctrl-C (or SIGTERM) stopped it, so a script can tell an interrupted
// check from a failed one. Either way the spool is gone by then: the walk
// cancels its downloads and removes their files on the way out.
func auditErrorExit(received func() os.Signal) int {
	if sig := received(); sig != nil {
		return signalExit(sig)
	}
	return exitError
}

// parseLocals reads --local node=path (or a bare path when exactly one
// --node is given).
func parseLocals(raw, nodes []string) (map[string]string, error) {
	out := map[string]string{}
	for _, l := range raw {
		id, p, ok := strings.Cut(l, "=")
		if !ok {
			if len(nodes) != 1 {
				return nil, fmt.Errorf("--local %q names no node: write --local <node-id>=<path>, or give exactly one --node", l)
			}
			id, p = nodes[0], l
		}
		if id == "" || p == "" {
			return nil, fmt.Errorf("--local %q needs a node id and a path", l)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("--local names node %q twice", id)
		}
		out[id] = p
	}
	return out, nil
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// auditReport is the whole verdict: the worst node result wins.
type auditReport struct {
	Result      auditlog.Result       `json:"result"`
	WindowStart time.Time             `json:"window_start"`
	CheckedAt   time.Time             `json:"checked_at"`
	Nodes       []auditlog.NodeReport `json:"nodes"`
}

func verifyAudit(ctx context.Context, opts auditVerifyOptions, now time.Time) (auditReport, error) {
	report := auditReport{Result: auditlog.ResultPass, WindowStart: opts.since.UTC(), CheckedAt: now}
	wcfg := opts.s3
	wcfg.Bucket, wcfg.Prefix = opts.witness.bucket, opts.witness.prefix
	reader, err := auditwitness.NewReader(ctx, wcfg)
	if err != nil {
		return report, err
	}
	var export exportFactory
	if opts.export != nil {
		ecfg := opts.s3
		ecfg.Bucket, ecfg.Prefix = opts.export.bucket, opts.export.prefix
		client, err := auditexport.NewS3Client(ctx, ecfg)
		if err != nil {
			return report, err
		}
		export = func() (auditlog.ExportSource, func(), error) {
			return newS3Export(client, opts.export.bucket, opts.export.prefix, now, opts.fetchConcurrency)
		}
	} else {
		export = func() (auditlog.ExportSource, func(), error) {
			return dirExport{root: opts.exportDir, now: now}, func() {}, nil
		}
	}
	nodes := opts.nodes
	if len(nodes) == 0 {
		if nodes, err = reader.Nodes(ctx); err != nil {
			return report, err
		}
		if len(nodes) == 0 {
			return report, fmt.Errorf("the witness at s3://%s/%s holds no node heads", opts.witness.bucket, opts.witness.prefix)
		}
	}
	for id := range opts.local {
		if !contains(nodes, id) {
			return report, fmt.Errorf("--local names node %q, which is not being verified", id)
		}
	}
	for _, id := range nodes {
		rep, err := verifyAuditNode(ctx, reader, export, opts, id, now)
		if err != nil {
			return report, fmt.Errorf("node %s: %w", id, err)
		}
		report.Nodes = append(report.Nodes, rep)
		report.Result = worse(report.Result, rep.Result)
	}
	return report, nil
}

type exportFactory func() (auditlog.ExportSource, func(), error)

func verifyAuditNode(ctx context.Context, reader *auditwitness.Reader, export exportFactory, opts auditVerifyOptions, nodeID string, now time.Time) (auditlog.NodeReport, error) {
	in, done, err := auditNodeInput(ctx, reader, export, opts, nodeID, now)
	if err != nil {
		return auditlog.NodeReport{}, err
	}
	defer done()
	return auditlog.VerifyNode(ctx, in)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func worse(a, b auditlog.Result) auditlog.Result {
	rank := map[auditlog.Result]int{auditlog.ResultPass: 0, auditlog.ResultIncomplete: 1, auditlog.ResultFail: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func printAuditReport(w io.Writer, r auditReport) {
	fmt.Fprintf(w, "%s  window from %s\n", r.Result, r.WindowStart.Format(time.RFC3339))
	for _, n := range r.Nodes {
		fmt.Fprintf(w, "\n%s  node %s: %d of %d heads in the window linked", n.Result, n.NodeID, n.HeadsLinked, n.HeadsInWindow)
		if n.HeadsBeforeWindow > 0 {
			fmt.Fprintf(w, ", %d before the window not checked", n.HeadsBeforeWindow)
		}
		fmt.Fprintln(w)
		if n.EvidenceFrom != nil && n.EvidenceTo != nil {
			fmt.Fprintf(w, "  evidence: %d records from %s to %s, %d export batches", n.RecordsChecked, n.EvidenceFrom.Format(time.RFC3339), n.EvidenceTo.Format(time.RFC3339), n.ExportBatches)
			if n.UnreachedBatches > 0 {
				fmt.Fprintf(w, " (%d re-sent or overlapping)", n.UnreachedBatches)
			}
			fmt.Fprintln(w)
		}
		for _, p := range n.Pending {
			state := "waiting for its records"
			if p.Stale {
				state = "waiting longer than --max-lag"
			}
			fmt.Fprintf(w, "  pending: head %.16s witnessed %s, %s\n", p.HeadHex, p.At.Format(time.RFC3339), state)
		}
		for _, p := range n.Problems {
			fmt.Fprintf(w, "  FAIL: %s\n", p)
		}
		for _, warn := range n.Warnings {
			fmt.Fprintf(w, "  note: %s\n", warn)
		}
	}
}

// dirExport reads batches saved from a webhook or bus receiver, laid out
// the way the S3 exporter writes them: <root>/node=<id>/YYYY/MM/DD/*.jsonl.
type dirExport struct {
	root string
	now  time.Time
}

func (d dirExport) Days(_ context.Context, _, from string) ([]string, error) {
	return calendarDays(from, d.now)
}

func (d dirExport) dayDir(nodeID, day string) (string, error) {
	t, err := time.Parse("2006-01-02", day)
	if err != nil {
		return "", err
	}
	return filepath.Join(d.root, filepath.FromSlash(auditexport.DayPrefix("", nodeID, t))), nil
}

func (d dirExport) Batches(_ context.Context, nodeID, day string) ([]string, error) {
	dir, err := d.dayDir(nodeID, day)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func (d dirExport) Open(_ context.Context, nodeID, day, name string) (io.ReadCloser, error) {
	dir, err := d.dayDir(nodeID, day)
	if err != nil {
		return nil, err
	}
	return os.Open(filepath.Join(dir, path.Base(name)))
}

// calendarDays lists every UTC date from from through now.
func calendarDays(from string, now time.Time) ([]string, error) {
	t, err := time.Parse("2006-01-02", from)
	if err != nil {
		return nil, err
	}
	last := now.UTC().Format("2006-01-02")
	var days []string
	for d := t; d.Format("2006-01-02") <= last; d = d.AddDate(0, 0, 1) {
		days = append(days, d.Format("2006-01-02"))
	}
	return days, nil
}
