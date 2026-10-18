package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/auditwitness"
)

// `aerolvm audit search` answers "what did Ana do this week" from the audit
// export (plans/identity-and-access.md §5.10). It walks each node's records
// with the same reader `audit verify` uses, so every match it prints has
// been proven to link into its node's chain, and the verdict at the end
// says whether that history held up. A live fleet-wide query would fan out
// to every node; that is the SIEM's job, and the export already feeds it.

// auditSearchDefaultLimit bounds the matches printed. The walk always runs
// to the end, because the verdict needs every record.
const auditSearchDefaultLimit = 1000

type auditSearchOptions struct {
	auditVerifyOptions
	// hasWitness is false without --witness: the chain is still checked
	// record by record, but no witnessed head is.
	hasWitness bool
	filter     auditlog.SearchFilter
	limit      int
}

// auditSearchMatch is one printed record and the node whose log holds it.
type auditSearchMatch struct {
	NodeID string         `json:"node_id"`
	Record auditlog.Event `json:"record"`
}

// auditSearchReport is the --json output.
type auditSearchReport struct {
	Result      auditlog.Result       `json:"result"`
	WindowStart time.Time             `json:"window_start"`
	CheckedAt   time.Time             `json:"checked_at"`
	Witnessed   bool                  `json:"witnessed"`
	Matched     int                   `json:"matched"`
	Matches     []auditSearchMatch    `json:"matches"`
	Nodes       []auditlog.NodeReport `json:"nodes"`
}

func runAuditSearch(ctx context.Context, a *app, args []string) int {
	const verbName = "audit search"
	fs, c := a.newFlagSet(verbName)
	var (
		witnessURL, exportURL, exportDir, sinceRaw, untilRaw string
		region, endpoint                                     string
		pathStyle                                            bool
		maxLag                                               = auditVerifyDefaultMaxLag
		limit                                                = auditSearchDefaultLimit
		locals, nodes                                        stringList
		filter                                               auditlog.SearchFilter
	)
	fs.StringVar(&witnessURL, "witness", "", "")
	fs.StringVar(&exportURL, "export", "", "")
	fs.StringVar(&exportDir, "export-dir", "", "")
	fs.StringVar(&sinceRaw, "since", "", "")
	fs.StringVar(&untilRaw, "until", "", "")
	fs.StringVar(&filter.Caller, "caller", "", "")
	fs.StringVar(&filter.Kind, "kind", "", "")
	fs.StringVar(&filter.SandboxID, "sandbox", "", "")
	fs.StringVar(&filter.Result, "result", "", "")
	fs.IntVar(&limit, "limit", limit, "")
	fs.DurationVar(&maxLag, "max-lag", maxLag, "")
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
	opts := auditSearchOptions{auditVerifyOptions: auditVerifyOptions{nodes: nodes, maxLag: maxLag, exportDir: exportDir}, limit: limit}
	switch {
	case sinceRaw == "":
		return a.usageError(c, verbName, "--since is required: the window to search is yours to choose")
	case (exportURL == "") == (exportDir == ""):
		return a.usageError(c, verbName, "give exactly one of --export or --export-dir")
	case maxLag < 0:
		return a.usageError(c, verbName, "--max-lag must not be negative")
	case limit < 0:
		return a.usageError(c, verbName, "--limit must not be negative (0 prints every match)")
	}
	if witnessURL != "" {
		if opts.witness, err = parseS3URL("witness", witnessURL); err != nil {
			return a.usageError(c, verbName, "%v", err)
		}
		opts.hasWitness = true
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
	filter.Since = opts.since
	if untilRaw != "" {
		if filter.Until, err = parseUntil(untilRaw, now); err != nil {
			return a.usageError(c, verbName, "%v", err)
		}
		if !filter.Until.After(filter.Since) {
			return a.usageError(c, verbName, "--until must be after --since")
		}
	}
	opts.filter = filter
	if opts.local, err = parseLocals(locals, nodes); err != nil {
		return a.usageError(c, verbName, "%v", err)
	}
	opts.s3 = auditexport.S3Config{Region: region, Endpoint: endpoint, PathStyle: pathStyle}

	var out io.Writer = a.stdout
	if c.json {
		out = nil
	}
	report, err := searchAudit(ctx, opts, now, out)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(report)
	} else {
		printAuditSearchSummary(a.stdout, report, opts.limit)
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

// parseUntil accepts what parseSince accepts; a duration or days count back
// from now.
func parseUntil(raw string, now time.Time) (time.Time, error) {
	t, err := parseSince(raw, now)
	if err != nil {
		return time.Time{}, errors.New(strings.Replace(err.Error(), "--since", "--until", 1))
	}
	return t, nil
}

// searchAudit walks every selected node. Matches stream to out as they are
// found (text mode); with out nil they are collected for the JSON report.
// Either way at most opts.limit are kept or printed (0: all).
func searchAudit(ctx context.Context, opts auditSearchOptions, now time.Time, out io.Writer) (auditSearchReport, error) {
	report := auditSearchReport{Result: auditlog.ResultPass, WindowStart: opts.since.UTC(), CheckedAt: now, Witnessed: opts.hasWitness, Matches: []auditSearchMatch{}}
	var reader *auditwitness.Reader
	if opts.hasWitness {
		wcfg := opts.s3
		wcfg.Bucket, wcfg.Prefix = opts.witness.bucket, opts.witness.prefix
		var err error
		if reader, err = auditwitness.NewReader(ctx, wcfg); err != nil {
			return report, err
		}
	}
	export, lister, err := searchExport(ctx, opts.auditVerifyOptions, now)
	if err != nil {
		return report, err
	}
	nodes := opts.nodes
	if len(nodes) == 0 {
		if reader != nil {
			nodes, err = reader.Nodes(ctx)
		} else {
			nodes, err = lister(ctx)
		}
		if err != nil {
			return report, err
		}
		if len(nodes) == 0 {
			return report, errors.New("no nodes found: name them with --node, or check the export location")
		}
	}
	for id := range opts.local {
		if !contains(nodes, id) {
			return report, fmt.Errorf("--local names node %q, which is not being searched", id)
		}
	}
	for _, id := range nodes {
		in, done, err := auditNodeInput(ctx, reader, export, opts.auditVerifyOptions, id, now)
		if err != nil {
			return report, fmt.Errorf("node %s: %w", id, err)
		}
		rep, err := auditlog.SearchNode(ctx, in, opts.filter, func(ev auditlog.Event) {
			report.Matched++
			if opts.limit > 0 && report.Matched > opts.limit {
				return
			}
			if out != nil {
				fmt.Fprintln(out, formatAuditRecord(id, ev))
				return
			}
			report.Matches = append(report.Matches, auditSearchMatch{NodeID: id, Record: ev})
		})
		done()
		if err != nil {
			return report, fmt.Errorf("node %s: %w", id, err)
		}
		report.Nodes = append(report.Nodes, rep)
		report.Result = worse(report.Result, rep.Result)
	}
	return report, nil
}

// auditNodeInput is what the shared reader needs for one node: its
// witnessed heads (none without a witness), the export, and a local log
// copy when one was given. done releases what it opened.
func auditNodeInput(ctx context.Context, reader *auditwitness.Reader, export exportFactory, opts auditVerifyOptions, nodeID string, now time.Time) (auditlog.NodeInput, func(), error) {
	in := auditlog.NodeInput{NodeID: nodeID, Since: opts.since, Now: now, MaxLag: opts.maxLag, NoWitness: reader == nil}
	if reader != nil {
		hist, err := reader.History(ctx, nodeID, opts.since)
		if err != nil {
			return in, func() {}, err
		}
		in.HiddenKeys, in.NewestWitnessDay = hist.HiddenKeys, hist.NewestDay
		for _, h := range hist.Heads {
			in.Heads = append(in.Heads, auditlog.WitnessedHead{HeadHex: h.HeadHex, At: h.LastModified, Ref: h.Key + "@" + h.VersionID})
		}
		if p := hist.Prior; p != nil {
			in.Prior = &auditlog.WitnessedHead{HeadHex: p.HeadHex, At: p.LastModified, Ref: p.Key + "@" + p.VersionID}
		}
	}
	src, release, err := export()
	if err != nil {
		return in, func() {}, err
	}
	in.Export = src
	done := release
	if p, ok := opts.local[nodeID]; ok {
		f, err := os.Open(p)
		if err != nil {
			release()
			return in, func() {}, fmt.Errorf("open the local log: %w", err)
		}
		in.Local = f
		done = func() { _ = f.Close(); release() }
	}
	return in, done, nil
}

// searchExport builds the export reader and, for a search without a
// witness, the lister that finds the nodes the export holds.
func searchExport(ctx context.Context, opts auditVerifyOptions, now time.Time) (exportFactory, func(context.Context) ([]string, error), error) {
	if opts.export == nil {
		dir := dirExport{root: opts.exportDir, now: now}
		return func() (auditlog.ExportSource, func(), error) { return dir, func() {}, nil }, dir.nodes, nil
	}
	ecfg := opts.s3
	ecfg.Bucket, ecfg.Prefix = opts.export.bucket, opts.export.prefix
	client, err := auditexport.NewS3Client(ctx, ecfg)
	if err != nil {
		return nil, nil, err
	}
	factory := func() (auditlog.ExportSource, func(), error) {
		return newS3Export(client, opts.export.bucket, opts.export.prefix, now)
	}
	lister := func(ctx context.Context) ([]string, error) {
		return s3ExportNodes(ctx, client, opts.export.bucket, opts.export.prefix)
	}
	return factory, lister, nil
}

// nodes lists the node=<id> directories under the export root.
func (d dirExport) nodes(context.Context) ([]string, error) {
	entries, err := os.ReadDir(d.root)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if id, ok := strings.CutPrefix(e.Name(), "node="); ok && e.IsDir() && id != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// s3ExportNodes lists the node=<id>/ prefixes under an S3 export.
func s3ExportNodes(ctx context.Context, api *s3.Client, bucket, prefix string) ([]string, error) {
	base := strings.Trim(prefix, "/")
	if base != "" {
		base += "/"
	}
	in := &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(base + "node="), Delimiter: aws.String("/")}
	var ids []string
	for {
		out, err := api.ListObjectsV2(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("list s3://%s/%s: %w", bucket, base, err)
		}
		for _, p := range out.CommonPrefixes {
			id := strings.TrimSuffix(strings.TrimPrefix(aws.ToString(p.Prefix), base+"node="), "/")
			if id != "" {
				ids = append(ids, id)
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		in.ContinuationToken = out.NextContinuationToken
	}
	sort.Strings(ids)
	return ids, nil
}

// formatAuditRecord is one match as a line: when, where, what, who, then
// the call. Fields that are empty are left out.
func formatAuditRecord(nodeID string, ev auditlog.Event) string {
	parts := []string{ev.Time.UTC().Format(time.RFC3339Nano), nodeID, orDash(ev.Kind), orDash(ev.Result)}
	if c := ev.Caller; c != nil {
		who := "caller=" + c.ID
		if c.Name != "" {
			who += " (" + c.Name + ")"
		}
		parts = append(parts, who)
		if c.Team != "" {
			parts = append(parts, "team="+c.Team)
		}
		if c.Via != "" {
			parts = append(parts, "via="+c.Via)
		}
	}
	if ev.Ref != "" {
		parts = append(parts, strconv.Quote(ev.Ref))
	}
	if ev.SandboxID != "" {
		parts = append(parts, "sandbox="+ev.SandboxID)
	}
	if ev.Reason != "" && ev.Reason != "ok" {
		parts = append(parts, "reason="+ev.Reason)
	}
	if ev.Dropped > 0 {
		parts = append(parts, "dropped="+strconv.FormatInt(ev.Dropped, 10))
	}
	if r := ev.Request; r != nil {
		if r.Status != 0 {
			parts = append(parts, "status="+strconv.Itoa(r.Status))
		}
		if r.Target != "" {
			parts = append(parts, "target="+r.Target)
		}
		if r.Surface != "" {
			parts = append(parts, "surface="+r.Surface)
		}
		if r.Count > 1 {
			parts = append(parts, "count="+strconv.FormatInt(r.Count, 10))
		}
		if r.Digest != "" {
			parts = append(parts, "digest="+r.Digest)
		}
		if len(r.Argv) > 0 {
			parts = append(parts, "argv="+strconv.Quote(strings.Join(r.Argv, " ")))
		}
		if len(r.Routes) > 0 {
			parts = append(parts, "routes="+strconv.Quote(strings.Join(r.Routes, ", ")))
		}
		if r.Source != "" {
			parts = append(parts, "source="+r.Source)
		}
		if g := r.Grant; g != nil {
			parts = append(parts, "grant_role="+g.Role, "grant_team="+g.Team)
		}
	}
	if ev.CorrelationID != "" {
		parts = append(parts, "correlation_id="+ev.CorrelationID)
	}
	return strings.Join(parts, "  ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// printAuditSearchSummary ends a text search with the count and each
// node's verdict, in the same words `audit verify` uses.
func printAuditSearchSummary(w io.Writer, r auditSearchReport, limit int) {
	shown := r.Matched
	if limit > 0 && shown > limit {
		shown = limit
	}
	if shown < r.Matched {
		fmt.Fprintf(w, "\n%d records matched; the first %d are shown (raise --limit, or 0 for all)\n", r.Matched, shown)
	} else {
		fmt.Fprintf(w, "\n%d records matched\n", r.Matched)
	}
	if !r.Witnessed {
		fmt.Fprintln(w, "no --witness: each record was checked to link to the one before it, but not against witnessed heads")
	}
	printAuditReport(w, auditReport{Result: r.Result, WindowStart: r.WindowStart, CheckedAt: r.CheckedAt, Nodes: r.Nodes})
}
