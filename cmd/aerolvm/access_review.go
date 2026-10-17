package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/auditwitness"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// `aerolvm access review` is the quarterly access-review evidence a SOC 2
// auditor asks for (CC6.2/6.3; plans/identity-and-access.md §5.10, CEO
// review D7). It joins two inputs into one report:
//
//   - GET /v1/tokens (auditor or admin): every token sandboxd holds, with
//     its role, team, creator and expiry;
//   - the audit export, read by the walk `audit verify` and `audit search`
//     use: every principal the records name in the window, what each last
//     did and how many calls of each kind, the token creates (with the role
//     and team they handed out) and revokes, and the refused credentials.
//
// Every record the review counts has been proven to link into its node's
// chain. A tampered batch fails the whole review the way `audit verify`
// fails, and no report is printed: rows built from a history that does not
// hold up are not evidence. There is no server endpoint behind any of it.
//
// Memory holds one row per principal, token change and refusing source, plus
// at most accessReviewParallelNodes nodes' shares waiting to be merged; never
// the records, which stream through the walk.

// accessReviewExpiringWithin is how close an expiry must be to be flagged.
// Tokens nothing renews (a metrics scrape) have no other warning (D8).
const accessReviewExpiringWithin = 30 * 24 * time.Hour

// accessReviewParallelNodes bounds how many nodes are read at once. Each
// node's chain is independent; against S3 the walk waits on the network.
const accessReviewParallelNodes = 4

// accessReviewMaxSources bounds the refused-credential rows. A spray from
// many addresses writes one auth_denied record per address per minute; past
// the cap the rest fold into one row, so the report stays readable and its
// memory bounded.
const accessReviewMaxSources = 1000

// otherSources is the row the sources past accessReviewMaxSources fold into.
const otherSources = "(other sources)"

// The routes the review recognises in api records, as sandboxd's mux names
// them (pkg/api/v1/routes.go). They are repeated here because the CLI may
// not import a server package (deps_test.go).
const (
	tokensRoute    = "/v1/tokens"
	tokenItemRoute = "/v1/tokens/{id}"
)

// auditKindGap is the marker the daemon's writer leaves when its queue
// overflowed (internal/service's secretAuditKindGap): Dropped records were
// lost before they reached the chain.
const auditKindGap = "gap"

// Read-record settings the review infers per node from the records
// themselves: sandboxd reports SB_AUDIT_API_RECORDS nowhere else.
const (
	readRecordsAll       = "all"
	readRecordsMutations = "mutations"
	readRecordsNone      = "none"
	readRecordsMixed     = "mixed"
)

// reviewFlag marks a row the reviewer should look at. The names are part of
// the report format (the CSV flags column and the JSON), so a SIEM query can
// reproduce the report: change them only together with the docs.
type reviewFlag string

const (
	flagAdmin            reviewFlag = "admin"
	flagAdminGrant       reviewFlag = "admin_grant"
	flagExpired          reviewFlag = "expired"
	flagExpiring         reviewFlag = "expiring"
	flagRevoked          reviewFlag = "revoked"
	flagNotListed        reviewFlag = "not_listed"
	flagNoRecordedAction reviewFlag = "no_recorded_action"
	flagDenied           reviewFlag = "denied"
	flagRefused          reviewFlag = "refused"
	flagRateLimited      reviewFlag = "rate_limited"
)

// flagOrder is the order findings are listed in: who holds the most power
// first, then access that should already be gone, then activity.
var flagOrder = []reviewFlag{flagAdmin, flagAdminGrant, flagExpired, flagExpiring, flagRevoked, flagNotListed, flagNoRecordedAction, flagDenied, flagRefused, flagRateLimited}

// Token change kinds.
const (
	changeCreated = "created"
	changeRevoked = "revoked"
)

// accessReview is the whole report; the Markdown, the CSV and the JSON are
// three renderings of it.
type accessReview struct {
	Result      auditlog.Result `json:"result"`
	WindowStart time.Time       `json:"window_start"`
	GeneratedAt time.Time       `json:"generated_at"`
	Witnessed   bool            `json:"witnessed"`
	// ReadRecords is what the records show of SB_AUDIT_API_RECORDS across
	// the nodes: all, mutations, mixed, or none (no api record at all).
	ReadRecords string            `json:"api_read_records"`
	Findings    []reviewFinding   `json:"findings"`
	Tokens      []reviewToken     `json:"tokens"`
	Changes     []reviewChange    `json:"token_changes"`
	Principals  []reviewPrincipal `json:"principals"`
	Refused     []reviewRefusal   `json:"refused_credentials"`
	Nodes       []reviewNode      `json:"nodes"`
}

// reviewActivity is what the records say one principal did in the window.
type reviewActivity struct {
	// Calls counts calls by record kind. A coalesced record counts as the
	// calls it stands for, a rate_limited record as the calls it summarized.
	Calls map[string]int64 `json:"calls,omitempty"`
	// Denied counts calls refused with 403.
	Denied int64 `json:"denied,omitempty"`
	// RateLimited counts calls the flood budget summarized instead of
	// recording one by one.
	RateLimited int64      `json:"rate_limited,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	LastAction  string     `json:"last_action,omitempty"`
	LastNode    string     `json:"last_node,omitempty"`
}

// reviewToken is one listed token joined with its activity.
type reviewToken struct {
	models.APIToken
	reviewActivity
	Flags []reviewFlag `json:"flags"`
}

// reviewPrincipal is a caller the records name that is not a listed token:
// people, the operator token, nodes, daemon subsystems, sandbox SSH keys,
// and tokens no longer listed.
type reviewPrincipal struct {
	ID    string   `json:"id"`
	Kind  string   `json:"kind"`
	Name  string   `json:"name,omitempty"`
	Teams []string `json:"teams,omitempty"`
	reviewActivity
	Flags []reviewFlag `json:"flags"`

	teams  map[string]bool
	nameAt time.Time
}

// reviewChange is a token create or revoke the records hold.
type reviewChange struct {
	Change  string    `json:"change"`
	TokenID string    `json:"token_id"`
	Role    string    `json:"role,omitempty"`
	Team    string    `json:"team,omitempty"`
	At      time.Time `json:"at"`
	By      string    `json:"by,omitempty"`
	ByName  string    `json:"by_name,omitempty"`
	Node    string    `json:"node"`
	// Flags is admin_grant on a create that handed out the admin role, and
	// revoked on a revoke.
	Flags []reviewFlag `json:"flags"`
}

// reviewRefusal is the refused credentials (401s) from one source address.
type reviewRefusal struct {
	Source string `json:"source"`
	// Count includes the 401s each auth_denied record folded in.
	Count      int64            `json:"count"`
	Reasons    map[string]int64 `json:"reasons,omitempty"`
	LastSeen   time.Time        `json:"last_seen"`
	LastAction string           `json:"last_action,omitempty"`
	LastNode   string           `json:"last_node"`
}

// reviewNode is one node's verdict and what its records show about the
// report's coverage.
type reviewNode struct {
	auditlog.NodeReport
	ReadRecords string `json:"api_read_records"`
	APIRecords  int64  `json:"api_records"`
	// Lost is how many records the node's writer dropped (gap markers).
	Lost int64 `json:"records_lost"`
}

// reviewFinding is one flagged row, in words.
type reviewFinding struct {
	Flag    reviewFlag `json:"flag"`
	Subject string     `json:"subject"`
	Name    string     `json:"name,omitempty"`
	Detail  string     `json:"detail"`
}

type accessReviewOptions struct {
	auditVerifyOptions
	hasWitness bool
	format     string
}

// errNoExportBatches is the empty-export case: nothing to review, which is
// INCOMPLETE (exit 3), never a pass.
var errNoExportBatches = errors.New("no export batches found: check --export or --export-dir, and that the exporter has run since --since")

func runAccess(ctx context.Context, a *app, args []string) int {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "review":
		return runAccessReview(ctx, a, args)
	case "":
		return a.usageError(nil, "access", "expected a subcommand: review")
	}
	return a.usageError(nil, "access", "unknown subcommand %q: expected review", sub)
}

func runAccessReview(ctx context.Context, a *app, args []string) int {
	const verbName = "access review"
	fs, c := a.newFlagSet(verbName)
	var (
		witnessURL, exportURL, exportDir, sinceRaw string
		region, endpoint                           string
		pathStyle                                  bool
		maxLag                                     = auditVerifyDefaultMaxLag
		format                                     = "md"
	)
	fs.StringVar(&witnessURL, "witness", "", "")
	fs.StringVar(&exportURL, "export", "", "")
	fs.StringVar(&exportDir, "export-dir", "", "")
	fs.StringVar(&sinceRaw, "since", "", "")
	fs.StringVar(&format, "format", format, "")
	fs.DurationVar(&maxLag, "max-lag", maxLag, "")
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
	now := a.clock().UTC()
	opts := accessReviewOptions{auditVerifyOptions: auditVerifyOptions{maxLag: maxLag, exportDir: exportDir}, format: format}
	switch {
	case sinceRaw == "":
		return a.usageError(c, verbName, "--since is required: the review window is yours to choose (a quarter is 90d)")
	case (exportURL == "") == (exportDir == ""):
		return a.usageError(c, verbName, "give exactly one of --export or --export-dir")
	case format != "md" && format != "csv":
		return a.usageError(c, verbName, "--format must be md or csv, got %q", format)
	case maxLag < 0:
		return a.usageError(c, verbName, "--max-lag must not be negative")
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
	opts.s3 = auditexport.S3Config{Region: region, Endpoint: endpoint, PathStyle: pathStyle}

	// The token list first: a caller who may not read it (token.read is
	// auditor or admin) learns that before the export walk, which can take
	// minutes.
	var list models.APITokenList
	if err := a.tokenAPI(ctx, c, http.MethodGet, tokensRoute, nil, &list); err != nil {
		return a.fail(c, err, exitError)
	}
	merge := newReviewMerge(opts.since, now, opts.hasWitness)
	err = walkReviewEvidence(ctx, opts, now, merge.add)
	if errors.Is(err, errNoExportBatches) {
		return a.fail(c, err, exitIncomplete)
	}
	if err != nil {
		return a.fail(c, err, exitError)
	}
	review := merge.finish(list.Tokens)
	// A contradiction outranks an empty export: a hidden witness head with
	// no batches anywhere is a FAIL, not "nothing to review".
	if review.Result == auditlog.ResultFail {
		return a.failReview(c, review)
	}
	if merge.batches == 0 {
		return a.fail(c, errNoExportBatches, exitIncomplete)
	}
	switch {
	case c.json:
		a.printJSON(review)
	case opts.format == "csv":
		writeAccessReviewCSV(a.stdout, review)
	default:
		writeAccessReviewMarkdown(a.stdout, review)
	}
	if review.Result == auditlog.ResultIncomplete {
		return exitIncomplete
	}
	return exitOK
}

// failReview reports a review whose evidence did not verify. Nothing goes to
// stdout: a report built from that history must not be filed. The verdict,
// in audit verify's words, goes to stderr.
func (a *app) failReview(c *commonFlags, r accessReview) int {
	var problems []string
	nodes := make([]auditlog.NodeReport, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		nodes = append(nodes, n.NodeReport)
		for _, p := range n.Problems {
			problems = append(problems, "node "+n.NodeID+": "+p)
		}
	}
	err := fmt.Errorf("the audit export did not verify, so no access review was produced: %s", strings.Join(problems, "; "))
	if c.json {
		return a.fail(c, err, exitError)
	}
	printAuditReport(a.stderr, auditReport{Result: r.Result, WindowStart: r.WindowStart, CheckedAt: r.GeneratedAt, Nodes: nodes})
	fmt.Fprintln(a.stderr, "\naerolvm: the audit export did not verify, so no access review was produced")
	return exitError
}

// reviewShare is one node's part of the review, folded from its records as
// the verifying walk hands them over.
type reviewShare struct {
	node       string
	report     auditlog.NodeReport
	principals map[string]*reviewPrincipal
	changes    []reviewChange
	refused    map[string]*reviewRefusal
	apiRecords int64
	plainReads int64
	lost       int64
}

func newReviewShare(node string) *reviewShare {
	return &reviewShare{node: node, principals: map[string]*reviewPrincipal{}, refused: map[string]*reviewRefusal{}}
}

// walkReviewEvidence reads every node, up to accessReviewParallelNodes at a
// time, and hands each node's share to add in node order, so the report does
// not depend on which node finished first. A node's slot frees only when its
// share is merged, which bounds the shares held at once. The first error
// stops the nodes not yet started and is returned once the rest finish.
func walkReviewEvidence(ctx context.Context, opts accessReviewOptions, now time.Time, add func(*reviewShare)) error {
	var reader *auditwitness.Reader
	if opts.hasWitness {
		wcfg := opts.s3
		wcfg.Bucket, wcfg.Prefix = opts.witness.bucket, opts.witness.prefix
		var err error
		if reader, err = auditwitness.NewReader(ctx, wcfg); err != nil {
			return err
		}
	}
	export, lister, err := searchExport(ctx, opts.auditVerifyOptions, now)
	if err != nil {
		return err
	}
	var nodes []string
	if reader != nil {
		nodes, err = reader.Nodes(ctx)
	} else {
		nodes, err = lister(ctx)
	}
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return errNoExportBatches
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		share *reviewShare
		err   error
	}
	done := make([]chan result, len(nodes))
	for i := range done {
		done[i] = make(chan result, 1)
	}
	// Every node takes a slot, in order, and the merge loop frees it. The
	// oldest unmerged node always holds one, so the loop below never waits
	// on a node that cannot start.
	slots := make(chan struct{}, accessReviewParallelNodes)
	go func() {
		for i, id := range nodes {
			slots <- struct{}{}
			if err := ctx.Err(); err != nil {
				// An earlier node failed: the review is lost, so the rest
				// are not read.
				done[i] <- result{err: err}
				continue
			}
			go func() {
				share, err := reviewOneNode(ctx, reader, export, opts.auditVerifyOptions, id, now)
				if err != nil {
					err = fmt.Errorf("node %s: %w", id, err)
				}
				done[i] <- result{share: share, err: err}
			}()
		}
	}()
	// Errors are taken in node order too: the one reported is the first
	// failing node, whichever failed first in time.
	var firstErr error
	for i := range nodes {
		res := <-done[i]
		switch {
		case res.err != nil:
			if firstErr == nil {
				firstErr = res.err
				cancel()
			}
		case firstErr == nil:
			add(res.share)
		}
		<-slots
	}
	return firstErr
}

// reviewOneNode walks one node with no filter but the window: the review needs
// every record in it.
func reviewOneNode(ctx context.Context, reader *auditwitness.Reader, export exportFactory, opts auditVerifyOptions, id string, now time.Time) (*reviewShare, error) {
	in, done, err := auditNodeInput(ctx, reader, export, opts, id, now)
	if err != nil {
		return nil, err
	}
	defer done()
	share := newReviewShare(id)
	rep, err := auditlog.SearchNode(ctx, in, auditlog.SearchFilter{Since: opts.since}, share.observe)
	if err != nil {
		return nil, err
	}
	share.report = rep
	return share, nil
}

// observe folds one verified record into the share.
func (s *reviewShare) observe(ev auditlog.Event) {
	switch ev.Kind {
	case auditKindGap:
		s.lost += ev.Dropped
		return
	case auditlog.KindAuthDenied:
		s.refusal(ev)
		return
	case auditlog.KindAPI:
		s.apiRecords++
		if plainRead(ev) {
			s.plainReads++
		}
		s.tokenChange(ev)
	}
	c := ev.Caller
	if c == nil {
		return
	}
	id := clean(c.ID)
	if id == "" {
		return
	}
	p := s.principals[id]
	if p == nil {
		p = &reviewPrincipal{ID: id, Kind: clean(c.Kind), teams: map[string]bool{}}
		s.principals[id] = p
	}
	p.add(s.node, ev)
}

// plainRead reports whether ev is a read that only SB_AUDIT_API_RECORDS=all
// records: an allowed GET on a /v1 route that is neither the token list nor
// a toolbox or session route (those are recorded under the default too, as
// are refusals; pkg/api's shouldRecordCall). Facade routes are left out, so
// the inference can miss "all" but never claims it falsely.
func plainRead(ev auditlog.Event) bool {
	r := ev.Request
	if r == nil || ev.Result == auditlog.APIResultDenied || r.Status == http.StatusSwitchingProtocols {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	route := r.Route
	if !strings.HasPrefix(route, "/v1/") || route == tokensRoute {
		return false
	}
	return !strings.Contains(route, "/toolbox") && !strings.Contains(route, "/sessions")
}

// tokenChange records a successful token create or revoke.
func (s *reviewShare) tokenChange(ev auditlog.Event) {
	r := ev.Request
	if r == nil || ev.Result != auditlog.APIResultOK || clean(r.Target) == "" {
		return
	}
	ch := reviewChange{TokenID: clean(r.Target), At: ev.Time.UTC(), Node: s.node, Flags: []reviewFlag{}}
	switch {
	case r.Method == http.MethodPost && r.Route == tokensRoute:
		ch.Change = changeCreated
		if g := r.Grant; g != nil {
			ch.Role, ch.Team = clean(g.Role), clean(g.Team)
		}
		if ch.Role == string(controlplane.RoleAdmin) {
			ch.Flags = append(ch.Flags, flagAdminGrant)
		}
	case r.Method == http.MethodDelete && r.Route == tokenItemRoute:
		ch.Change = changeRevoked
		ch.Flags = append(ch.Flags, flagRevoked)
	default:
		return
	}
	if c := ev.Caller; c != nil {
		ch.By, ch.ByName = clean(c.ID), clean(c.Name)
	}
	s.changes = append(s.changes, ch)
}

// refusal counts one auth_denied record against its source address.
func (s *reviewShare) refusal(ev auditlog.Event) {
	src := ""
	if ev.Request != nil {
		src = clean(ev.Request.Source)
	}
	r := refusalFor(s.refused, src)
	n := int64(1)
	if ev.Dropped > 0 {
		n += ev.Dropped
	}
	r.Count += n
	r.Reasons[orUnknown(clean(ev.Reason))] += n
	if !ev.Time.Before(r.LastSeen) {
		r.LastSeen, r.LastAction, r.LastNode = ev.Time.UTC(), clean(ev.Ref), s.node
	}
}

// refusalFor returns src's row, folding sources past the cap into one.
func refusalFor(m map[string]*reviewRefusal, src string) *reviewRefusal {
	src = orUnknown(src)
	if r, ok := m[src]; ok {
		return r
	}
	if len(m) >= accessReviewMaxSources {
		src = otherSources
		if r, ok := m[src]; ok {
			return r
		}
	}
	r := &reviewRefusal{Source: src, Reasons: map[string]int64{}}
	m[src] = r
	return r
}

// sourcesInOrder lists a share's refusing sources sorted, with the folded
// row last, so which sources fold when shares merge past the cap does not
// depend on map order.
func sourcesInOrder(m map[string]*reviewRefusal) []string {
	srcs := make([]string, 0, len(m))
	for src := range m {
		if src != otherSources {
			srcs = append(srcs, src)
		}
	}
	sort.Strings(srcs)
	if _, ok := m[otherSources]; ok {
		srcs = append(srcs, otherSources)
	}
	return srcs
}

// add folds one record by this principal.
func (p *reviewPrincipal) add(node string, ev auditlog.Event) {
	n := int64(1)
	switch {
	case ev.Reason == auditlog.ReasonRateLimited && ev.Dropped > 0:
		n = ev.Dropped
	case ev.Request != nil && ev.Request.Count > 1:
		n = ev.Request.Count
	}
	if p.Calls == nil {
		p.Calls = map[string]int64{}
	}
	p.Calls[orUnknown(clean(ev.Kind))] += n
	if ev.Kind == auditlog.KindAPI {
		if ev.Result == auditlog.APIResultDenied {
			p.Denied += n
		}
		if ev.Reason == auditlog.ReasonRateLimited {
			p.RateLimited += n
		}
	}
	if name := clean(ev.Caller.Name); name != "" && !ev.Time.Before(p.nameAt) {
		p.Name, p.nameAt = name, ev.Time
	}
	if team := clean(ev.Caller.Team); team != "" {
		p.teams[team] = true
	}
	if p.LastSeen == nil || ev.Time.After(*p.LastSeen) {
		t := ev.Time.UTC()
		p.LastSeen, p.LastAction, p.LastNode = &t, actionText(ev), node
	}
}

// merge folds another node's row for the same principal. Shares are merged
// in node order and a later node wins only a strictly later time, so the
// result does not depend on which node finished first.
func (p *reviewPrincipal) merge(o *reviewPrincipal) {
	// Both rows came from add, which always fills Calls and LastSeen.
	for k, v := range o.Calls {
		p.Calls[k] += v
	}
	p.Denied += o.Denied
	p.RateLimited += o.RateLimited
	for t := range o.teams {
		p.teams[t] = true
	}
	if o.Name != "" && (p.Name == "" || o.nameAt.After(p.nameAt)) {
		p.Name, p.nameAt = o.Name, o.nameAt
	}
	if o.LastSeen.After(*p.LastSeen) {
		p.LastSeen, p.LastAction, p.LastNode = o.LastSeen, o.LastAction, o.LastNode
	}
}

// actionText is a record as a "last action": the route for an api record,
// the kind and ref for anything else.
func actionText(ev auditlog.Event) string {
	if ev.Reason == auditlog.ReasonRateLimited && ev.Request != nil && len(ev.Request.Routes) > 0 {
		return clean("rate_limited " + strings.Join(ev.Request.Routes, ", "))
	}
	ref := clean(ev.Ref)
	if ev.Kind == auditlog.KindAPI {
		return ref
	}
	return strings.TrimSpace(orUnknown(clean(ev.Kind)) + " " + ref)
}

// clean is every value from a record or the token list as the report shows
// it: control characters stripped and at most 256 characters (Section 3,
// finding 3.6), the rule the server applies to display names.
func clean(s string) string { return controlplane.SanitizeDisplayName(s) }

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// reviewMerge folds node shares, in node order, into the report. Each share
// is merged and dropped as soon as the shares before it are, so memory holds
// the merged rows plus at most accessReviewParallelNodes shares.
type reviewMerge struct {
	r          accessReview
	principals map[string]*reviewPrincipal
	refused    map[string]*reviewRefusal
	nodeReads  []string
	// batches counts export batches across nodes; none at all is the
	// empty-export case.
	batches int
}

func newReviewMerge(since, now time.Time, witnessed bool) *reviewMerge {
	return &reviewMerge{
		r: accessReview{
			Result: auditlog.ResultPass, WindowStart: since.UTC(), GeneratedAt: now, Witnessed: witnessed,
			Findings: []reviewFinding{}, Tokens: []reviewToken{}, Changes: []reviewChange{},
			Principals: []reviewPrincipal{}, Refused: []reviewRefusal{}, Nodes: []reviewNode{},
		},
		principals: map[string]*reviewPrincipal{},
		refused:    map[string]*reviewRefusal{},
	}
}

// add merges one node's share.
func (m *reviewMerge) add(s *reviewShare) {
	r := &m.r
	r.Result = worse(r.Result, s.report.Result)
	m.batches += s.report.ExportBatches
	reads := readRecordsNone
	switch {
	case s.plainReads > 0:
		reads = readRecordsAll
	case s.apiRecords > 0:
		reads = readRecordsMutations
	}
	m.nodeReads = append(m.nodeReads, reads)
	r.Nodes = append(r.Nodes, reviewNode{NodeReport: s.report, ReadRecords: reads, APIRecords: s.apiRecords, Lost: s.lost})
	for id, p := range s.principals {
		if have, ok := m.principals[id]; ok {
			have.merge(p)
		} else {
			m.principals[id] = p
		}
	}
	r.Changes = append(r.Changes, s.changes...)
	for _, src := range sourcesInOrder(s.refused) {
		o := s.refused[src]
		have := refusalFor(m.refused, src)
		have.Count += o.Count
		for k, v := range o.Reasons {
			have.Reasons[k] += v
		}
		if o.LastSeen.After(have.LastSeen) {
			have.LastSeen, have.LastAction, have.LastNode = o.LastSeen, o.LastAction, o.LastNode
		}
	}
}

// finish joins the merged evidence with the token list, flags every row and
// returns the report. Call it once, after the last add.
func (m *reviewMerge) finish(tokens []models.APIToken) accessReview {
	r := m.r
	r.ReadRecords = fleetReadRecords(m.nodeReads)
	sort.SliceStable(r.Changes, func(i, j int) bool {
		a, b := r.Changes[i], r.Changes[j]
		return cmp.Or(a.At.Compare(b.At), cmp.Compare(a.Node, b.Node), cmp.Compare(a.TokenID, b.TokenID)) < 0
	})
	var f findings
	r.Tokens = tokenRows(tokens, m.principals, r.GeneratedAt, r.ReadRecords, &f)
	revoked := map[string]bool{}
	for _, ch := range r.Changes {
		by := who(ch.By, ch.ByName)
		switch {
		case ch.Change == changeRevoked:
			revoked[ch.TokenID] = true
			f.add(flagRevoked, ch.TokenID, "", "revoked at "+ch.At.Format(time.RFC3339)+" by "+by+" on "+ch.Node)
		case ch.Role == string(controlplane.RoleAdmin):
			f.add(flagAdminGrant, ch.TokenID, "", "minted with role admin on "+teamWords(ch.Team)+" by "+by+" at "+ch.At.Format(time.RFC3339)+" on "+ch.Node)
		}
	}
	r.Principals = principalRows(m.principals, revoked, &f)
	for _, ref := range m.refused {
		r.Refused = append(r.Refused, *ref)
	}
	sort.Slice(r.Refused, func(i, j int) bool {
		a, b := r.Refused[i], r.Refused[j]
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Source, b.Source)) < 0
	})
	for _, ref := range r.Refused {
		f.add(flagRefused, ref.Source, "", fmt.Sprintf("%d refused %s (401): %s", ref.Count, plural(ref.Count, "credential", "credentials"), countsWords(ref.Reasons, " ")))
	}
	r.Findings = f.sorted()
	return r
}

// buildAccessReview is a whole merge over shares already in hand.
func buildAccessReview(tokens []models.APIToken, shares []*reviewShare, since, now time.Time, witnessed bool) accessReview {
	m := newReviewMerge(since, now, witnessed)
	for _, s := range shares {
		m.add(s)
	}
	return m.finish(tokens)
}

// tokenRows joins each listed token with its activity, taking the token's
// principal out of principals so it is not listed twice, and flags it.
func tokenRows(tokens []models.APIToken, principals map[string]*reviewPrincipal, now time.Time, readRecords string, f *findings) []reviewToken {
	readsCaveat := ""
	if readRecords != readRecordsAll {
		readsCaveat = "; plain reads leave no record unless SB_AUDIT_API_RECORDS=all, so read-only use would not show"
	}
	listed := append([]models.APIToken(nil), tokens...)
	sort.SliceStable(listed, func(i, j int) bool {
		a, b := listed[i], listed[j]
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Team, b.Team), cmp.Compare(a.ID, b.ID)) < 0
	})
	rows := []reviewToken{}
	for _, t := range listed {
		t.ID, t.Name, t.Role, t.Team, t.CreatedBy = clean(t.ID), clean(t.Name), clean(t.Role), clean(t.Team), clean(t.CreatedBy)
		row := reviewToken{APIToken: t, Flags: []reviewFlag{}}
		if p, ok := principals[t.ID]; ok {
			row.reviewActivity = p.reviewActivity
			delete(principals, t.ID)
		}
		flag := func(fl reviewFlag, detail string) {
			row.Flags = append(row.Flags, fl)
			f.add(fl, t.ID, t.Name, detail)
		}
		if t.Role == string(controlplane.RoleAdmin) {
			flag(flagAdmin, "role admin on "+teamWords(t.Team))
		}
		switch left := t.ExpiresAt.Sub(now); {
		case t.Expired || left <= 0:
			flag(flagExpired, "expired "+t.ExpiresAt.UTC().Format(time.RFC3339)+"; it no longer authenticates, and the expiry sweep removes it 30 days after it expired")
		case left <= accessReviewExpiringWithin:
			flag(flagExpiring, "expires "+t.ExpiresAt.UTC().Format(time.RFC3339)+", in "+daysWords(left))
		}
		if row.Calls[auditlog.KindAPI] == 0 {
			flag(flagNoRecordedAction, "no api record names it in the window"+readsCaveat)
		}
		activityFlags(row.reviewActivity, flag)
		rows = append(rows, row)
	}
	return rows
}

// principalRows lists the principals that are not listed tokens, by kind
// then id, and flags them.
func principalRows(principals map[string]*reviewPrincipal, revoked map[string]bool, f *findings) []reviewPrincipal {
	ps := make([]*reviewPrincipal, 0, len(principals))
	for _, p := range principals {
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool {
		return cmp.Or(cmp.Compare(ps[i].Kind, ps[j].Kind), cmp.Compare(ps[i].ID, ps[j].ID)) < 0
	})
	rows := []reviewPrincipal{}
	for _, p := range ps {
		for t := range p.teams {
			p.Teams = append(p.Teams, t)
		}
		sort.Strings(p.Teams)
		p.Flags = []reviewFlag{}
		flag := func(fl reviewFlag, detail string) {
			p.Flags = append(p.Flags, fl)
			f.add(fl, p.ID, p.Name, detail)
		}
		switch controlplane.PrincipalKind(p.Kind) {
		case controlplane.PrincipalOperator:
			flag(flagAdmin, "the operator token (PAT): admin on every team")
		case controlplane.PrincipalNode:
			flag(flagAdmin, "a cluster node calling on its own behalf: admin on every team")
		case controlplane.PrincipalToken:
			if revoked[p.ID] {
				flag(flagNotListed, "acted in the window but is not in the token list: revoked in the window")
			} else {
				flag(flagNotListed, "acted in the window but is not in the token list: revoked, or removed by the expiry sweep")
			}
		}
		activityFlags(p.reviewActivity, flag)
		rows = append(rows, *p)
	}
	return rows
}

// activityFlags flags refused and summarized calls, for tokens and other
// principals alike.
func activityFlags(a reviewActivity, flag func(reviewFlag, string)) {
	if a.Denied > 0 {
		flag(flagDenied, fmt.Sprintf("%d %s refused with 403", a.Denied, plural(a.Denied, "call", "calls")))
	}
	if a.RateLimited > 0 {
		flag(flagRateLimited, fmt.Sprintf("%d %s summarized by the audit flood budget: their routes are on record, each call is not", a.RateLimited, plural(a.RateLimited, "call", "calls")))
	}
}

// findings collects the flagged rows in words.
type findings []reviewFinding

func (f *findings) add(flag reviewFlag, subject, name, detail string) {
	*f = append(*f, reviewFinding{Flag: flag, Subject: subject, Name: name, Detail: detail})
}

// sorted orders findings by flagOrder, then subject.
func (f findings) sorted() []reviewFinding {
	rank := map[reviewFlag]int{}
	for i, fl := range flagOrder {
		rank[fl] = i
	}
	out := append([]reviewFinding{}, f...)
	sort.SliceStable(out, func(i, j int) bool {
		return cmp.Or(cmp.Compare(rank[out[i].Flag], rank[out[j].Flag]), cmp.Compare(out[i].Subject, out[j].Subject)) < 0
	})
	return out
}

// fleetReadRecords sums up the per-node read-record settings.
func fleetReadRecords(nodes []string) string {
	seen := map[string]bool{}
	for _, n := range nodes {
		seen[n] = true
	}
	switch {
	case seen[readRecordsAll] && len(seen) == 1:
		return readRecordsAll
	case seen[readRecordsAll]:
		return readRecordsMixed
	case seen[readRecordsMutations]:
		return readRecordsMutations
	}
	return readRecordsNone
}

// who names a principal for people: the name with the id, or the id alone.
func who(id, name string) string {
	switch {
	case id == "":
		return "an unrecorded caller"
	case name == "" || name == id:
		return id
	}
	return name + " (" + id + ")"
}

func daysWords(d time.Duration) string {
	days := int64(d / (24 * time.Hour))
	if days < 1 {
		return "less than a day"
	}
	return fmt.Sprintf("%d %s", days, plural(days, "day", "days"))
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// countsWords prints a count map in key order: "api 4, secret_open 1" with
// sep " ", or "api=4; secret_open=1" with sep "=".
func countsWords(m map[string]int64, sep string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s%s%d", k, sep, m[k]))
	}
	if sep == "=" {
		return strings.Join(parts, "; ")
	}
	return strings.Join(parts, ", ")
}
