package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// The access review's two file formats. Both print every value from a record
// or the token list through an escaper (Section 3, finding 3.6): a display
// name is whatever an identity provider's claim said, and a request target
// is whatever a caller put in a URL path, so neither may turn into Markdown
// markup or a spreadsheet formula in the file an auditor opens.

// mdEscape makes s literal text in a Markdown table cell. It backslash-
// escapes the characters that start inline markup (emphasis, code, links,
// raw HTML, entities, GitHub math and strikethrough) and the cell separator,
// and breaks the two patterns GitHub turns into links without any markup
// ("https://…" and "www.…"), so a display name cannot become a link to
// somewhere else.
func mdEscape(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch r {
		case '\\', '`', '*', '_', '[', ']', '<', '>', '|', '~', '&', '$', '#', '!':
			b.WriteByte('\\')
		case ':':
			if strings.HasPrefix(s[i:], "://") {
				b.WriteByte('\\')
			}
		case '.':
			if i >= 3 && strings.EqualFold(s[i-3:i], "www") {
				b.WriteByte('\\')
			}
		case '\n', '\r', '\t':
			r = ' '
		}
		b.WriteRune(r)
	}
	return b.String()
}

// csvCell keeps a value from being read as a formula by a spreadsheet: a
// cell that starts with =, +, - or @ (or a tab or carriage return, which
// some spreadsheets skip before looking) gets a leading apostrophe.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// mdRow writes one table row, every cell escaped. An empty cell prints as a
// dash so the table still reads as a table.
func mdRow(w io.Writer, cells ...string) {
	parts := make([]string, len(cells))
	for i, c := range cells {
		if c == "" {
			c = "-"
		}
		parts[i] = mdEscape(c)
	}
	fmt.Fprintf(w, "| %s |\n", strings.Join(parts, " | "))
}

// mdHeader writes a table's header and separator rows.
func mdHeader(w io.Writer, cells ...string) {
	mdRow(w, cells...)
	fmt.Fprintf(w, "|%s\n", strings.Repeat("---|", len(cells)))
}

func day(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

func stamp(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func flagsText(fs []reviewFlag, sep string) string {
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = string(f)
	}
	return strings.Join(parts, sep)
}

// lastActionText is "when what (node)".
func lastActionText(a reviewActivity) string {
	if a.LastSeen == nil {
		return ""
	}
	return stamp(a.LastSeen) + " " + a.LastAction + " on " + a.LastNode
}

// evidenceWords sums up the verdict for the report's header.
func evidenceWords(r accessReview) string {
	var records int64
	for _, n := range r.Nodes {
		records += n.RecordsChecked
	}
	s := fmt.Sprintf("%s on %d %s, %d %s checked", r.Result, len(r.Nodes), plural(int64(len(r.Nodes)), "node", "nodes"), records, plural(records, "record", "records"))
	if r.Witnessed {
		return s + "; every witnessed head in the window was checked against the chain"
	}
	return s + "; no --witness, so each record was checked to link to the one before it, but no witnessed head was checked"
}

// readRecordsWords explains what the inferred read-record setting means for
// the no_recorded_action flag (§5.10), so it is not read as "unused".
func readRecordsWords(r accessReview) string {
	switch r.ReadRecords {
	case readRecordsAll:
		return "all: plain reads are on record on every node (SB_AUDIT_API_RECORDS=all), so no_recorded_action means no recorded use at all"
	case readRecordsMixed:
		var on []string
		for _, n := range r.Nodes {
			if n.ReadRecords == readRecordsAll {
				on = append(on, n.NodeID)
			}
		}
		return "mixed: plain reads are on record only on " + strings.Join(on, ", ") + "; elsewhere a read-only token (viewer, auditor, a metrics scrape) shows no recorded action even when it is used"
	case readRecordsMutations:
		return "mutations: no plain read is on record on any node (SB_AUDIT_API_RECORDS=mutations, the default), so a read-only token (viewer, auditor, a metrics scrape) shows no recorded action even when it is used"
	}
	return "none: no api record is in the window on any node (SB_AUDIT_API_RECORDS=off, or no calls), so every token shows no recorded action"
}

// nodeNotes is what the evidence table says about one node besides counts.
func nodeNotes(n reviewNode, witnessed bool) string {
	var notes []string
	if n.RecordsChecked == 0 {
		notes = append(notes, "no records in the window")
	}
	if stale := countStale(n.Pending); stale > 0 {
		notes = append(notes, fmt.Sprintf("%d witnessed %s waited longer than --max-lag for records", stale, plural(int64(stale), "head", "heads")))
	}
	if n.UnreachedBatches > 0 {
		notes = append(notes, fmt.Sprintf("%d re-sent or overlapping %s", n.UnreachedBatches, plural(int64(n.UnreachedBatches), "batch", "batches")))
	}
	for _, w := range n.Warnings {
		// The no-witness caveat is said once, in the header.
		if !witnessed && strings.HasPrefix(w, "no witness given") {
			continue
		}
		notes = append(notes, w)
	}
	return strings.Join(notes, "; ")
}

func countStale(ps []auditlog.PendingHead) int {
	n := 0
	for _, p := range ps {
		if p.Stale {
			n++
		}
	}
	return n
}

// writeAccessReviewMarkdown renders the report as a Markdown document.
func writeAccessReviewMarkdown(w io.Writer, r accessReview) {
	fmt.Fprintln(w, "# AerolVM access review")
	fmt.Fprintln(w)
	if r.Result == auditlog.ResultIncomplete {
		fmt.Fprintln(w, "> **INCOMPLETE:** heads witnessed after the newest exported records have waited longer than --max-lag, so this report can miss the newest records. Run it again once the export catches up.")
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "- **Window:** %s to %s\n", r.WindowStart.UTC().Format(time.RFC3339), r.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "- **Evidence:** %s\n", mdEscape(evidenceWords(r)))
	fmt.Fprintf(w, "- **Read records:** %s\n", mdEscape(readRecordsWords(r)))
	fmt.Fprintf(w, "- **Tokens:** %d listed by GET /v1/tokens\n", len(r.Tokens))
	fmt.Fprintln(w, "- **Scope:** this report lists the tokens sandboxd holds and every principal the audit records name in the window. It cannot list people an identity provider would let in who never called the API. Roles are shown for tokens and the operator token; a person who signs in through an identity provider gets a role from the identity file's bindings, which this report does not read.")

	fmt.Fprintln(w, "\n## Findings")
	fmt.Fprintln(w)
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
	} else {
		mdHeader(w, "Flag", "Subject", "Name", "Detail")
		for _, f := range r.Findings {
			mdRow(w, string(f.Flag), f.Subject, f.Name, f.Detail)
		}
	}

	fmt.Fprintln(w, "\n## Tokens")
	fmt.Fprintln(w)
	if len(r.Tokens) == 0 {
		fmt.Fprintln(w, "No tokens are listed.")
	} else {
		mdHeader(w, "Token", "Name", "Role", "Team", "Created by", "Created", "Expires", "Last action", "Calls", "Flags")
		for _, t := range r.Tokens {
			mdRow(w, t.ID, t.Name, t.Role, t.Team, t.CreatedBy, day(t.CreatedAt), day(t.ExpiresAt), lastActionText(t.reviewActivity), countsWords(t.Calls, " "), flagsText(t.Flags, ", "))
		}
	}

	fmt.Fprintln(w, "\n## Token changes in the window")
	fmt.Fprintln(w)
	if len(r.Changes) == 0 {
		fmt.Fprintln(w, "No token was created or revoked in the window.")
	} else {
		mdHeader(w, "When", "Change", "Token", "Role", "Team", "By", "Node", "Flags")
		for _, ch := range r.Changes {
			mdRow(w, ch.At.Format(time.RFC3339), ch.Change, ch.TokenID, ch.Role, ch.Team, who(ch.By, ch.ByName), ch.Node, flagsText(ch.Flags, ", "))
		}
	}

	fmt.Fprintln(w, "\n## Principals seen in the window")
	fmt.Fprintln(w)
	if len(r.Principals) == 0 {
		fmt.Fprintln(w, "No principal besides the listed tokens is named in the window.")
	} else {
		fmt.Fprintln(w, "Listed tokens are in the table above and not repeated here.")
		fmt.Fprintln(w)
		mdHeader(w, "Principal", "Kind", "Name", "Teams", "Last action", "Calls", "Flags")
		for _, p := range r.Principals {
			mdRow(w, p.ID, p.Kind, p.Name, strings.Join(p.Teams, ", "), lastActionText(p.reviewActivity), countsWords(p.Calls, " "), flagsText(p.Flags, ", "))
		}
	}

	fmt.Fprintln(w, "\n## Refused credentials")
	fmt.Fprintln(w)
	if len(r.Refused) == 0 {
		fmt.Fprintln(w, "No credential was refused in the window.")
	} else {
		mdHeader(w, "Source", "Refusals", "Reasons", "Last", "Node")
		for _, ref := range r.Refused {
			last := ref.LastSeen.UTC().Format(time.RFC3339) + " " + ref.LastAction
			mdRow(w, ref.Source, strconv.FormatInt(ref.Count, 10), countsWords(ref.Reasons, " "), strings.TrimSpace(last), ref.LastNode)
		}
	}

	fmt.Fprintln(w, "\n## Evidence")
	fmt.Fprintln(w)
	mdHeader(w, "Node", "Result", "Records", "From", "To", "Batches", "Read records", "Lost", "Notes")
	for _, n := range r.Nodes {
		mdRow(w, n.NodeID, string(n.Result), strconv.FormatInt(n.RecordsChecked, 10), stamp(n.EvidenceFrom), stamp(n.EvidenceTo),
			strconv.Itoa(n.ExportBatches), n.ReadRecords, strconv.FormatInt(n.Lost, 10), nodeNotes(n, r.Witnessed))
	}
}

// accessReviewCSVHeader is the CSV's one header. Every row has a type in
// the first column; the columns a type does not use stay empty.
var accessReviewCSVHeader = []string{"row", "id", "name", "kind", "role", "team", "created_by", "created_at", "expires_at", "last_seen", "last_action", "node", "calls", "denied", "rate_limited", "flags", "detail"}

// writeAccessReviewCSV renders the report as one CSV table: a review row
// with the verdict, one row per node, token, token change, other principal
// and refusing source.
func writeAccessReviewCSV(w io.Writer, r accessReview) {
	cw := csv.NewWriter(w)
	row := func(cells ...string) {
		out := make([]string, len(cells))
		for i, c := range cells {
			out[i] = csvCell(c)
		}
		_ = cw.Write(out)
	}
	num := func(n int64) string { return strconv.FormatInt(n, 10) }
	total := func(m map[string]int64) string {
		var n int64
		for _, v := range m {
			n += v
		}
		return num(n)
	}
	_ = cw.Write(accessReviewCSVHeader)
	row("review", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		fmt.Sprintf("result=%s; window_start=%s; generated_at=%s; witnessed=%t; api_read_records=%s; tokens=%d",
			r.Result, r.WindowStart.Format(time.RFC3339), r.GeneratedAt.Format(time.RFC3339), r.Witnessed, r.ReadRecords, len(r.Tokens)))
	for _, n := range r.Nodes {
		detail := fmt.Sprintf("result=%s; evidence_from=%s; evidence_to=%s; batches=%d; api_read_records=%s; records_lost=%d",
			n.Result, stamp(n.EvidenceFrom), stamp(n.EvidenceTo), n.ExportBatches, n.ReadRecords, n.Lost)
		if notes := nodeNotes(n, r.Witnessed); notes != "" {
			detail += "; notes=" + notes
		}
		row("node", n.NodeID, "", "", "", "", "", "", "", "", "", n.NodeID, num(n.RecordsChecked), "", "", "", detail)
	}
	for _, t := range r.Tokens {
		row("token", t.ID, t.Name, "token", t.Role, t.Team, t.CreatedBy, t.CreatedAt.UTC().Format(time.RFC3339), t.ExpiresAt.UTC().Format(time.RFC3339),
			stamp(t.LastSeen), t.LastAction, t.LastNode, total(t.Calls), num(t.Denied), num(t.RateLimited), flagsText(t.Flags, ";"), countsWords(t.Calls, "="))
	}
	for _, ch := range r.Changes {
		row("token_"+ch.Change, ch.TokenID, "", "token", ch.Role, ch.Team, "", "", "", ch.At.Format(time.RFC3339), "", ch.Node, "", "", "", flagsText(ch.Flags, ";"),
			"by="+who(ch.By, ch.ByName))
	}
	for _, p := range r.Principals {
		row("principal", p.ID, p.Name, p.Kind, "", strings.Join(p.Teams, " "), "", "", "",
			stamp(p.LastSeen), p.LastAction, p.LastNode, total(p.Calls), num(p.Denied), num(p.RateLimited), flagsText(p.Flags, ";"), countsWords(p.Calls, "="))
	}
	for _, ref := range r.Refused {
		row("refused_source", ref.Source, "", "auth_denied", "", "", "", "", "", ref.LastSeen.Format(time.RFC3339), ref.LastAction, ref.LastNode, num(ref.Count), "", "", string(flagRefused), countsWords(ref.Reasons, "="))
	}
	cw.Flush()
}
