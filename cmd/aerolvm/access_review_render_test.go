package main

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

func TestMarkdownEscape(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ana@acme.com", "ana@acme.com"},
		{"a|b", `a\|b`},
		{"*bold* _em_ `code` ~strike~", `\*bold\* \_em\_ \` + "`" + `code\` + "`" + ` \~strike\~`},
		{"<script>alert(1)</script>", `\<script\>alert(1)\</script\>`},
		{"[x](https://evil.example)", `\[x\](https\://evil.example)`},
		{"see www.evil.example and WWW.x", `see www\.evil.example and WWW\.x`},
		{"&lt; $x$ #1 !", `\&lt; \$x\$ \#1 \!`},
		{`back\slash`, `back\\slash`},
		{"two\nlines\tand\rcr", "two lines and cr"},
		{"12:30 http:x", "12:30 http:x"},
		{"/v1/sandboxes/{id}/toolbox/{path...}", "/v1/sandboxes/{id}/toolbox/{path...}"},
	}
	for _, c := range cases {
		if got := mdEscape(c.in); got != c.want {
			t.Errorf("mdEscape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCSVCellFormulaInjection(t *testing.T) {
	cases := []struct{ in, want string }{
		{"=SUM(A1:A9)", "'=SUM(A1:A9)"},
		{"+1-1", "'+1-1"},
		{"-legacy-ci", "'-legacy-ci"},
		{"@cmd", "'@cmd"},
		{"\tx", "'\tx"},
		{"\rx", "'\rx"},
		{"ana@acme.com", "ana@acme.com"},
		{"a=b", "a=b"},
		{"", ""},
	}
	for _, c := range cases {
		if got := csvCell(c.in); got != c.want {
			t.Errorf("csvCell(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestReadRecordsWords: each inferred setting says what no_recorded_action
// means under it, and "mixed" names the nodes that record reads.
func TestReadRecordsWords(t *testing.T) {
	nodes := []reviewNode{
		{NodeReport: auditlog.NodeReport{NodeID: "node-a"}, ReadRecords: readRecordsAll},
		{NodeReport: auditlog.NodeReport{NodeID: "node-b"}, ReadRecords: readRecordsMutations},
		{NodeReport: auditlog.NodeReport{NodeID: "node-c"}, ReadRecords: readRecordsAll},
	}
	cases := []struct{ setting, want string }{
		{readRecordsAll, "no_recorded_action means no recorded use at all"},
		{readRecordsMixed, "only on node-a, node-c;"},
		{readRecordsMutations, "SB_AUDIT_API_RECORDS=mutations, the default"},
		{readRecordsNone, "SB_AUDIT_API_RECORDS=off, or no calls"},
	}
	for _, c := range cases {
		got := readRecordsWords(accessReview{ReadRecords: c.setting, Nodes: nodes})
		if !strings.HasPrefix(got, c.setting+": ") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q does not say %q", c.setting, got, c.want)
		}
	}
}

func TestNodeNotes(t *testing.T) {
	n := reviewNode{NodeReport: auditlog.NodeReport{
		RecordsChecked:   4,
		Pending:          []auditlog.PendingHead{{Stale: true}, {Stale: false}, {Stale: true}},
		UnreachedBatches: 2,
		Warnings:         []string{"no witness given: ...", "export for node n has a gap on 2026-10-16"},
	}}
	want := "2 witnessed heads waited longer than --max-lag for records; 2 re-sent or overlapping batches; export for node n has a gap on 2026-10-16"
	if got := nodeNotes(n, false); got != want {
		t.Fatalf("notes without a witness:\n  %s\nwant\n  %s", got, want)
	}
	// With a witness there is no no-witness caveat to fold into the header.
	if got := nodeNotes(n, true); !strings.Contains(got, "no witness given") {
		t.Fatalf("notes with a witness: %s", got)
	}
}

// TestEmptyAccessReviewRenders: a review with nothing to list still says so
// in every section, and the CSV still carries its review row.
func TestEmptyAccessReviewRenders(t *testing.T) {
	share := newReviewShare("node-a")
	share.report = auditlog.NodeReport{NodeID: "node-a", Result: auditlog.ResultPass}
	r := buildAccessReview(nil, []*reviewShare{share}, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), reviewNow, true)
	var md bytes.Buffer
	writeAccessReviewMarkdown(&md, r)
	for _, want := range []string{
		"PASS on 1 node, 0 records checked; every witnessed head in the window was checked against the chain",
		"No findings.", "No tokens are listed.", "No token was created or revoked in the window.",
		"No principal besides the listed tokens is named in the window.", "No credential was refused in the window.",
		"| node-a | PASS | 0 | - | - | 0 | none | 0 | no records in the window |",
	} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("empty Markdown review is missing %q:\n%s", want, md.String())
		}
	}
	var out bytes.Buffer
	writeAccessReviewCSV(&out, r)
	rows, err := csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[1][0] != "review" || rows[2][0] != "node" || len(rows[1]) != len(accessReviewCSVHeader) {
		t.Fatalf("empty CSV review: %q", rows)
	}
	if day(time.Time{}) != "" || stamp(nil) != "" {
		t.Fatal("a missing time must print as an empty cell")
	}
}
