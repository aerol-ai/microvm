package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// TestIdentityFileMatchesTheServerParser pins the review's lenient reader to
// sandboxd's: for the same file, the same SHA-256 and the same canonical
// binding lines, so a line in the bindings table is the line an
// identity_config record carries. The import is test-only: the CLI binary
// never links internal/identity (TestDependencyGuard builds it without).
func TestIdentityFileMatchesTheServerParser(t *testing.T) {
	docs := map[string]string{
		"fixture": reviewIdentityYAML,
		"app role and multi-claim": `version: 1
issuers:
  - name: entra
    url: https://login.microsoftonline.com/tid/v2.0
    audiences: [api://aerolvm]
  - name: gh
    url: https://token.actions.githubusercontent.com
    audiences: [aerolvm]
bindings:
  - { issuer: entra, app_role: " AerolVM.Admin ", role: admin, team: "*" }
  - { issuer: entra, app_role: AerolVM.Auditor, role: auditor }
  - { issuer: gh, claim: { workflow: deploy, " repository ": " acme/api ", ref: refs/heads/main }, role: runner, team: api }
  - { issuer: gh, claim: { sub: "repo:acme/web:environment:prod" }, role: viewer, team: "*" }
deny_subjects: ["gh:repo:acme/old", "entra:x"]
`,
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			server, err := identity.Parse([]byte(doc))
			if err != nil {
				t.Fatalf("the server refuses the test file: %v", err)
			}
			review, err := parseIdentityFile([]byte(doc))
			if err != nil {
				t.Fatal(err)
			}
			sum := server.Summary()
			var lines []string
			for _, b := range review.Bindings {
				lines = append(lines, b.Line)
			}
			if review.Hash != server.Hash() || !reflect.DeepEqual(lines, sum.Bindings) || review.DenySubjects != len(sum.Deny) || len(review.Issuers) != len(server.Issuers) {
				t.Fatalf("review reads\n  %s %q (%d denied)\nsandboxd reads\n  %s %q (%d denied)", review.Hash, lines, review.DenySubjects, server.Hash(), sum.Bindings, len(sum.Deny))
			}
		})
	}
}

func TestParseIdentityFile(t *testing.T) {
	file, err := parseIdentityFile([]byte(reviewIdentityYAML))
	if err != nil {
		t.Fatal(err)
	}
	if file.Hash != reviewIdentityHash() || len(file.Bindings) != 6 || file.DenySubjects != 1 ||
		!reflect.DeepEqual(file.Issuers, []reviewIssuer{{"okta", "Acme Okta"}, {"github-actions", ""}}) {
		t.Fatalf("file = %+v", file)
	}
	want := []string{"admin,every_team", "every_team", "every_team", "", "", ""}
	for i, b := range file.Bindings {
		if got := flagsText(b.Flags, ","); got != want[i] || b.Index != i+1 {
			t.Errorf("binding %d (%s): flags %q, want %q", b.Index, b.Line, got, want[i])
		}
	}
	if b := file.Bindings[0]; b.Team != "*" || b.Match != `group="platform-admins"` || b.Issuer != "okta" || b.Role != "admin" {
		t.Errorf("an admin binding with no team is bound to every team: %+v", b)
	}

	big := append([]byte(reviewIdentityYAML), bytes.Repeat([]byte("#"), maxIdentityFileBytes)...)
	cases := []struct{ name, doc, want string }{
		{"empty", "", "empty"},
		{"comments only", "# nothing\n", "empty"},
		{"not YAML", "version: [1\n", "yaml"},
		{"wrong version", "version: 2\n", "version 2, want 1"},
		{"two matchers", "version: 1\nbindings:\n  - {issuer: okta, group: a, app_role: b, role: runner, team: x}\n", "exactly one of group, app_role or claim"},
		{"no matcher", "version: 1\nbindings:\n  - {issuer: okta, role: runner, team: x}\n", "exactly one of"},
		{"bad role", "version: 1\nbindings:\n  - {issuer: okta, group: a, role: owner, team: x}\n", `role "owner"`},
		{"no team", "version: 1\nbindings:\n  - {issuer: okta, group: a, role: runner}\n", "needs a team"},
		{"too large", string(big), "larger than"},
	}
	for _, c := range cases {
		if _, err := parseIdentityFile([]byte(c.doc)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", c.name, err, c.want)
		}
	}
	if _, err := readIdentityFile(filepath.Join(t.TempDir(), "nope.yaml")); err == nil || !strings.Contains(err.Error(), "--identity-file") {
		t.Errorf("missing file: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentityFile(bad); err == nil || !strings.Contains(err.Error(), bad+": version 2") {
		t.Errorf("bad file: %v", err)
	}
	dir := t.TempDir()
	if _, err := readIdentityFile(dir); err == nil {
		t.Error("a directory is not an identity file")
	}
}

func TestBindingLineHelpers(t *testing.T) {
	cases := []struct {
		line, role, team string
		ok               bool
		flags            string
	}{
		{`okta group="a -> b" -> admin/*`, "admin", "*", true, "admin,every_team"},
		{`okta group="x" -> runner/payments`, "runner", "payments", true, ""},
		{`gh claim:sub="s" -> viewer/*`, "viewer", "*", true, "every_team"},
		{"okta:00u9eve", "", "", false, ""},
	}
	for _, c := range cases {
		role, team, ok := bindingGrant(c.line)
		if role != c.role || team != c.team || ok != c.ok || flagsText(grantFlags(c.line), ",") != c.flags {
			t.Errorf("%q: %q %q %v %v", c.line, role, team, ok, grantFlags(c.line))
		}
	}
	long := strings.Repeat("é", maxReviewLineRunes+5)
	if got := cleanLine(" a\x00b\n "); got != "ab" {
		t.Errorf("cleanLine strips control characters: %q", got)
	}
	if got := []rune(cleanLine(long)); len(got) != maxReviewLineRunes+1 || got[len(got)-1] != '…' {
		t.Errorf("cleanLine caps at %d runes: %d", maxReviewLineRunes, len(got))
	}
}

// TestIdentityChangeRows covers the record shapes the fixture does not
// carry: a node's first file, removed issuers, lines left out, and a record
// with nothing in it.
func TestIdentityChangeRows(t *testing.T) {
	at := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	share := newReviewShare("node-c")
	share.identityChange(auditlog.Event{Time: at, Kind: auditlog.KindIdentityConfig})
	share.identityChange(auditlog.Event{Time: at, Kind: auditlog.KindIdentityConfig, IdentityConfig: &auditlog.IdentityConfig{
		NewHash: "h1", IssuersRemoved: []string{"old url=x"}, Omitted: 3, BindingsAdded: []string{"okta group=\"a\" -> runner/x"},
	}})
	share.identityChange(auditlog.Event{Time: at.Add(time.Hour), Kind: auditlog.KindIdentityConfig, IdentityConfig: &auditlog.IdentityConfig{OldHash: "h1", NewHash: "h2"}})
	if len(share.identityChanges) != 2 || share.identityHash != "h2" {
		t.Fatalf("a record with no body is skipped and the newest hash wins: %+v", share)
	}
	first := share.identityChanges[0]
	if got := identityChangeWords(first); got != "identity file changed from no file recorded before to h1 at 2026-10-16T08:00:00Z: 1 binding added, 1 issuer removed, 3 lines left out of the record" {
		t.Errorf("first file: %s", got)
	}
	if got := flagsText(first.Flags, ","); got != "identity_change" {
		t.Errorf("a runner binding is no admin grant: %s", got)
	}
	var kinds []string
	for _, l := range changeLines(first, shortHash) {
		kinds = append(kinds, l.change+":"+l.line)
	}
	want := []string{"file:old_hash=(none) new_hash=h1", `binding_added:okta group="a" -> runner/x`, "issuer_removed:old url=x", "lines_omitted:3 lines left out of the record; the hashes name both files"}
	if !reflect.DeepEqual(kinds, want) {
		t.Errorf("rows =\n %q\nwant\n %q", kinds, want)
	}
	if got := identityChangeWords(share.identityChanges[1]); !strings.HasSuffix(got, ": no line changed") {
		t.Errorf("empty change: %s", got)
	}
}

// TestAccessReviewIdentityJSON is the identity part of the fixture review
// on the structure: the three identity_config records with their flags, the
// file's bindings, and which nodes record that file.
func TestAccessReviewIdentityJSON(t *testing.T) {
	h := newReviewHarness(t, nil, 0)
	if code := h.run(reviewArgs("--json", "--identity-file", filepath.Join(reviewFixture, "identity.yaml"))...); code != exitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	var rep accessReview
	h.jsonOut(&rep)
	ch := rep.IdentityChanges
	if len(ch) != 3 || ch[0].Node != "node-a" || ch[1].Node != "node-b" || ch[0].NewHash != reviewIdentityHash() ||
		flagsText(ch[0].Flags, ",") != "identity_change,admin_grant" || !ch[2].Reordered || flagsText(ch[2].Flags, ",") != "identity_change" {
		t.Fatalf("identity changes: %+v", ch)
	}
	f := rep.IdentityFile
	if f == nil || f.Hash != reviewIdentityHash() || len(f.Bindings) != 6 || f.Bindings[4].Team != "-ops" {
		t.Fatalf("identity file: %+v", f)
	}
	same, other, unknown := enforcement(f, rep.Nodes)
	if !reflect.DeepEqual(same, []string{"node-a"}) || len(other) != 1 || other[0] != (nodeFile{"node-b", identityV3Hash}) || !reflect.DeepEqual(unknown, []string{"node-c"}) {
		t.Fatalf("enforcement: %v %v %v", same, other, unknown)
	}
	grants := 0
	for _, fd := range rep.Findings {
		if fd.Flag == flagAdminGrant {
			grants++
		}
	}
	if grants != 3 {
		t.Fatalf("admin grants: one token, one binding on each of two nodes; got %d", grants)
	}
}

// TestIdentityBindingsRender: a file with no bindings says so, and a file
// every node records is enforced everywhere.
func TestIdentityBindingsRender(t *testing.T) {
	file, err := parseIdentityFile([]byte("version: 1\nissuers:\n  - {name: okta}\n"))
	if err != nil {
		t.Fatal(err)
	}
	share := newReviewShare("node-a")
	share.report = auditlog.NodeReport{NodeID: "node-a", Result: auditlog.ResultPass, ExportBatches: 1}
	share.identityHash = file.Hash
	m := newReviewMerge(reviewNow.Add(-time.Hour), reviewNow, false)
	m.add(share)
	r := m.finish(nil, file)
	var md bytes.Buffer
	writeAccessReviewMarkdown(&md, r)
	for _, want := range []string{"The file holds no bindings", "issuers okta; 0 bindings; 0 denied subjects", "this file, by the newest identity\\_config record on node-a\n"} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("missing %q:\n%s", want, md.String())
		}
	}
}
