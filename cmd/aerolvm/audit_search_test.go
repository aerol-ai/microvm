package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// testdata/audit-export is a fixture export in the layout the S3 and
// webhook exporters write: two nodes, each with a chain of api records
// (calls by a CI token and two people, a refusal, a coalesced exec, a
// rate_limited summary, an SSH session, a lifecycle auto-stop, a forwarded
// MCP call), a secret open, an auth_denied record and a flood-mode change.
// Its hashes were computed by LinkEvent; the search verifies them.
const fixtureExport = "testdata/audit-export"

const fixtureSince = "2026-10-16T00:00:00Z"

// TestAuditSearchFixture is "what did Ana do": every record whose caller is
// her, on every node, in chain order per node, after the chain checked out.
func TestAuditSearchFixture(t *testing.T) {
	h := newHarness(t)
	if code := h.run("audit", "search", "--export-dir", fixtureExport, "--since", fixtureSince, "--caller", "ANA@acme.com"); code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, h.stdout.String(), h.stderr.String())
	}
	out := h.stdout.String()
	want := []string{
		`2026-10-16T09:10:00Z  node-a  api  ok  caller=oidc:okta:00u1ana (ana@acme.com)  team=payments  "POST /v1/sandboxes/{id}/toolbox/{path...}"  sandbox=sb-1  status=200  target=process/execute  digest=9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7  correlation_id=corr-2`,
		`2026-10-16T09:50:00Z  node-a  api  ok  caller=oidc:okta:00u1ana (ana@acme.com)  team=payments  "DELETE /v1/sandboxes/{id}"  sandbox=sb-1  status=204  correlation_id=corr-6`,
		`2026-10-16T09:25:00Z  node-b  api  ok  caller=oidc:okta:00u1ana (ana@acme.com)  team=payments  via=node-a  "POST /v1/sandboxes/{id}/stop"  sandbox=sb-3  status=200  surface=mcp  correlation_id=corr-b3`,
		"3 records matched",
		"no --witness: each record was checked to link to the one before it",
		"PASS  node node-a",
		"PASS  node node-b",
	}
	for _, line := range want {
		if !strings.Contains(out, line) {
			t.Fatalf("output is missing\n  %s\nin:\n%s", line, out)
		}
	}
	if strings.Contains(out, "bob@acme.com") || strings.Contains(out, "ci-deploy") {
		t.Fatalf("another caller's record matched:\n%s", out)
	}
}

func TestAuditSearchFilters(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		matched int
		want    string
	}{
		{"every record", nil, 12, "12 records matched"},
		{"refusals", []string{"--result", "denied"}, 2, `caller=oidc:okta:00u2bob (bob@acme.com)`},
		{"auth_denied names the source and the folded count", []string{"--kind", "auth_denied"}, 1, "dropped=3  status=401  source=203.0.113.9"},
		{"one sandbox", []string{"--sandbox", "sb-3"}, 3, "sandbox=sb-3"},
		{"the CI token, by id", []string{"--caller", "tok_7Hq2abcdEFGH"}, 4, `routes="POST /v1/sandboxes/{id}/toolbox/{path...}"`},
		{"a coalesced exec shows its count", []string{"--caller", "ci-deploy", "--node", "node-b"}, 1, "count=17"},
		{"ssh sessions by the sandbox key", []string{"--caller", "sb-3"}, 1, "surface=ssh"},
		{"system actions", []string{"--caller", "system:lifecycle"}, 1, `"SYSTEM lifecycle.auto_stop"`},
		{"until bounds the window", []string{"--until", "2026-10-16T09:06:00Z"}, 3, "3 records matched"},
		{"limit prints the first N, counts all", []string{"--limit", "2"}, 12, "12 records matched; the first 2 are shown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			args := append([]string{"audit", "search", "--export-dir", fixtureExport, "--since", fixtureSince}, tc.args...)
			if code := h.run(args...); code != exitOK {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, h.stdout.String(), h.stderr.String())
			}
			if !strings.Contains(h.stdout.String(), tc.want) {
				t.Fatalf("output does not mention %q:\n%s", tc.want, h.stdout.String())
			}
			h2 := newHarness(t)
			if code := h2.run(append(args, "--json")...); code != exitOK {
				t.Fatalf("json exit %d: %s", code, h2.stderr.String())
			}
			var rep auditSearchReport
			h2.jsonOut(&rep)
			if rep.Matched != tc.matched || rep.Result != auditlog.ResultPass || rep.Witnessed {
				t.Fatalf("json report: matched %d result %s witnessed %v, want %d PASS unwitnessed", rep.Matched, rep.Result, rep.Witnessed, tc.matched)
			}
		})
	}
}

// TestAuditSearchTamperedExportFails: a rewritten record breaks its node's
// chain, so the search fails, and the forged record is not printed as a
// match.
func TestAuditSearchTamperedExportFails(t *testing.T) {
	root := t.TempDir()
	copyTree(t, fixtureExport, root)
	batch := filepath.Join(root, "node=node-a", "2026", "10", "16", "node-a_1.jsonl")
	raw, err := os.ReadFile(batch)
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.Replace(string(raw), `"id":"oidc:okta:00u1ana","name":"ana@acme.com"`, `"id":"oidc:okta:00u9eve","name":"eve@acme.com"`, 1)
	if forged == string(raw) {
		t.Fatal("fixture changed: nothing to forge")
	}
	if err := os.WriteFile(batch, []byte(forged), 0o644); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	if code := h.run("audit", "search", "--export-dir", root, "--since", fixtureSince, "--caller", "eve@acme.com"); code != exitError {
		t.Fatalf("exit %d, want %d\n%s", code, exitError, h.stdout.String())
	}
	out := h.stdout.String()
	if !strings.Contains(out, "FAIL  node node-a") || !strings.Contains(out, "does not link") || !strings.Contains(out, "0 records matched") {
		t.Fatalf("tampered search output:\n%s", out)
	}
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if info.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, raw, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAuditSearchWithWitnessAndS3: with --witness the search is a full
// verification; without one, the nodes come from the S3 export itself.
func TestAuditSearchWithWitnessAndS3(t *testing.T) {
	start := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Minute)
	since := start.Add(6 * time.Hour)
	fake := auditFake(t)
	a := newAuditNode("node-a", start, 270)
	b := newAuditNode("node-b", start, 270)
	a.publish(fake, 0)
	b.publish(fake, 0)
	s3 := []string{"--export", "s3://audit/audit", "--endpoint", fake.URL, "--region", "us-east-1", "--path-style", "--since", since.Format(time.RFC3339)}

	h := newHarness(t)
	if code := h.run(append([]string{"audit", "search", "--witness", "s3://witness/witness/", "--sandbox", "sb", "--limit", "0", "--json"}, s3...)...); code != exitOK {
		t.Fatalf("witnessed search exit %d\n%s\n%s", code, h.stdout.String(), h.stderr.String())
	}
	var rep auditSearchReport
	h.jsonOut(&rep)
	if !rep.Witnessed || len(rep.Nodes) != 2 || rep.Matched == 0 || len(rep.Matches) != rep.Matched {
		t.Fatalf("witnessed report: %+v", rep)
	}
	for _, n := range rep.Nodes {
		if n.HeadsInWindow == 0 || n.HeadsLinked != n.HeadsInWindow {
			t.Fatalf("node %s: %d of %d heads linked", n.NodeID, n.HeadsLinked, n.HeadsInWindow)
		}
	}

	h = newHarness(t)
	if code := h.run(append([]string{"audit", "search", "--json"}, s3...)...); code != exitOK {
		t.Fatalf("unwitnessed S3 search exit %d\n%s\n%s", code, h.stdout.String(), h.stderr.String())
	}
	rep = auditSearchReport{}
	h.jsonOut(&rep)
	if rep.Witnessed || len(rep.Nodes) != 2 || rep.Nodes[0].NodeID != "node-a" || rep.Nodes[1].NodeID != "node-b" {
		t.Fatalf("nodes from the S3 export: %+v", rep.Nodes)
	}
	// 234 records per node inside the window (the first six hours of each
	// node's 270 are before --since), every one kept under the limit.
	if rep.Matched != 468 || len(rep.Matches) != min(rep.Matched, auditSearchDefaultLimit) {
		t.Fatalf("matched %d, kept %d", rep.Matched, len(rep.Matches))
	}
}

func TestAuditSearchUsageAndErrors(t *testing.T) {
	fake := auditFake(t)
	empty := t.TempDir()
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no since", []string{"audit", "search", "--export-dir", fixtureExport}, exitUsage, "--since is required"},
		{"no export", []string{"audit", "search", "--since", "1d"}, exitUsage, "exactly one of --export or --export-dir"},
		{"both exports", []string{"audit", "search", "--since", "1d", "--export", "s3://a", "--export-dir", "x"}, exitUsage, "exactly one of"},
		{"bad since", []string{"audit", "search", "--since", "soon", "--export-dir", fixtureExport}, exitUsage, "--since must be"},
		{"bad until", []string{"audit", "search", "--since", "1d", "--until", "later", "--export-dir", fixtureExport}, exitUsage, "--until must be"},
		{"until before since", []string{"audit", "search", "--since", fixtureSince, "--until", "2026-10-15T00:00:00Z", "--export-dir", fixtureExport}, exitUsage, "--until must be after --since"},
		{"negative limit", []string{"audit", "search", "--since", "1d", "--export-dir", fixtureExport, "--limit", "-1"}, exitUsage, "--limit"},
		{"negative lag", []string{"audit", "search", "--since", "1d", "--export-dir", fixtureExport, "--max-lag", "-1m"}, exitUsage, "--max-lag"},
		{"bad witness URL", []string{"audit", "search", "--since", "1d", "--export-dir", fixtureExport, "--witness", "https://w"}, exitUsage, "--witness must be s3://"},
		{"bad export URL", []string{"audit", "search", "--since", "1d", "--export", "s3:///x"}, exitUsage, "--export must be s3://"},
		{"bare local without one node", []string{"audit", "search", "--since", "1d", "--export-dir", fixtureExport, "--local", "x.jsonl"}, exitUsage, "names no node"},
		{"unexpected argument", []string{"audit", "search", "extra", "--since", "1d", "--export-dir", fixtureExport}, exitUsage, "unexpected argument"},
		{"unknown flag", []string{"audit", "search", "--nope"}, exitUsage, "nope"},
		{"an empty export holds no nodes", []string{"audit", "search", "--since", "1d", "--export-dir", empty}, exitError, "no nodes found"},
		{"a missing export dir", []string{"audit", "search", "--since", "1d", "--export-dir", filepath.Join(empty, "nope")}, exitError, "no such file"},
		{"local for a node not searched", []string{"audit", "search", "--since", "1d", "--export-dir", fixtureExport, "--node", "node-a", "--local", "node-b=x"}, exitError, `names node "node-b"`},
		{"unreadable local log", []string{"audit", "search", "--since", "1d", "--export-dir", fixtureExport, "--node", "node-a", "--local", "/does/not/exist"}, exitError, "open the local log"},
		{"missing witness bucket", []string{"audit", "search", "--since", "1d", "--export-dir", fixtureExport, "--witness", "s3://missing", "--endpoint", fake.URL, "--region", "us-east-1", "--path-style"}, exitError, "missing"},
		{"missing export bucket", []string{"audit", "search", "--since", "1d", "--export", "s3://missing", "--endpoint", fake.URL, "--region", "us-east-1", "--path-style"}, exitError, "missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			if code := h.run(c.args...); code != c.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, c.code, h.stdout.String(), h.stderr.String())
			}
			if out := h.stdout.String() + h.stderr.String(); !strings.Contains(out, c.want) {
				t.Fatalf("output does not mention %q:\n%s", c.want, out)
			}
		})
	}
}

// TestFormatAuditRecordTokenCreate: a token create's line names the token
// it minted and what it can do.
func TestFormatAuditRecordTokenCreate(t *testing.T) {
	ev := auditlog.Event{
		Time: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC), Kind: auditlog.KindAPI, Result: auditlog.APIResultOK,
		Ref: "POST /v1/tokens", Caller: &auditlog.Caller{Kind: "operator", ID: "operator"},
		Request: &auditlog.Request{Method: "POST", Route: "/v1/tokens", Status: 201, Target: "tok_7Hq2abcdEFGH", Grant: &auditlog.Grant{Role: "admin", Team: "*"}},
	}
	want := `2026-10-17T09:00:00Z  node-a  api  ok  caller=operator  "POST /v1/tokens"  status=201  target=tok_7Hq2abcdEFGH  grant_role=admin  grant_team=*`
	if got := formatAuditRecord("node-a", ev); got != want {
		t.Fatalf("line =\n  %s\nwant\n  %s", got, want)
	}
}

// TestAuditSearchIncompleteAndLocal: a witnessed head newer than the
// evidence past --max-lag makes the search INCOMPLETE (exit 3), as audit
// verify does; a local log copy supplies the records not exported yet.
func TestAuditSearchIncompleteAndLocal(t *testing.T) {
	start := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Minute)
	fake := auditFake(t)
	a := newAuditNode("node-a", start, 270)
	a.publish(fake, 20)
	args := []string{"audit", "search", "--witness", "s3://witness/witness/", "--export", "s3://audit/audit", "--endpoint", fake.URL,
		"--region", "us-east-1", "--path-style", "--since", start.Add(6 * time.Hour).Format(time.RFC3339), "--node", "node-a"}
	h := newHarness(t)
	if code := h.run(args...); code != exitIncomplete {
		t.Fatalf("exit %d, want %d\n%s", code, exitIncomplete, h.stdout.String())
	}
	local := filepath.Join(t.TempDir(), "secrets.jsonl")
	if err := os.WriteFile(local, batchBody(a.evs[100:]), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.run(append(args, "--local", local)...); code != exitOK {
		t.Fatalf("with the local log: exit %d\n%s\n%s", code, h.stdout.String(), h.stderr.String())
	}
}
