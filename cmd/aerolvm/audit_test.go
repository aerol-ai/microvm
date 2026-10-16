package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/auditwitness"
	"github.com/aerol-ai/microvm/pkg/auditwitness/s3fake"
)

// auditNode is one node's honest history laid out the way production lays
// it out: records exported to an S3 export bucket in batches, and every
// tenth head locked in a witness bucket.
type auditNode struct {
	id      string
	evs     []auditlog.Event
	batches []auditBatch
}

type auditBatch struct {
	key  string
	evs  []auditlog.Event
	last time.Time
}

func newAuditNode(id string, start time.Time, n int) *auditNode {
	node := &auditNode{id: id}
	prev := auditlog.GenesisPrevHash
	for i := 0; i < n; i++ {
		ev := auditlog.Event{Time: start.Add(time.Duration(i) * 10 * time.Minute), EventID: fmt.Sprintf("%s-%d", id, i), NodeID: id, SandboxID: "sb", Result: "success"}
		auditlog.LinkEvent(prev, &ev)
		prev = ev.EventHash
		node.evs = append(node.evs, ev)
	}
	for start := 0; start < n; start += 6 {
		end := min(start+6, n)
		last := node.evs[end-1].Time.Add(time.Second)
		batchID := fmt.Sprintf("%s:%d:%x", id, start*512, start)
		node.batches = append(node.batches, auditBatch{key: auditexport.ObjectKey("audit", id, batchID, last), evs: node.evs[start:end], last: last})
	}
	return node
}

func batchBody(evs []auditlog.Event) []byte {
	var buf bytes.Buffer
	for _, ev := range evs {
		raw, _ := json.Marshal(ev)
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// publish writes the node's export and witness into the fake. dropExport
// leaves out the last n batches, as an export that stopped would.
func (n *auditNode) publish(fake *s3fake.Server, dropExport int) {
	for i, b := range n.batches {
		if i >= len(n.batches)-dropExport {
			break
		}
		fake.Put("audit", b.key, batchBody(b.evs))
	}
	for i := 9; i < len(n.evs); i += 10 {
		n.witness(fake, n.evs[i].EventHash, n.evs[i].Time.Add(20*time.Second))
	}
}

func (n *auditNode) witness(fake *s3fake.Server, head string, at time.Time) {
	fake.SetClock(func() time.Time { return at })
	body, _ := json.Marshal(auditwitness.HeadRecord{NodeID: n.id, HeadHex: head, Observed: at})
	fake.Put("witness", auditwitness.HeadKey("witness/", n.id, at), body)
	fake.SetClock(nil)
}

func auditFake(t *testing.T) *s3fake.Server {
	t.Helper()
	fake := s3fake.New()
	t.Cleanup(fake.Close)
	fake.CreateBucket("witness", s3fake.BucketOptions{Lock: &s3fake.Lock{Mode: s3fake.ModeCompliance, Days: 30}})
	fake.CreateBucket("audit", s3fake.BucketOptions{})
	dir := t.TempDir()
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "none"))
	return fake
}

func verifyArgs(fake *s3fake.Server, since time.Time, extra ...string) []string {
	return append([]string{"audit", "verify",
		"--witness", "s3://witness/witness/", "--since", since.Format(time.RFC3339),
		"--endpoint", fake.URL, "--region", "us-east-1", "--path-style"}, extra...)
}

func TestAuditVerify(t *testing.T) {
	start := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Minute)
	since := start.Add(6 * time.Hour)
	cases := []struct {
		name   string
		setup  func(fake *s3fake.Server, a, b *auditNode)
		extra  []string
		code   int
		result auditlog.Result
		want   string
	}{
		{
			name:   "honest history on two nodes",
			setup:  func(fake *s3fake.Server, a, b *auditNode) { a.publish(fake, 0); b.publish(fake, 0) },
			code:   exitOK,
			result: auditlog.ResultPass,
		},
		{
			name: "a forged head on one node fails the whole run",
			setup: func(fake *s3fake.Server, a, b *auditNode) {
				a.publish(fake, 0)
				b.publish(fake, 0)
				b.witness(fake, strings.Repeat("ab", 32), b.evs[120].Time)
			},
			code:   exitError,
			result: auditlog.ResultFail,
			want:   "not on the chain",
		},
		{
			name: "an export that stopped hours ago is incomplete, never a pass",
			setup: func(fake *s3fake.Server, a, b *auditNode) {
				a.publish(fake, 0)
				b.publish(fake, 20)
			},
			code:   exitIncomplete,
			result: auditlog.ResultIncomplete,
		},
		{
			name: "one node selected",
			setup: func(fake *s3fake.Server, a, b *auditNode) {
				a.publish(fake, 0)
				b.publish(fake, 20)
			},
			extra:  []string{"--node", "node-a"},
			code:   exitOK,
			result: auditlog.ResultPass,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := auditFake(t)
			a := newAuditNode("node-a", start, 270)
			b := newAuditNode("node-b", start, 270)
			c.setup(fake, a, b)
			h := newHarness(t)
			args := verifyArgs(fake, since, append([]string{"--export", "s3://audit/audit", "--json"}, c.extra...)...)
			if code := h.run(args...); code != c.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, c.code, h.stdout.String(), h.stderr.String())
			}
			var rep auditReport
			h.jsonOut(&rep)
			if rep.Result != c.result {
				t.Fatalf("result %s, want %s: %s", rep.Result, c.result, h.stdout.String())
			}
			if c.want != "" && !strings.Contains(h.stdout.String(), c.want) {
				t.Fatalf("report does not mention %q: %s", c.want, h.stdout.String())
			}
			for _, n := range rep.Nodes {
				if n.HeadsInWindow == 0 || (n.Result == auditlog.ResultPass && n.HeadsLinked != n.HeadsInWindow) {
					t.Fatalf("node %s: %d of %d linked", n.NodeID, n.HeadsLinked, n.HeadsInWindow)
				}
			}
		})
	}
}

// Batches saved from a webhook receiver in the export layout, plus a local
// log for the records the export has not received yet.
func TestAuditVerifyExportDirAndLocalLog(t *testing.T) {
	start := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Minute)
	fake := auditFake(t)
	a := newAuditNode("node-a", start, 270)
	a.publish(fake, 0)
	root := t.TempDir()
	for _, b := range a.batches[:len(a.batches)-10] {
		p := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(b.key, "audit/")))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, batchBody(b.evs), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	local := filepath.Join(t.TempDir(), "secrets.jsonl")
	if err := os.WriteFile(local, batchBody(a.evs[200:]), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	since := start.Add(6 * time.Hour)
	if code := h.run(verifyArgs(fake, since, "--export-dir", root, "--node", "node-a")...); code != exitIncomplete {
		t.Fatalf("without the local log: exit %d, want %d\n%s", code, exitIncomplete, h.stdout.String())
	}
	if !strings.Contains(h.stdout.String(), "waiting longer than --max-lag") {
		t.Fatalf("human output: %s", h.stdout.String())
	}
	if code := h.run(verifyArgs(fake, since, "--export-dir", root, "--node", "node-a", "--local", local)...); code != exitOK {
		t.Fatalf("with the local log: exit %d\nstdout: %s\nstderr: %s", code, h.stdout.String(), h.stderr.String())
	}
	out := h.stdout.String()
	for _, want := range []string{"PASS  window from", "PASS  node node-a", "evidence:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("human output missing %q:\n%s", want, out)
		}
	}
}

func TestAuditVerifyUsageAndErrors(t *testing.T) {
	fake := auditFake(t)
	since := time.Now().Add(-time.Hour)
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no subcommand", []string{"audit"}, exitUsage, "Usage: aerolvm audit verify"},
		{"unknown subcommand", []string{"audit", "check"}, exitUsage, `unknown audit command "check"`},
		{"no witness", []string{"audit", "verify", "--since", "1d", "--export", "s3://a"}, exitUsage, "--witness is required"},
		{"no since", []string{"audit", "verify", "--witness", "s3://w", "--export", "s3://a"}, exitUsage, "--since is required"},
		{"no export", []string{"audit", "verify", "--witness", "s3://w", "--since", "1d"}, exitUsage, "exactly one of --export or --export-dir"},
		{"both exports", []string{"audit", "verify", "--witness", "s3://w", "--since", "1d", "--export", "s3://a", "--export-dir", "x"}, exitUsage, "exactly one of"},
		{"bad witness URL", []string{"audit", "verify", "--witness", "https://w", "--since", "1d", "--export", "s3://a"}, exitUsage, "--witness must be s3://"},
		{"bad export URL", []string{"audit", "verify", "--witness", "s3://w", "--since", "1d", "--export", "s3:///x"}, exitUsage, "--export must be s3://"},
		{"bad since", []string{"audit", "verify", "--witness", "s3://w", "--since", "last week", "--export", "s3://a"}, exitUsage, "--since must be"},
		{"negative lag", []string{"audit", "verify", "--witness", "s3://w", "--since", "1d", "--export", "s3://a", "--max-lag", "-1m"}, exitUsage, "--max-lag"},
		{"bare local without one node", []string{"audit", "verify", "--witness", "s3://w", "--since", "1d", "--export", "s3://a", "--local", "x.jsonl"}, exitUsage, "names no node"},
		{"local twice", []string{"audit", "verify", "--witness", "s3://w", "--since", "1d", "--export", "s3://a", "--local", "n=a", "--local", "n=b"}, exitUsage, "twice"},
		{"local without a path", []string{"audit", "verify", "--witness", "s3://w", "--since", "1d", "--export", "s3://a", "--local", "n="}, exitUsage, "needs a node id and a path"},
		{"unexpected argument", []string{"audit", "verify", "extra", "--witness", "s3://w", "--since", "1d", "--export", "s3://a"}, exitUsage, "unexpected argument"},
		{"unknown flag", []string{"audit", "verify", "--nope"}, exitUsage, "nope"},
		{"missing witness bucket", verifyArgs(fake, since, "--witness", "s3://missing", "--export", "s3://audit/audit"), exitError, "missing"},
		{"empty witness", verifyArgs(fake, since, "--export", "s3://audit/audit"), exitError, "holds no node heads"},
		{"local for a node not verified", verifyArgs(fake, since, "--export", "s3://audit/audit", "--node", "a", "--local", "b=x"), exitError, `names node "b"`},
		{"unreadable local log", verifyArgs(fake, since, "--export", "s3://audit/audit", "--node", "a", "--local", "/does/not/exist"), exitError, "open the local log"},
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

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Time{
		"2026-10-01T00:00:00Z": time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		"30d":                  now.AddDate(0, 0, -30),
		"36h":                  now.Add(-36 * time.Hour),
	}
	for raw, want := range cases {
		got, err := parseSince(raw, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseSince(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
	for _, bad := range []string{"", "0d", "-3h", "yesterday", "xd"} {
		if _, err := parseSince(bad, now); err == nil {
			t.Errorf("parseSince(%q) accepted", bad)
		}
	}
}

func TestCalendarDaysAndWorse(t *testing.T) {
	days, err := calendarDays("2026-10-30", time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC))
	if err != nil || strings.Join(days, ",") != "2026-10-30,2026-10-31,2026-11-01" {
		t.Fatalf("days = %v %v", days, err)
	}
	if _, err := calendarDays("bad", time.Now()); err == nil {
		t.Fatal("a bad start day must fail")
	}
	if worse(auditlog.ResultFail, auditlog.ResultIncomplete) != auditlog.ResultFail || worse(auditlog.ResultPass, auditlog.ResultIncomplete) != auditlog.ResultIncomplete {
		t.Fatal("worse ranks FAIL > INCOMPLETE > PASS")
	}
}

// A node down across the window's start comes back re-shipping the head it
// had before. That head's record is older than the evidence the verifier
// reads; it must count as unchanged from the prior head, not as missing.
func TestAuditVerifyNodeDownAcrossWindowStart(t *testing.T) {
	fake := auditFake(t)
	start := time.Now().UTC().Add(-6 * 24 * time.Hour).Truncate(time.Hour)
	node := newAuditNode("node-a", start, 60)
	// Ten hours of records, then the node is down for days.
	for _, b := range node.batches[:5] {
		fake.Put("audit", b.key, batchBody(b.evs))
	}
	node.witness(fake, node.evs[29].EventHash, node.evs[29].Time.Add(time.Minute))
	// Back four days later: the unchanged head is re-shipped first, then new
	// records arrive and are witnessed.
	back := start.Add(4 * 24 * time.Hour)
	node.witness(fake, node.evs[29].EventHash, back)
	next := newAuditNode("node-a", back.Add(time.Minute), 0)
	prev := node.evs[29].EventHash
	for i := 0; i < 12; i++ {
		ev := auditlog.Event{Time: back.Add(time.Duration(i+1) * time.Minute), EventID: fmt.Sprintf("back-%d", i), NodeID: "node-a", SandboxID: "sb", Result: "success"}
		auditlog.LinkEvent(prev, &ev)
		prev = ev.EventHash
		next.evs = append(next.evs, ev)
	}
	fake.Put("audit", auditexport.ObjectKey("audit", "node-a", "node-a:9999:back", next.evs[11].Time), batchBody(next.evs))
	node.witness(fake, next.evs[11].EventHash, next.evs[11].Time.Add(20*time.Second))
	h := newHarness(t)
	since := back.Add(-time.Hour)
	if code := h.run(verifyArgs(fake, since, "--export", "s3://audit/audit")...); code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, h.stdout.String(), h.stderr.String())
	}
}
