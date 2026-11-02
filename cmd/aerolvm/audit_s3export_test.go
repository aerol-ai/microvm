package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/auditwitness/s3fake"
)

// s3Watch sits in front of the in-memory S3 fake and watches the reads of
// export batches: how many GETs run at once, how many have started, and how
// far they run ahead of the verifier. The fake itself serves one request at
// a time, so the watch counts a GET from the moment it arrives.
type s3Watch struct {
	*httptest.Server
	inner http.Handler

	mu          sync.Mutex
	inflight    int
	maxInflight int
	started     int
	// opened, when set, is how many batches the verifier has asked for;
	// maxAhead is the most GETs started beyond it.
	opened   func() int
	maxAhead int

	// delay holds every GET this long, so downloads overlap.
	delay time.Duration
	// fail answers the batch whose key ends in it with 403 AccessDenied;
	// truncate cuts that batch's body short.
	fail, truncate string
	// gate, when set, holds every GET until it is closed or the client
	// gives up.
	gate chan struct{}
	// pairUp holds the first GET until a second one arrives (or five
	// seconds pass, which only a one-at-a-time reader ever waits out).
	pairUp   bool
	paired   chan struct{}
	pairOnce sync.Once
}

func watchS3(t *testing.T, fake *s3fake.Server) *s3Watch {
	t.Helper()
	w := &s3Watch{inner: fake.Config.Handler, paired: make(chan struct{})}
	w.Server = httptest.NewServer(http.HandlerFunc(w.serve))
	t.Cleanup(w.Close)
	return w
}

func (w *s3Watch) serve(rw http.ResponseWriter, r *http.Request) {
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if r.Method != http.MethodGet || bucket != "audit" || key == "" {
		w.inner.ServeHTTP(rw, r)
		return
	}
	w.mu.Lock()
	w.inflight++
	w.started++
	w.maxInflight = max(w.maxInflight, w.inflight)
	if w.opened != nil {
		w.maxAhead = max(w.maxAhead, w.started-w.opened())
	}
	if w.inflight >= 2 {
		w.pairOnce.Do(func() { close(w.paired) })
	}
	first, gate := w.started == 1, w.gate
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		w.inflight--
		w.mu.Unlock()
	}()
	if w.pairUp && first {
		select {
		case <-w.paired:
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
	}
	time.Sleep(w.delay)
	switch {
	case w.fail != "" && strings.HasSuffix(key, w.fail):
		rw.Header().Set("Content-Type", "application/xml")
		rw.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(rw, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
	case w.truncate != "" && strings.HasSuffix(key, w.truncate):
		rw.Header().Set("Content-Length", "4096")
		rw.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(rw, `{"time":`)
	default:
		w.inner.ServeHTTP(rw, r)
	}
}

func (w *s3Watch) stats() (inflight, maxInflight, started, maxAhead int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.inflight, w.maxInflight, w.started, w.maxAhead
}

// s3Args points the CLI at the watch with the usual client settings.
func (w *s3Watch) s3Args() []string {
	return []string{"--export", "s3://audit/audit", "--endpoint", w.URL, "--region", "us-east-1", "--path-style"}
}

func watchClient(t *testing.T, w *s3Watch) *s3.Client {
	t.Helper()
	client, err := auditexport.NewS3Client(t.Context(), auditexport.S3Config{Endpoint: w.URL, Region: "us-east-1", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// newDenseAuditNode is newAuditNode for a busy node: n records step apart,
// per records to a batch, so one day holds many batches.
func newDenseAuditNode(id string, start time.Time, n, per int, step time.Duration) *auditNode {
	node := &auditNode{id: id}
	prev := auditlog.GenesisPrevHash
	for i := range n {
		ev := auditlog.Event{Time: start.Add(time.Duration(i) * step), EventID: fmt.Sprintf("%s-%d", id, i), NodeID: id, SandboxID: "sb", Result: "success"}
		auditlog.LinkEvent(prev, &ev)
		prev = ev.EventHash
		node.evs = append(node.evs, ev)
	}
	for start := 0; start < n; start += per {
		end := min(start+per, n)
		last := node.evs[end-1].Time.Add(time.Second)
		batchID := fmt.Sprintf("%s:%d:%x", id, start*512, start)
		node.batches = append(node.batches, auditBatch{key: auditexport.ObjectKey("audit", id, batchID, last), evs: node.evs[start:end], last: last})
	}
	return node
}

func (n *auditNode) putExport(fake *s3fake.Server) {
	for _, b := range n.batches {
		fake.Put("audit", b.key, batchBody(b.evs))
	}
}

// waitUntil polls cond, failing the test after ten seconds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("still waiting after 10s for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func countFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// spoolDirs lists the spool directories the CLI left under TMPDIR.
func spoolDirs(t *testing.T, tmp string) []string {
	t.Helper()
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "aerolvm-audit-verify-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestAuditSearchReadsS3BatchesInParallel is the scaling fix itself: the
// export is downloaded several batches at a time, never more than the
// default concurrency. Read one GET at a time, a node-day of one-second
// batches is hours from outside the region (UC-279 timed out on it).
func TestAuditSearchReadsS3BatchesInParallel(t *testing.T) {
	fake := auditFake(t)
	w := watchS3(t, fake)
	w.pairUp, w.delay = true, time.Millisecond
	start := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Minute)
	node := newDenseAuditNode("node-a", start, 120, 2, time.Minute)
	node.putExport(fake)

	h := newHarness(t)
	args := append([]string{"audit", "search", "--since", start.Format(time.RFC3339), "--node", "node-a", "--json"}, w.s3Args()...)
	if code := h.run(args...); code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, h.stdout.String(), h.stderr.String())
	}
	var rep auditSearchReport
	h.jsonOut(&rep)
	if rep.Result != auditlog.ResultPass || rep.Matched != 120 {
		t.Fatalf("result %s with %d matches, want PASS with 120", rep.Result, rep.Matched)
	}
	_, most, started, _ := w.stats()
	t.Logf("%d GETs for %d batches, at most %d in flight", started, len(node.batches), most)
	if most < 2 {
		t.Fatalf("the export was read one GET at a time (at most %d in flight)", most)
	}
	if most > auditFetchDefaultConcurrency {
		t.Fatalf("%d GETs in flight, more than the default of %d", most, auditFetchDefaultConcurrency)
	}
	// The verifier reads every batch at least twice; S3 sees each once.
	if started != len(node.batches) {
		t.Fatalf("%d GETs for %d batches", started, len(node.batches))
	}
}

// TestAuditFetchConcurrencyFlag: the flag bounds the downloads in flight,
// 1 is the old one-at-a-time reader, and a value out of range is a usage
// error on every verb that reads the export.
func TestAuditFetchConcurrencyFlag(t *testing.T) {
	start := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Minute)
	for _, n := range []int{1, 3} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			fake := auditFake(t)
			w := watchS3(t, fake)
			w.pairUp, w.delay = n > 1, time.Millisecond
			newDenseAuditNode("node-a", start, 120, 2, time.Minute).putExport(fake)
			h := newHarness(t)
			args := append([]string{"audit", "search", "--since", start.Format(time.RFC3339), "--fetch-concurrency", fmt.Sprint(n)}, w.s3Args()...)
			if code := h.run(args...); code != exitOK {
				t.Fatalf("exit %d\nstderr: %s", code, h.stderr.String())
			}
			if _, most, _, _ := w.stats(); most > n || (n > 1 && most < 2) {
				t.Fatalf("--fetch-concurrency %d: %d GETs in flight at most", n, most)
			}
		})
	}
	for _, verb := range [][]string{{"audit", "verify", "--witness", "s3://w"}, {"audit", "search"}, {"access", "review"}} {
		for _, bad := range []string{"0", "257"} {
			h := newHarness(t)
			args := append(append([]string{}, verb...), "--since", "1d", "--export", "s3://a", "--fetch-concurrency", bad)
			if code := h.run(args...); code != exitUsage || !strings.Contains(h.stderr.String(), "--fetch-concurrency must be between 1 and 256") {
				t.Fatalf("%v: exit %d, stderr %s", args, code, h.stderr.String())
			}
		}
	}
}

// TestAuditS3SpoolIsRemovedOnEveryExit: whatever ends the walk (the end of
// the export, a batch that cannot be read, a body cut short, Ctrl-C) the
// downloads in flight are stopped and nothing is left under TMPDIR.
func TestAuditS3SpoolIsRemovedOnEveryExit(t *testing.T) {
	start := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Minute)
	node := newDenseAuditNode("node-a", start, 120, 2, time.Minute)
	mid := node.batches[30].key[strings.LastIndex(node.batches[30].key, "/")+1:]
	cases := []struct {
		name  string
		setup func(w *s3Watch)
		code  int
		want  string
	}{
		{name: "the walk ends", code: exitOK},
		{name: "a batch that cannot be read", setup: func(w *s3Watch) { w.fail = mid }, code: exitError, want: "read export batch"},
		{name: "a batch cut short", setup: func(w *s3Watch) { w.truncate = mid }, code: exitError, want: "unexpected EOF"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			fake := auditFake(t)
			w := watchS3(t, fake)
			node.putExport(fake)
			if c.setup != nil {
				c.setup(w)
			}
			h := newHarness(t)
			args := append([]string{"audit", "search", "--since", start.Format(time.RFC3339), "--fetch-concurrency", "8"}, w.s3Args()...)
			if code := h.run(args...); code != c.code {
				t.Fatalf("exit %d, want %d\nstderr: %s", code, c.code, h.stderr.String())
			}
			if (c.want != "" && !strings.Contains(h.stderr.String(), c.want)) || (c.code != exitOK && !strings.Contains(h.stderr.String(), mid)) {
				t.Fatalf("stderr does not name the batch and %q: %s", c.want, h.stderr.String())
			}
			if left := spoolDirs(t, tmp); len(left) > 0 {
				t.Fatalf("spool left behind: %v", left)
			}
		})
	}

	t.Run("Ctrl-C", func(t *testing.T) {
		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)
		fake := auditFake(t)
		w := watchS3(t, fake)
		node.putExport(fake)
		w.gate = make(chan struct{})
		defer close(w.gate)
		h := newHarness(t)
		args := append([]string{"audit", "search", "--since", start.Format(time.RFC3339), "--fetch-concurrency", "4"}, w.s3Args()...)
		done := make(chan int, 1)
		go func() { done <- h.run(args...) }()
		waitUntil(t, "four GETs in flight", func() bool { n, _, _, _ := w.stats(); return n == 4 })
		if len(spoolDirs(t, tmp)) != 1 {
			t.Fatal("no spool while the walk runs")
		}
		h.interrupt <- os.Interrupt
		select {
		case code := <-done:
			if code != signalExit(os.Interrupt) {
				t.Fatalf("exit %d, want %d\nstderr: %s", code, signalExit(os.Interrupt), h.stderr.String())
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Ctrl-C did not stop the walk")
		}
		if left := spoolDirs(t, tmp); len(left) > 0 {
			t.Fatalf("spool left behind: %v", left)
		}
		waitUntil(t, "the GETs to be abandoned", func() bool { n, _, _, _ := w.stats(); return n == 0 })
	})
}

// TestS3ExportReadAheadIsBounded: with nothing taken, the downloads stop
// at the read-ahead cap; each batch handed over lets exactly one more start; every
// batch is downloaded once and stays spooled for the day's second read; the
// next day drops the spool, and close removes the directory.
func TestS3ExportReadAheadIsBounded(t *testing.T) {
	ctx := t.Context()
	fake := auditFake(t)
	w := watchS3(t, fake)
	day := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
	node := newDenseAuditNode("node-a", day, 120, 2, time.Minute)
	node.putExport(fake)
	const workers = 2
	ahead := auditFetchAheadFactor * workers
	src, done, err := newS3Export(watchClient(t, w), "audit", "audit", day.Add(3*time.Hour), workers)
	if err != nil {
		t.Fatal(err)
	}
	e := src.(*s3Export)
	names, err := e.Batches(ctx, "node-a", "2026-10-16")
	if err != nil || len(names) != len(node.batches) {
		t.Fatalf("listed %d of %d: %v", len(names), len(node.batches), err)
	}
	waitUntil(t, "the read-ahead to fill", func() bool {
		_, _, started, _ := w.stats()
		return started == ahead && countFiles(t, e.dir) == ahead
	})
	time.Sleep(50 * time.Millisecond)
	if _, _, started, _ := w.stats(); started != ahead || countFiles(t, e.dir) != ahead {
		t.Fatalf("with nothing taken: %d GETs and %d spooled files, want %d", started, countFiles(t, e.dir), ahead)
	}
	bodies := map[string]string{}
	for _, b := range node.batches {
		bodies[b.key[strings.LastIndex(b.key, "/")+1:]] = string(batchBody(b.evs))
	}
	for i, name := range names {
		rc, err := e.Open(ctx, "node-a", "2026-10-16", name)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		_ = rc.Close()
		if string(got) != bodies[name] {
			t.Fatalf("batch %s came back changed", name)
		}
		if _, _, started, _ := w.stats(); started > i+1+ahead {
			t.Fatalf("after %d batches taken, %d GETs started: more than %d ahead", i+1, started, ahead)
		}
	}
	if _, _, started, _ := w.stats(); started != len(names) || countFiles(t, e.dir) != len(names) {
		t.Fatalf("%d GETs and %d spooled files for %d batches", started, countFiles(t, e.dir), len(names))
	}
	// The second read (the chain walk) comes from the spool, as does a
	// re-listing of the same day.
	if again, err := e.Batches(ctx, "node-a", "2026-10-16"); err != nil || len(again) != len(names) {
		t.Fatalf("re-listing: %d, %v", len(again), err)
	}
	rc, err := e.Open(ctx, "node-a", "2026-10-16", names[0])
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()
	if _, _, started, _ := w.stats(); started != len(names) {
		t.Fatalf("a spooled batch was downloaded again: %d GETs", started)
	}
	if _, err := e.Batches(ctx, "node-a", "2026-10-17"); err != nil {
		t.Fatal(err)
	}
	if n := countFiles(t, e.dir); n != 0 {
		t.Fatalf("the next day left %d files of the last one", n)
	}
	done()
	if _, err := os.Stat(e.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("spool dir after close: %v", err)
	}
}

// countingSource is the verifier's side of the read-ahead: it counts the
// batches asked for (before the source sees the call) and takes its time
// with each, so the downloads have every chance to run ahead.
type countingSource struct {
	auditlog.ExportSource
	mu     sync.Mutex
	seen   map[string]bool
	opened atomic.Int64
}

func (c *countingSource) Open(ctx context.Context, nodeID, day, name string) (io.ReadCloser, error) {
	c.mu.Lock()
	first := !c.seen[day+"/"+name]
	c.seen[day+"/"+name] = true
	c.mu.Unlock()
	if first {
		c.opened.Add(1)
		time.Sleep(time.Millisecond)
	}
	return c.ExportSource.Open(ctx, nodeID, day, name)
}

// TestS3ExportUnderTheVerifier: driven by the real walk, downloads overlap
// (more than one in flight, never more than the workers), never run more
// than the cap ahead of what the walk has asked for, and each batch is
// fetched once although the walk reads it twice.
func TestS3ExportUnderTheVerifier(t *testing.T) {
	fake := auditFake(t)
	w := watchS3(t, fake)
	w.pairUp, w.delay = true, 2*time.Millisecond
	day := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
	node := newDenseAuditNode("node-a", day, 120, 2, time.Minute)
	node.putExport(fake)
	const workers = 3
	src, done, err := newS3Export(watchClient(t, w), "audit", "audit", day.Add(3*time.Hour), workers)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	cs := &countingSource{ExportSource: src, seen: map[string]bool{}}
	w.opened = func() int { return int(cs.opened.Load()) }
	var matched int
	rep, err := auditlog.SearchNode(t.Context(), auditlog.NodeInput{NodeID: "node-a", Since: day, Now: day.Add(3 * time.Hour), Export: cs, NoWitness: true},
		auditlog.SearchFilter{Since: day}, func(auditlog.Event) { matched++ })
	if err != nil || rep.Result != auditlog.ResultPass || matched != 120 {
		t.Fatalf("result %s, %d matched, err %v", rep.Result, matched, err)
	}
	_, most, started, ahead := w.stats()
	if most < 2 || most > workers {
		t.Fatalf("%d GETs in flight at most, want 2..%d", most, workers)
	}
	if ahead > auditFetchAheadFactor*workers {
		t.Fatalf("downloads ran %d batches ahead of the walk, cap %d", ahead, auditFetchAheadFactor*workers)
	}
	if started != len(node.batches) {
		t.Fatalf("%d GETs for %d batches", started, len(node.batches))
	}
}

// TestS3ExportSameVerdictAndMatchesAsSerial: over the same batches, the
// prefetching S3 reader and the one-file-at-a-time directory reader give
// the same report and the same matches, at any concurrency, for an honest
// export, a tampered batch in the middle of the window, and a batch missing
// from it. The verdict cannot depend on which download finishes first.
func TestS3ExportSameVerdictAndMatchesAsSerial(t *testing.T) {
	start := time.Date(2026, 10, 14, 1, 0, 0, 0, time.UTC)
	since, now := start.Add(6*time.Hour), start.Add(50*time.Hour)
	const mid = 22 // records 132-137, late on the window's first day
	cases := []struct {
		name    string
		mutate  func(n *auditNode, bodies map[string][]byte)
		result  auditlog.Result
		problem string
	}{
		{name: "honest", result: auditlog.ResultPass},
		{
			name: "a tampered batch in the window",
			mutate: func(n *auditNode, bodies map[string][]byte) {
				evs := append([]auditlog.Event(nil), n.batches[mid].evs...)
				evs[2].Result = "denied" // the hash still names "success"
				bodies[n.batches[mid].key] = batchBody(evs)
			},
			result: auditlog.ResultFail, problem: "does not link",
		},
		{
			name:    "a batch missing from the window",
			mutate:  func(n *auditNode, bodies map[string][]byte) { delete(bodies, n.batches[mid].key) },
			result:  auditlog.ResultFail,
			problem: "the export is missing the records between them",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := auditFake(t)
			w := watchS3(t, fake)
			node := newAuditNode("node-a", start, 270)
			bodies := map[string][]byte{}
			for _, b := range node.batches {
				bodies[b.key] = batchBody(b.evs)
			}
			if c.mutate != nil {
				c.mutate(node, bodies)
			}
			root := t.TempDir()
			for key, body := range bodies {
				fake.Put("audit", key, body)
				p := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(key, "audit/")))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, body, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var heads []auditlog.WitnessedHead
			for i := 9; i < len(node.evs); i += 10 {
				heads = append(heads, auditlog.WitnessedHead{HeadHex: node.evs[i].EventHash, At: node.evs[i].Time.Add(20 * time.Second)})
			}
			search := func(src auditlog.ExportSource) (auditlog.NodeReport, []string) {
				t.Helper()
				in := auditlog.NodeInput{NodeID: "node-a", Heads: heads, Since: since, Now: now, MaxLag: time.Hour, Export: src, NewestWitnessDay: now.Format("2006-01-02")}
				var ids []string
				rep, err := auditlog.SearchNode(t.Context(), in, auditlog.SearchFilter{Since: since}, func(ev auditlog.Event) { ids = append(ids, ev.EventID) })
				if err != nil {
					t.Fatal(err)
				}
				return rep, ids
			}
			serial, serialIDs := search(dirExport{root: root, now: now})
			if serial.Result != c.result || (c.problem != "" && !strings.Contains(strings.Join(serial.Problems, "\n"), c.problem)) {
				t.Fatalf("serial reader: %s %v, want %s mentioning %q", serial.Result, serial.Problems, c.result, c.problem)
			}
			client := watchClient(t, w)
			for _, n := range []int{1, 4, auditFetchDefaultConcurrency} {
				src, done, err := newS3Export(client, "audit", "audit", now, n)
				if err != nil {
					t.Fatal(err)
				}
				rep, ids := search(src)
				done()
				if !reflect.DeepEqual(rep, serial) {
					a, _ := json.Marshal(rep)
					b, _ := json.Marshal(serial)
					t.Fatalf("concurrency %d: report differs from the serial reader\n got %s\nwant %s", n, a, b)
				}
				if !reflect.DeepEqual(ids, serialIDs) {
					t.Fatalf("concurrency %d: %d matches, serial %d", n, len(ids), len(serialIDs))
				}
			}
		})
	}
}

// TestS3ExportEdges covers what the walk never does but the source still
// handles: a batch of another day, a batch added after the listing, a batch
// asked for before its turn to be downloaded, a wait the caller abandons,
// and close while downloads are stuck or the read-ahead is full.
func TestS3ExportEdges(t *testing.T) {
	ctx := t.Context()
	day := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
	node := newDenseAuditNode("node-a", day, 40, 2, time.Minute)
	var fake *s3fake.Server
	setup := func(t *testing.T, workers int) (*s3Watch, *s3Export, func(), []string) {
		fake = auditFake(t)
		w := watchS3(t, fake)
		node.putExport(fake)
		src, done, err := newS3Export(watchClient(t, w), "audit", "audit", day.Add(3*time.Hour), workers)
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, len(node.batches))
		for i, b := range node.batches {
			names[i] = b.key[strings.LastIndex(b.key, "/")+1:]
		}
		return w, src.(*s3Export), done, names
	}

	t.Run("another day is read through and not kept", func(t *testing.T) {
		_, e, done, names := setup(t, 2)
		defer done()
		rc, err := e.Open(ctx, "node-a", "2026-10-16", names[3])
		if err != nil {
			t.Fatal(err)
		}
		if countFiles(t, e.dir) != 1 {
			t.Fatal("the batch was not read through a file")
		}
		if err := rc.Close(); err != nil || countFiles(t, e.dir) != 0 {
			t.Fatalf("close: %v, %d files left", err, countFiles(t, e.dir))
		}
		if _, err := e.Open(ctx, "node-a", "not-a-day", names[3]); err == nil {
			t.Fatal("a bad day was read")
		}
		if _, err := e.Batches(ctx, "node-a", "not-a-day"); err == nil {
			t.Fatal("a bad day was listed")
		}
	})

	t.Run("a batch the listing missed, and one taken before its turn", func(t *testing.T) {
		w, e, done, names := setup(t, 1)
		defer done()
		listed, err := e.Batches(ctx, "node-a", "2026-10-16")
		if err != nil || len(listed) != len(names) {
			t.Fatal(listed, err)
		}
		// The last batch, asked for first, is downloaded here; the workers
		// are never handed it.
		rc, err := e.Open(ctx, "node-a", "2026-10-16", listed[len(listed)-1])
		if err != nil {
			t.Fatal(err)
		}
		_ = rc.Close()
		late := auditexport.ObjectKey("audit", "node-a", "node-a:999999:late", day.Add(2*time.Hour))
		fake.Put("audit", late, batchBody(node.evs[:1]))
		lateName := late[strings.LastIndex(late, "/")+1:]
		for _, name := range append(listed, lateName) {
			rc, err := e.Open(ctx, "node-a", "2026-10-16", name)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			_ = rc.Close()
		}
		if _, _, started, _ := w.stats(); started != len(listed)+1 {
			t.Fatalf("%d GETs for %d batches", started, len(listed)+1)
		}
	})

	t.Run("a failed download fails every read of it and leaves no file", func(t *testing.T) {
		w, e, done, names := setup(t, 2)
		defer done()
		w.fail = names[1]
		if _, err := e.Batches(ctx, "node-a", "2026-10-16"); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if _, err := e.Open(ctx, "node-a", "2026-10-16", names[1]); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
				t.Fatalf("read %d: %v", i, err)
			}
		}
		rc, err := e.Open(ctx, "node-a", "2026-10-16", names[0])
		if err != nil {
			t.Fatalf("a good batch next to a bad one: %v", err)
		}
		_ = rc.Close()
		// Without a spool directory, a download has nowhere to go.
		gone := &s3Export{api: e.api, bucket: "audit", prefix: "audit", dir: filepath.Join(t.TempDir(), "gone")}
		if _, err := gone.fetch(ctx, "node-a", "2026-10-16", names[2]); err == nil {
			t.Fatal("a download with no spool directory succeeded")
		}
	})

	t.Run("a wait the caller gives up", func(t *testing.T) {
		w, e, done, _ := setup(t, 1)
		defer done()
		w.gate = make(chan struct{})
		defer close(w.gate)
		listed, _ := e.Batches(ctx, "node-a", "2026-10-16")
		waitUntil(t, "the first GET", func() bool { n, _, _, _ := w.stats(); return n == 1 })
		short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
		if _, err := e.Open(short, "node-a", "2026-10-16", listed[0]); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err %v, want the caller's deadline", err)
		}
	})

	t.Run("close while downloads are stuck", func(t *testing.T) {
		w, e, done, _ := setup(t, 1)
		w.gate = make(chan struct{})
		defer close(w.gate)
		if _, err := e.Batches(ctx, "node-a", "2026-10-16"); err != nil {
			t.Fatal(err)
		}
		// One worker holds the first batch; the second waits in the queue.
		waitUntil(t, "the first GET", func() bool { n, _, _, _ := w.stats(); return n == 1 })
		closed := make(chan struct{})
		go func() { done(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(10 * time.Second):
			t.Fatal("close waited on a stuck download")
		}
		if _, err := os.Stat(e.dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("spool dir after close: %v", err)
		}
	})

	t.Run("close with the read-ahead full", func(t *testing.T) {
		w, e, done, _ := setup(t, 1)
		if _, err := e.Batches(ctx, "node-a", "2026-10-16"); err != nil {
			t.Fatal(err)
		}
		waitUntil(t, "the read-ahead to fill", func() bool {
			_, _, started, _ := w.stats()
			return started == auditFetchAheadFactor && countFiles(t, e.dir) == auditFetchAheadFactor
		})
		done()
		if _, err := os.Stat(e.dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("spool dir after close: %v", err)
		}
	})

	t.Run("a listing that fails", func(t *testing.T) {
		_, e, done, _ := setup(t, 1)
		defer done()
		e.bucket = "missing"
		if _, err := e.Batches(ctx, "node-a", "2026-10-16"); err == nil || !strings.Contains(err.Error(), "list s3://missing/") {
			t.Fatalf("err %v", err)
		}
	})
}
