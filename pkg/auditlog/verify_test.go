package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"
	"time"
)

// memExport is an export store in memory, in the export layout: one map of
// batches per UTC day.
type memExport struct {
	days    map[string]map[string][]byte
	opens   int
	openErr error
}

func newMemExport() *memExport { return &memExport{days: map[string]map[string][]byte{}} }

func (m *memExport) put(day, name string, evs []Event) {
	if m.days[day] == nil {
		m.days[day] = map[string][]byte{}
	}
	m.days[day][name] = ndjson(evs)
}

func (m *memExport) putRaw(day, name string, body []byte) {
	if m.days[day] == nil {
		m.days[day] = map[string][]byte{}
	}
	m.days[day][name] = body
}

func (m *memExport) drop(day, name string) { delete(m.days[day], name) }

func (m *memExport) Days(_ context.Context, _, from string) ([]string, error) {
	var out []string
	for d := range m.days {
		if d >= from {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memExport) Batches(_ context.Context, _, day string) ([]string, error) {
	var out []string
	for n := range m.days[day] {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (m *memExport) Open(_ context.Context, _, day, name string) (io.ReadCloser, error) {
	m.opens++
	if m.openErr != nil {
		return nil, m.openErr
	}
	b, ok := m.days[day][name]
	if !ok {
		return nil, fmt.Errorf("no batch %s/%s", day, name)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func ndjson(evs []Event) []byte {
	var buf bytes.Buffer
	for _, ev := range evs {
		raw, _ := json.Marshal(ev)
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

var t0 = time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)

// chainFrom builds n linked records after prev, one every step from start.
func chainFrom(prev string, n int, start time.Time, step time.Duration, tag string) []Event {
	evs := make([]Event, n)
	for i := range evs {
		ev := Event{Time: start.Add(time.Duration(i) * step), EventID: fmt.Sprintf("%s-%d", tag, i), SandboxID: "sb", Result: "success"}
		LinkEvent(prev, &ev)
		prev = ev.EventHash
		evs[i] = ev
	}
	return evs
}

// history is a node's honest records, their export, and the heads a
// witness recorded every tenth record (each shipped twice, the way a daily
// re-ship or a repair repeats an unchanged head).
type history struct {
	evs    []Event
	export *memExport
	heads  []WitnessedHead
	// batchOf maps a record index to its batch's day and name.
	batchOf map[int][2]string
}

func newHistory(n, batch int) *history {
	h := &history{evs: chainFrom(GenesisPrevHash, n, t0, 15*time.Minute, "r"), export: newMemExport(), batchOf: map[int][2]string{}}
	for start := 0; start < n; start += batch {
		end := min(start+batch, n)
		last := h.evs[end-1]
		day := last.Time.UTC().Format("2006-01-02")
		// Offsets restart every 40 records, the way a retention prune
		// re-pins the export cursor, so names sort out of chain order.
		name := fmt.Sprintf("node-a_%d_%04x.jsonl", (start%40)*1000+999, start)
		h.export.put(day, name, h.evs[start:end])
		for i := start; i < end; i++ {
			h.batchOf[i] = [2]string{day, name}
		}
	}
	for i := 9; i < n; i += 10 {
		w := WitnessedHead{HeadHex: h.evs[i].EventHash, At: h.evs[i].Time.Add(20 * time.Second), Ref: fmt.Sprintf("head %d", i)}
		h.heads = append(h.heads, w, WitnessedHead{HeadHex: w.HeadHex, At: w.At.Add(30 * time.Second), Ref: w.Ref + " again"})
	}
	return h
}

func (h *history) input() NodeInput {
	return NodeInput{
		NodeID:           "node-a",
		Heads:            h.heads,
		Since:            t0.Add(12 * time.Hour),
		Now:              h.evs[len(h.evs)-1].Time.Add(5 * time.Minute),
		MaxLag:           15 * time.Minute,
		Export:           h.export,
		NewestWitnessDay: h.evs[len(h.evs)-1].Time.UTC().Format("2006-01-02"),
	}
}

func verify(t *testing.T, in NodeInput) NodeReport {
	t.Helper()
	rep, err := VerifyNode(context.Background(), in)
	if err != nil {
		t.Fatalf("VerifyNode: %v", err)
	}
	return rep
}

func wantResult(t *testing.T, rep NodeReport, want Result, problem string) {
	t.Helper()
	if rep.Result != want {
		t.Fatalf("result = %s, want %s; problems %q warnings %q pending %+v", rep.Result, want, rep.Problems, rep.Warnings, rep.Pending)
	}
	if problem != "" && !strings.Contains(strings.Join(rep.Problems, "\n"), problem) {
		t.Fatalf("problems %q do not mention %q", rep.Problems, problem)
	}
}

func headAt(evs []Event, i int, after time.Duration, ref string) WitnessedHead {
	return WitnessedHead{HeadHex: evs[i].EventHash, At: evs[i].Time.Add(after), Ref: ref}
}

func TestVerifyHonestHistoryAcrossDaysAndPrunes(t *testing.T) {
	h := newHistory(300, 7)
	rep := verify(t, h.input())
	wantResult(t, rep, ResultPass, "")
	if rep.HeadsLinked != rep.HeadsInWindow || rep.HeadsInWindow == 0 || rep.HeadsBeforeWindow == 0 {
		t.Fatalf("heads: %d of %d linked, %d before window", rep.HeadsLinked, rep.HeadsInWindow, rep.HeadsBeforeWindow)
	}
	if rep.UnreachedBatches != 0 || len(rep.Warnings) != 0 || rep.Silent {
		t.Fatalf("unreached=%d warnings=%q silent=%v", rep.UnreachedBatches, rep.Warnings, rep.Silent)
	}
	if rep.EvidenceFrom == nil || rep.EvidenceTo == nil || rep.RecordsChecked == 0 {
		t.Fatalf("evidence window not reported: %+v", rep)
	}
}

// A batch re-sent after midnight lands in the next day's prefix. It is a
// copy of records already checked, not new evidence and not a gap.
func TestVerifyBatchResentAfterMidnight(t *testing.T) {
	h := newHistory(300, 7)
	day1 := t0.Format("2006-01-02")
	var lastName string
	for n := range h.export.days[day1] {
		if lastName == "" || h.export.days[day1][n] != nil && bytes.Contains(h.export.days[day1][n], []byte(h.lastEventOn(day1).EventID+`"`)) {
			lastName = n
		}
	}
	day2 := t0.AddDate(0, 0, 1).Format("2006-01-02")
	h.export.putRaw(day2, "resent_"+lastName, h.export.days[day1][lastName])
	rep := verify(t, h.input())
	wantResult(t, rep, ResultPass, "")
	if rep.UnreachedBatches != 1 {
		t.Fatalf("unreached batches = %d, want the one re-send", rep.UnreachedBatches)
	}
}

func (h *history) lastEventOn(day string) Event {
	var last Event
	for _, ev := range h.evs {
		if ev.Time.UTC().Format("2006-01-02") == day {
			last = ev
		}
	}
	return last
}

// A re-export after a cursor reset cuts batches at new offsets: the record
// after the tip sits in the middle of a batch that starts earlier.
func TestVerifyOverlappingReExport(t *testing.T) {
	h := newHistory(300, 7)
	k := 150
	day, name := h.batchOf[k][0], h.batchOf[k][1]
	// The batch holding record k is lost; a later re-export covers records
	// k-3 .. k+20 in one batch that starts before the tip.
	start := k
	for start > 0 && h.batchOf[start-1] == h.batchOf[k] {
		start--
	}
	h.export.drop(day, name)
	h.export.put(day, "reexport_0_ffff.jsonl", h.evs[start-3:start+20])
	rep := verify(t, h.input())
	wantResult(t, rep, ResultPass, "")
}

func TestVerifyForgedNewerHead(t *testing.T) {
	h := newHistory(300, 7)
	forged := chainFrom(h.evs[200].EventHash, 1, h.evs[201].Time, time.Minute, "forged")[0]
	h.heads = append(h.heads, WitnessedHead{HeadHex: forged.EventHash, At: h.evs[205].Time, Ref: "forged"})
	sort.SliceStable(h.heads, func(i, j int) bool { return h.heads[i].At.Before(h.heads[j].At) })
	rep := verify(t, h.input())
	wantResult(t, rep, ResultFail, "forged")
}

func TestVerifyRollbackToOlderHead(t *testing.T) {
	h := newHistory(300, 7)
	old := headAt(h.evs, 99, 0, "old")
	old.At = h.evs[250].Time
	h.heads = append(h.heads, old)
	sort.SliceStable(h.heads, func(i, j int) bool { return h.heads[i].At.Before(h.heads[j].At) })
	rep := verify(t, h.input())
	wantResult(t, rep, ResultFail, "already passed on the chain")
}

func TestVerifyMissingLink(t *testing.T) {
	h := newHistory(300, 7)
	// Lose every batch that holds records 140..160 and nothing re-exports
	// them: the heads on either side are not linked.
	for i := 140; i <= 160; i++ {
		h.export.drop(h.batchOf[i][0], h.batchOf[i][1])
	}
	rep := verify(t, h.input())
	wantResult(t, rep, ResultFail, "")
	all := strings.Join(rep.Problems, "\n")
	if !strings.Contains(all, "no records link") && !strings.Contains(all, "is not on the chain before head") {
		t.Fatalf("problems %q name no missing link", rep.Problems)
	}
	if len(rep.Warnings) == 0 {
		t.Fatal("the gap must be reported")
	}
}

// Deleting the oldest exports inside the window must not shrink what gets
// checked: the window is the auditor's, not the evidence's (D22).
func TestVerifyRemovedEarlyExportsInsideWindow(t *testing.T) {
	h := newHistory(300, 7)
	day2 := t0.AddDate(0, 0, 1).Format("2006-01-02")
	for _, d := range []string{t0.Format("2006-01-02"), day2} {
		delete(h.export.days, d)
	}
	rep := verify(t, h.input())
	wantResult(t, rep, ResultFail, "is not on the chain before head")
}

func TestVerifyStalledExport(t *testing.T) {
	cases := []struct {
		name string
		// lost is how many trailing records never reached the export.
		lost int
		now  time.Duration
		want Result
	}{
		{"last batch not exported yet", 4, 5 * time.Minute, ResultPass},
		{"last batch waiting past the lag", 4, 2 * time.Hour, ResultIncomplete},
		{"export stalled for hours", 40, 5 * time.Minute, ResultIncomplete},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHistory(300, 7)
			for i := 300 - c.lost; i < 300; i++ {
				h.export.drop(h.batchOf[i][0], h.batchOf[i][1])
			}
			in := h.input()
			in.Now = h.evs[299].Time.Add(c.now)
			rep := verify(t, in)
			wantResult(t, rep, c.want, "")
			if len(rep.Pending) == 0 {
				t.Fatal("heads beyond the export must be pending")
			}
		})
	}
}

func TestVerifyLocalLogContinuesTheExport(t *testing.T) {
	h := newHistory(300, 7)
	for i := 260; i < 300; i++ {
		h.export.drop(h.batchOf[i][0], h.batchOf[i][1])
	}
	// The local log after a prune: a checkpoint naming the last dropped
	// record, then the retained records, overlapping the export.
	cp := Event{Time: h.evs[200].Time, EventID: "cp", Kind: KindRetentionCheckpoint, Result: "success"}
	LinkEvent(h.evs[199].EventHash, &cp)
	local := ndjson(append([]Event{cp}, h.evs[200:]...))
	in := h.input()
	in.Now = h.evs[299].Time.Add(2 * time.Hour)
	in.Local = bytes.NewReader(local)
	rep := verify(t, in)
	wantResult(t, rep, ResultPass, "")
	if len(rep.Pending) != 0 {
		t.Fatalf("the local log covers the tail; pending %+v", rep.Pending)
	}

	// A torn last line from a copy taken mid-write is ignored with a note.
	in.Local = bytes.NewReader(append(append([]byte{}, local...), []byte(`{"time":"2026`)...))
	rep = verify(t, in)
	wantResult(t, rep, ResultPass, "")
	if len(rep.Warnings) == 0 {
		t.Fatal("a torn tail must be noted")
	}
}

// A forged retention checkpoint followed by a rewritten tail verifies on
// the node, but it does not continue the exported chain (D5).
func TestVerifyForgedCheckpointAndRewrittenTail(t *testing.T) {
	h := newHistory(300, 7)
	for i := 260; i < 300; i++ {
		h.export.drop(h.batchOf[i][0], h.batchOf[i][1])
	}
	cp := Event{Time: h.evs[200].Time, EventID: "cp", Kind: KindRetentionCheckpoint, Result: "success"}
	LinkEvent(h.evs[199].EventHash, &cp)
	rewritten := chainFrom(h.evs[199].EventHash, 100, h.evs[200].Time, 15*time.Minute, "rewritten")
	in := h.input()
	in.Local = bytes.NewReader(ndjson(append([]Event{cp}, rewritten...)))
	in.Heads = append(in.Heads, WitnessedHead{HeadHex: rewritten[99].EventHash, At: rewritten[99].Time.Add(time.Minute), Ref: "rewritten head"})
	rep := verify(t, in)
	wantResult(t, rep, ResultFail, "does not continue the exported chain")
}

func TestVerifyExportFork(t *testing.T) {
	h := newHistory(300, 7)
	k := 99 // record 100 starts a batch: 98 = 14*7, so 98..104 is one batch
	for k%7 != 6 {
		k++
	}
	forged := chainFrom(h.evs[k].EventHash, 5, h.evs[k+1].Time, time.Minute, "fork")
	h.export.put(h.batchOf[k+1][0], "zzz_fork.jsonl", forged)
	rep := verify(t, h.input())
	wantResult(t, rep, ResultFail, "forks")
}

func TestVerifyUnchangedHeadsNeedNoRecords(t *testing.T) {
	evs := chainFrom(GenesisPrevHash, 3, t0, time.Minute, "idle")
	prior := headAt(evs, 2, time.Minute, "before the window")
	since := t0.AddDate(0, 0, 5)
	var heads []WitnessedHead
	for d := 0; d < 3; d++ {
		heads = append(heads, WitnessedHead{HeadHex: prior.HeadHex, At: since.AddDate(0, 0, d).Add(time.Minute), Ref: "daily re-ship"})
	}
	in := NodeInput{NodeID: "n", Heads: heads, Prior: &prior, Since: since, Now: since.AddDate(0, 0, 2).Add(time.Hour), MaxLag: 15 * time.Minute, Export: newMemExport(), NewestWitnessDay: since.AddDate(0, 0, 2).Format("2006-01-02")}
	rep := verify(t, in)
	wantResult(t, rep, ResultPass, "")
	if rep.HeadsLinked != 3 {
		t.Fatalf("linked = %d", rep.HeadsLinked)
	}
	// Without the prior head the first one needs records, and there are
	// none: it waits, and past the lag the result is incomplete.
	in.Prior = nil
	wantResult(t, verify(t, in), ResultIncomplete, "")
}

func TestVerifyHiddenKeysAndSilentNode(t *testing.T) {
	h := newHistory(300, 7)
	in := h.input()
	in.HiddenKeys = []string{"witness/node=node-a/day=2026-10-09/head.json"}
	wantResult(t, verify(t, in), ResultFail, "delete marker")

	in = h.input()
	in.NewestWitnessDay = t0.Format("2006-01-02")
	in.Now = t0.AddDate(0, 0, 9)
	rep := verify(t, in)
	if !rep.Silent || len(rep.Warnings) == 0 {
		t.Fatalf("silent = %v warnings %q", rep.Silent, rep.Warnings)
	}
	in.NewestWitnessDay = ""
	if rep := verify(t, in); !rep.Silent {
		t.Fatal("a node with no heads at all is silent")
	}
}

func TestVerifyCorruptEvidence(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(h *history, in *NodeInput)
		want    string
	}{
		{"malformed export line", func(h *history, _ *NodeInput) {
			h.export.putRaw(h.batchOf[150][0], h.batchOf[150][1], []byte("not json\n"))
		}, "not a JSON event"},
		{"oversized export line", func(h *history, _ *NodeInput) {
			h.export.putRaw(h.batchOf[150][0], h.batchOf[150][1], append(bytes.Repeat([]byte("a"), MaxLineBytes+1), '\n'))
		}, "longer than"},
		{"record that does not link", func(h *history, _ *NodeInput) {
			bad := h.evs[150]
			bad.Result = "tampered"
			evs := []Event{}
			for i := 0; i < len(h.evs); i++ {
				if h.batchOf[i] == h.batchOf[150] {
					if i == 150 {
						evs = append(evs, bad)
					} else {
						evs = append(evs, h.evs[i])
					}
				}
			}
			h.export.put(h.batchOf[150][0], h.batchOf[150][1], evs)
		}, "does not link"},
		{"malformed local line", func(_ *history, in *NodeInput) {
			in.Local = strings.NewReader("garbage\n")
		}, "local log: line 1"},
		{"oversized local line", func(_ *history, in *NodeInput) {
			in.Local = bytes.NewReader(append(bytes.Repeat([]byte("a"), MaxLineBytes+1), '\n'))
		}, "local log: line 1 is longer"},
		{"forged checkpoint hash", func(h *history, in *NodeInput) {
			cp := Event{Time: h.evs[200].Time, EventID: "cp", Kind: KindRetentionCheckpoint, Result: "success", PrevHash: h.evs[199].EventHash, EventHash: "bad"}
			in.Local = bytes.NewReader(ndjson([]Event{cp}))
		}, "wrong event_hash"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHistory(300, 7)
			in := h.input()
			c.corrupt(h, &in)
			wantResult(t, verify(t, in), ResultFail, c.want)
		})
	}
}

func TestVerifyReadErrors(t *testing.T) {
	h := newHistory(30, 7)
	h.export.openErr = errors.New("s3 down")
	if _, err := VerifyNode(context.Background(), h.input()); err == nil || !strings.Contains(err.Error(), "s3 down") {
		t.Fatalf("err = %v", err)
	}
	in := h.input()
	in.Export = failingExport{days: true}
	if _, err := VerifyNode(context.Background(), in); err == nil {
		t.Fatal("a Days error must be returned")
	}
	in.Export = failingExport{}
	if _, err := VerifyNode(context.Background(), in); err == nil {
		t.Fatal("a Batches error must be returned")
	}
	in = h.input()
	in.Export = nil
	in.Local = errReader{}
	if _, err := VerifyNode(context.Background(), in); err == nil {
		t.Fatal("a local read error must be returned")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyNode(ctx, h.input()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

type failingExport struct{ days bool }

func (f failingExport) Days(context.Context, string, string) ([]string, error) {
	if f.days {
		return nil, errors.New("list days")
	}
	return []string{"2026-10-08"}, nil
}
func (failingExport) Batches(context.Context, string, string) ([]string, error) {
	return nil, errors.New("list batches")
}
func (failingExport) Open(context.Context, string, string, string) (io.ReadCloser, error) {
	return nil, errors.New("open")
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("disk gone") }

// With no export at all the local log is the whole evidence, read from its
// leading checkpoint by the daemon's own rules.
func TestVerifyLocalOnly(t *testing.T) {
	h := newHistory(300, 7)
	cp := Event{Time: h.evs[0].Time, EventID: "cp", Kind: KindRetentionCheckpoint, Result: "success"}
	LinkEvent(GenesisPrevHash, &cp)
	in := h.input()
	in.Export = nil
	in.Local = bytes.NewReader(ndjson(append([]Event{cp}, h.evs...)))
	wantResult(t, verify(t, in), ResultPass, "")
}

// A generation re-exported from its first byte starts with the checkpoint;
// when it is the only batch holding the next records, the walk uses it.
func TestVerifyCheckpointFirstBatchContinuesTheChain(t *testing.T) {
	evs := chainFrom(GenesisPrevHash, 40, t0, time.Minute, "c")
	ex := newMemExport()
	day := t0.Format("2006-01-02")
	ex.put(day, "a.jsonl", evs[:20])
	cp := Event{Time: evs[19].Time, EventID: "cp", Kind: KindRetentionCheckpoint, Result: "success"}
	LinkEvent(evs[19].EventHash, &cp)
	ex.put(day, "b.jsonl", append([]Event{cp}, evs[20:]...))
	heads := []WitnessedHead{headAt(evs, 10, time.Minute, ""), headAt(evs, 39, time.Minute, "")}
	in := NodeInput{NodeID: "n", Heads: heads, Since: t0, Now: evs[39].Time.Add(time.Minute), MaxLag: time.Hour, Export: ex, NewestWitnessDay: day}
	wantResult(t, verify(t, in), ResultPass, "")
}

// Memory follows one day's batches, never the history: the index holds a
// day's batch ends and records stream through the chain verifier.
func TestVerifyMemoryIsBoundedByOneDay(t *testing.T) {
	h := newHistory(20000, 10) // ~208 days at one record every 15 minutes
	in := h.input()
	in.Since = t0
	v := newNodeVerifier(in)
	if err := v.walkExport(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.finish()
	wantResult(t, v.rep, ResultPass, "")
	perDay := 0
	for _, batches := range h.export.days {
		perDay = max(perDay, len(batches))
	}
	if v.peakIndexed > perDay || perDay > 12 {
		t.Fatalf("indexed %d batches at once; one day holds %d", v.peakIndexed, perDay)
	}
	if v.rep.RecordsChecked != 20000 {
		t.Fatalf("records checked = %d", v.rep.RecordsChecked)
	}
}

// Evidence that begins with a re-exported generation starts at its
// checkpoint: the walk steps over it and starts at the record after.
func TestVerifyEvidenceStartingWithCheckpoint(t *testing.T) {
	evs := chainFrom(GenesisPrevHash, 30, t0, time.Minute, "s")
	cp := Event{Time: evs[9].Time, EventID: "cp", Kind: KindRetentionCheckpoint, Result: "success"}
	LinkEvent(evs[9].EventHash, &cp)
	ex := newMemExport()
	day := t0.Format("2006-01-02")
	ex.put(day, "only.jsonl", append([]Event{cp}, evs[10:]...))
	heads := []WitnessedHead{headAt(evs, 15, time.Minute, ""), headAt(evs, 29, time.Minute, "")}
	in := NodeInput{NodeID: "n", Heads: heads, Since: t0, Now: evs[29].Time.Add(time.Minute), MaxLag: time.Hour, Export: ex, NewestWitnessDay: day}
	rep := verify(t, in)
	wantResult(t, rep, ResultPass, "")
	if rep.RecordsChecked != 20 {
		t.Fatalf("records = %d", rep.RecordsChecked)
	}
}

// A badly broken history still yields a readable report.
func TestVerifyCapsTheProblemList(t *testing.T) {
	h := newHistory(30, 7)
	in := h.input()
	for i := 0; i < maxProblems+10; i++ {
		in.HiddenKeys = append(in.HiddenKeys, fmt.Sprintf("k%d", i))
	}
	rep := verify(t, in)
	wantResult(t, rep, ResultFail, "and 10 more problems")
	if len(rep.Problems) != maxProblems+1 {
		t.Fatalf("problems listed = %d", len(rep.Problems))
	}
}
