package auditlog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// linked returns events chained from prev in order, each EventHash set.
func linked(prev string, events ...Event) []Event {
	out := make([]Event, len(events))
	for i, ev := range events {
		LinkEvent(prev, &ev)
		out[i] = ev
		prev = ev.EventHash
	}
	return out
}

func rec(id string) Event {
	return Event{Time: time.Unix(1_700_000_000, 0).UTC(), EventID: id, SandboxID: "sb-1", Actor: "alice", Result: "success"}
}

func jsonLine(t *testing.T, ev Event) []byte {
	t.Helper()
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func jsonLines(t *testing.T, events ...Event) []byte {
	t.Helper()
	var buf []byte
	for _, ev := range events {
		buf = append(buf, jsonLine(t, ev)...)
	}
	return buf
}

func TestChainVerifierLinkRules(t *testing.T) {
	g := linked(GenesisPrevHash, rec("a"), rec("b"), rec("c"))
	stubB := RedactForRetention(g[1])

	checkpoint := Event{EventID: "cp", Kind: KindRetentionCheckpoint, Result: "success", WitnessedThrough: "wt"}
	LinkEvent(strings.Repeat("d", 64), &checkpoint) // names a dropped predecessor
	afterCP := linked(strings.Repeat("e", 64), rec("kept-1"))[0]
	afterCP2 := linked(afterCP.EventHash, rec("kept-2"))[0]
	breakAgain := linked(strings.Repeat("f", 64), rec("break-again"))[0]

	tampered := g[1]
	tampered.SandboxID = "sb-2"
	smuggled := stubB
	smuggled.Actor = "alice"
	misplacedStub := stubB
	misplacedStub.PrevHash = "deadbeef"
	stubAfterCP := RedactForRetention(afterCP)
	stubAfterCPNext := linked(stubAfterCP.EventHash, rec("after-stub"))[0]
	lateCheckpoint := checkpoint
	LinkEvent(g[0].EventHash, &lateCheckpoint)
	notFromGenesis := linked(strings.Repeat("a", 64), rec("orphan"))[0]
	noPrev := g[0]
	noPrev.PrevHash = "  "
	noHash := g[0]
	noHash.EventHash = ""
	stubNoHash := stubB
	stubNoHash.EventHash = ""

	cases := []struct {
		name    string
		events  []Event
		failAt  int // index of the first rejected event; -1 when all pass
		wantErr string
	}{
		{"genesis chain", g, -1, ""},
		{"stub in place of a record", []Event{g[0], stubB, g[2]}, -1, ""},
		{"leading checkpoint bridges the dropped prefix once", []Event{checkpoint, afterCP, afterCP2}, -1, ""},
		{"stub right after a checkpoint may bridge too", []Event{checkpoint, stubAfterCP, stubAfterCPNext}, -1, ""},
		{"missing prev_hash is not a legacy format", []Event{noPrev}, 0, "prev_hash is missing"},
		{"missing event_hash", []Event{noHash}, 0, "event_hash is missing"},
		{"stub without event_hash", []Event{g[0], stubNoHash}, 1, "event_hash is missing"},
		{"tampered payload", []Event{g[0], tampered}, 1, "event_hash mismatch"},
		{"first record must start at genesis", []Event{notFromGenesis}, 0, "prev_hash mismatch"},
		{"skipped record", []Event{g[0], g[2]}, 1, "prev_hash mismatch"},
		{"break allowed only once after a checkpoint", []Event{checkpoint, afterCP, breakAgain}, 2, "prev_hash mismatch"},
		{"checkpoint after a record", []Event{g[0], lateCheckpoint}, 1, "retention checkpoint must be the first event"},
		{"checkpoint after a stub", []Event{g[0], stubB, lateCheckpoint}, 2, "retention checkpoint must be the first event"},
		{"stub with payload is a forgery", []Event{g[0], smuggled}, 1, "retention stub carries payload"},
		{"stub off its position", []Event{g[0], misplacedStub}, 1, "prev_hash mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewChainVerifier()
			for i, ev := range tc.events {
				err := v.Add(ev)
				if i == tc.failAt {
					if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
						t.Fatalf("event %d: err = %v, want %q", i, err, tc.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatalf("event %d: %v", i, err)
				}
				if v.Head() != ev.EventHash {
					t.Fatalf("event %d: head = %q, want %q", i, v.Head(), ev.EventHash)
				}
				if want := ev.Kind == KindRetentionCheckpoint; v.AllowBreak() != want {
					t.Fatalf("event %d: allowBreak = %v, want %v", i, v.AllowBreak(), want)
				}
			}
			if tc.failAt >= 0 {
				t.Fatalf("event %d accepted, want %q", tc.failAt, tc.wantErr)
			}
		})
	}
}

func TestChainVerifierNilAndGenesis(t *testing.T) {
	var nilV *ChainVerifier
	if err := nilV.Add(rec("x")); err == nil || err.Error() != "secret audit chain verifier unavailable" {
		t.Fatalf("nil Add = %v", err)
	}
	if nilV.Head() != "" || nilV.AllowBreak() {
		t.Fatal("nil verifier reports state")
	}
	v := NewChainVerifier()
	if v.Head() != GenesisPrevHash || v.AllowBreak() {
		t.Fatalf("fresh verifier head=%q allowBreak=%v", v.Head(), v.AllowBreak())
	}
}

// A resumed verifier must behave exactly as one that read the prefix: same
// head, same one-shot break after a checkpoint, and no second checkpoint.
func TestResumeChainVerifier(t *testing.T) {
	g := linked(GenesisPrevHash, rec("a"), rec("b"))
	checkpoint := Event{EventID: "cp", Kind: KindRetentionCheckpoint, Result: "success"}
	LinkEvent(g[1].EventHash, &checkpoint)
	bridge := linked(strings.Repeat("c", 64), rec("bridge"))[0]

	v := ResumeChainVerifier(g[0].EventHash, false)
	if v.Head() != g[0].EventHash || v.AllowBreak() {
		t.Fatalf("resumed head=%q allowBreak=%v", v.Head(), v.AllowBreak())
	}
	if err := v.Add(g[1]); err != nil {
		t.Fatalf("resumed link: %v", err)
	}
	// The resumed state already stands for a verified prefix, so even the
	// very next record may not be a checkpoint: that would let a forged
	// checkpoint at a resume point bridge to anything.
	for _, primed := range []ChainVerifier{ResumeChainVerifier(g[1].EventHash, false), ResumeChainVerifier(g[1].EventHash, true)} {
		if err := primed.Add(checkpoint); err == nil || !strings.Contains(err.Error(), "first event") {
			t.Fatalf("checkpoint right after resume = %v", err)
		}
	}

	broken := ResumeChainVerifier(g[0].EventHash, false)
	if err := broken.Add(bridge); err == nil || !strings.Contains(err.Error(), "prev_hash mismatch") {
		t.Fatalf("resume without break accepted a break: %v", err)
	}
	afterCP := ResumeChainVerifier(checkpoint.EventHash, true)
	if err := afterCP.Add(bridge); err != nil {
		t.Fatalf("resume after checkpoint refused the bridge: %v", err)
	}
	if afterCP.AllowBreak() {
		t.Fatal("break survived past the first record")
	}
}

func TestRedactForRetentionKeepsOnlyLinks(t *testing.T) {
	ev := linked(GenesisPrevHash, Event{
		Time: time.Unix(1_700_000_000, 0).UTC(), Actor: "alice", SandboxID: "sb", Ref: "r", Result: "failure",
		Reason: "not_found", CorrelationID: "c", EventID: "e", NodeID: "n", Kind: "egress", Destination: "d",
		Network: "tcp", BytesIn: 1, BytesOut: 2, IncarnationID: "i", OwnerRef: "o", Dropped: 3, WitnessedThrough: "w",
	})[0]
	stub := RedactForRetention(ev)
	want := Event{Time: ev.Time, EventID: "e", Result: "success", Reason: "prune", Kind: KindRetentionRedacted, PrevHash: ev.PrevHash, EventHash: ev.EventHash}
	if stub != want {
		t.Fatalf("stub = %+v\nwant %+v", stub, want)
	}
	if RedactForRetention(stub) != stub {
		t.Fatal("redaction is not idempotent: a stored stub would fail its own check")
	}
}

func TestScanChain(t *testing.T) {
	g := linked(GenesisPrevHash, rec("a"), rec("b"), rec("c"))
	stub := RedactForRetention(g[1])
	checkpoint := Event{EventID: "cp", Kind: KindRetentionCheckpoint, Result: "success", WitnessedThrough: " wt "}
	LinkEvent(strings.Repeat("d", 64), &checkpoint)
	bare := Event{EventID: "cp-bare", Kind: KindRetentionCheckpoint, Result: "success"}
	LinkEvent(strings.Repeat("d", 64), &bare)
	kept := linked(strings.Repeat("e", 64), rec("kept"))[0]

	l0, l1, l2 := jsonLine(t, g[0]), jsonLine(t, g[1]), jsonLine(t, g[2])
	full := jsonLines(t, g...)
	unlinked := linked(strings.Repeat("a", 64), rec("x"))[0]
	huge := bytes.Repeat([]byte("x"), MaxLineBytes+1)

	cases := []struct {
		name    string
		input   []byte
		want    ChainScan
		wantErr string
	}{
		{name: "empty", input: nil, want: ChainScan{Head: GenesisPrevHash}},
		{name: "chain", input: full, want: ChainScan{
			Head: g[2].EventHash, EventID: "c", LastLineStart: int64(len(l0) + len(l1)), ValidEnd: int64(len(full)), Records: 3}},
		{name: "terminated blank lines count as valid bytes", input: append(append(append([]byte{}, l0...), " \n\n"...), l1...), want: ChainScan{
			Head: g[1].EventHash, EventID: "b", LastLineStart: int64(len(l0) + 3), ValidEnd: int64(len(l0) + 3 + len(l1)), Records: 2}},
		{name: "unterminated trailing whitespace is left for the next append", input: append(append([]byte{}, l0...), "  "...), want: ChainScan{
			Head: g[0].EventHash, EventID: "a", ValidEnd: int64(len(l0)), Records: 1}},
		{name: "stubs are counted", input: jsonLines(t, g[0], stub, g[2]), want: ChainScan{
			Head: g[2].EventHash, EventID: "c", LastLineStart: int64(len(l0) + len(jsonLine(t, stub))), ValidEnd: int64(len(jsonLines(t, g[0], stub, g[2]))), Records: 3, Redacted: 1}},
		{name: "checkpoint witnessed_through is trimmed", input: jsonLines(t, checkpoint, kept), want: ChainScan{
			Head: kept.EventHash, EventID: "kept", LastLineStart: int64(len(jsonLine(t, checkpoint))), WitnessedThrough: "wt", ValidEnd: int64(len(jsonLines(t, checkpoint, kept))), Records: 2}},
		{name: "checkpoint without witnessed_through", input: jsonLines(t, bare), want: ChainScan{
			Head: bare.EventHash, EventID: "cp-bare", ValidEnd: int64(len(jsonLines(t, bare))), Records: 1}},
		{name: "torn tail is reported, not failed", input: append(append([]byte{}, l0...), l1[:len(l1)/2]...), want: ChainScan{
			Head: g[0].EventHash, EventID: "a", ValidEnd: int64(len(l0)), TornBytes: int64(len(l1) / 2), Records: 1}},
		{name: "final record missing only its newline", input: append(append([]byte{}, l0...), l1[:len(l1)-1]...), want: ChainScan{
			Head: g[1].EventHash, EventID: "b", LastLineStart: int64(len(l0)), ValidEnd: int64(len(l0) + len(l1) - 1), MissingNewline: true, Records: 2}},
		{name: "unterminated oversized tail is a tear", input: append(append([]byte{}, l0...), huge...), want: ChainScan{
			Head: g[0].EventHash, EventID: "a", ValidEnd: int64(len(l0)), TornBytes: int64(len(huge)), Records: 1}},
		{name: "terminated oversized line fails", input: append(append(append([]byte{}, l0...), huge...), '\n'),
			wantErr: fmt.Sprintf("secret audit chain line 2 exceeds %d bytes", MaxLineBytes)},
		{name: "terminated malformed line fails", input: append(append([]byte{}, l0...), "{not json\n"...),
			wantErr: "secret audit chain line 2: malformed json"},
		{name: "unterminated record that parses but does not link is not a tear", input: append(append([]byte{}, l0...), bytes.TrimSuffix(jsonLine(t, unlinked), []byte("\n"))...),
			wantErr: "secret audit chain line 2: prev_hash mismatch"},
		{name: "broken link fails with its line number", input: append(append([]byte{}, l0...), l2...),
			wantErr: "secret audit chain line 2: prev_hash mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ScanChain(bytes.NewReader(tc.input), ScanOptions{})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprintf("%+v", got) != fmt.Sprintf("%+v", tc.want) {
				t.Fatalf("scan = %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// The witness check names the hashes it needs and the scan says which it
// passed, so memory is O(len(probe)) rather than O(records).
func TestScanChainProbe(t *testing.T) {
	g := linked(GenesisPrevHash, rec("a"), rec("b"), rec("c"))
	input := jsonLines(t, g...)
	scan, err := ScanChain(bytes.NewReader(input), ScanOptions{Probe: []string{g[1].EventHash, "", strings.Repeat("0", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Found) != 1 || !scan.Found[g[1].EventHash] {
		t.Fatalf("found = %v", scan.Found)
	}
	scan, err = ScanChain(bytes.NewReader(input), ScanOptions{Probe: []string{strings.Repeat("0", 64)}})
	if err != nil || scan.Found != nil {
		t.Fatalf("unmatched probe: found = %v err = %v", scan.Found, err)
	}
}

// Checkpoint boot continues a chain from a trusted offset: offsets stay in
// file coordinates, nothing after the start reports the start record, and
// the caller's verifier is copied rather than advanced.
func TestScanChainPrimedVerifier(t *testing.T) {
	g := linked(GenesisPrevHash, rec("a"), rec("b"), rec("c"))
	l0, l1 := jsonLine(t, g[0]), jsonLine(t, g[1])
	full := jsonLines(t, g...)
	base := int64(len(l0) + len(l1))

	v := ResumeChainVerifier(g[1].EventHash, false)
	opts := ScanOptions{Base: base, Verifier: &v, StartEventID: "b", StartLineOffset: int64(len(l0))}
	scan, err := ScanChain(bytes.NewReader(full[base:]), opts)
	if err != nil {
		t.Fatal(err)
	}
	want := ChainScan{Head: g[2].EventHash, EventID: "c", LastLineStart: base, ValidEnd: int64(len(full)), Records: 1}
	if fmt.Sprintf("%+v", scan) != fmt.Sprintf("%+v", want) {
		t.Fatalf("scan = %+v\nwant %+v", scan, want)
	}
	if v.Head() != g[1].EventHash {
		t.Fatal("ScanChain advanced the caller's verifier")
	}

	idle, err := ScanChain(bytes.NewReader(nil), opts)
	if err != nil {
		t.Fatal(err)
	}
	want = ChainScan{Head: g[1].EventHash, EventID: "b", LastLineStart: int64(len(l0)), ValidEnd: base}
	if fmt.Sprintf("%+v", idle) != fmt.Sprintf("%+v", want) {
		t.Fatalf("nothing after the start: scan = %+v\nwant %+v", idle, want)
	}

	torn := append(append([]byte{}, full[base:]...), `{"tor`...)
	scan, err = ScanChain(bytes.NewReader(torn), opts)
	if err != nil || scan.TornBytes != 5 || scan.ValidEnd != int64(len(full)) {
		t.Fatalf("primed torn tail: scan = %+v err = %v", scan, err)
	}

	stale := ResumeChainVerifier(g[0].EventHash, false)
	opts.Verifier = &stale
	if _, err := ScanChain(bytes.NewReader(full[base:]), opts); err == nil || !strings.Contains(err.Error(), "line 1: prev_hash mismatch") {
		t.Fatalf("stale primed head = %v", err)
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestScanChainPropagatesReadErrors(t *testing.T) {
	boom := errors.New("disk on fire")
	scan, err := ScanChain(failingReader{boom}, ScanOptions{Base: 7})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if scan.Head != GenesisPrevHash || scan.ValidEnd != 7 {
		t.Fatalf("partial scan = %+v", scan)
	}
}

func TestReadLine(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name           string
		r              io.Reader
		size, max      int
		wantLine       string
		wantConsumed   int64
		wantTerminated bool
		wantTooLong    bool
		wantErr        error
	}{
		{name: "terminated", r: strings.NewReader("abc\nrest"), size: 16, max: 0, wantLine: "abc\n", wantConsumed: 4, wantTerminated: true},
		{name: "unterminated", r: strings.NewReader("abc"), size: 16, max: 0, wantLine: "abc", wantConsumed: 3},
		{name: "empty", r: strings.NewReader(""), size: 16, max: 0, wantLine: "", wantConsumed: 0},
		{name: "longer than the buffer is reassembled", r: strings.NewReader(strings.Repeat("y", 40) + "\n"), size: 16, max: 64,
			wantLine: strings.Repeat("y", 40) + "\n", wantConsumed: 41, wantTerminated: true},
		{name: "past max is counted but not kept", r: strings.NewReader(strings.Repeat("z", 40) + "\nnext"), size: 16, max: 10,
			wantConsumed: 41, wantTerminated: true, wantTooLong: true},
		{name: "unterminated past max", r: strings.NewReader(strings.Repeat("z", 40)), size: 16, max: 10,
			wantConsumed: 40, wantTooLong: true},
		{name: "read error drops the line", r: failingReader{boom}, size: 16, max: 0, wantErr: boom},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, consumed, terminated, tooLong, err := ReadLine(bufio.NewReaderSize(tc.r, tc.size), int64(tc.max))
			if !errors.Is(err, tc.wantErr) || string(line) != tc.wantLine || consumed != tc.wantConsumed ||
				terminated != tc.wantTerminated || tooLong != tc.wantTooLong {
				t.Fatalf("got line=%q consumed=%d terminated=%v tooLong=%v err=%v", line, consumed, terminated, tooLong, err)
			}
			if tc.wantTooLong && line != nil {
				t.Fatal("an oversized line was retained")
			}
		})
	}
}
