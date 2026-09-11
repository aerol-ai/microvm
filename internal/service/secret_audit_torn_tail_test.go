package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// Torn-tail repair contract: appends are one write per batch and fsynced on a
// ticker, so an unclean shutdown leaves a strict byte-prefix of the last batch.
// The sink must cut that tail at boot, keep every verified record, chain a
// torn_tail gap marker, and boot under strict mode — while every other defect
// (fully written garbage, a record that does not link) still fails closed.

// seedAuditFile writes refs in ONE batch (one on-disk write, like production)
// and returns the file path plus its clean bytes.
func seedAuditFile(t *testing.T, dir string, refs ...string) (string, []byte) {
	t.Helper()
	sink, err := newFileAuditSinkOpts(dir, 16, false)
	if err != nil {
		t.Fatalf("seed sink: %v", err)
	}
	events := make([]SecretAuditEvent, 0, len(refs))
	for _, ref := range refs {
		events = append(events, SecretAuditEvent{Result: secretAuditResultSuccess, Reason: secretAuditReasonOK, Ref: ref, SandboxID: "sb-seed"})
	}
	if len(events) > 0 {
		if err := sink.writeEventBatch(events, true, false); err != nil {
			t.Fatalf("seed batch: %v", err)
		}
	}
	if err := sink.Sync(); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	sink.Close()
	path := filepath.Join(dir, secretAuditFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	return path, raw
}

func readAuditEvents(t *testing.T, path string) []SecretAuditEvent {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []SecretAuditEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev SecretAuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("malformed retained line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return out
}

// lineEnds returns the offset just past each '\n' in raw.
func lineEnds(raw []byte) []int64 {
	var ends []int64
	for i, b := range raw {
		if b == '\n' {
			ends = append(ends, int64(i+1))
		}
	}
	return ends
}

func mustWriteRaw(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustChainVerify(t *testing.T, path string) string {
	t.Helper()
	head, _, err := RecomputeChainHead(path)
	if err != nil {
		t.Fatalf("chain does not verify after repair: %v", err)
	}
	return head
}

func tornMarkers(events []SecretAuditEvent) []SecretAuditEvent {
	var out []SecretAuditEvent
	for _, ev := range events {
		if ev.Kind == secretAuditKindGap && ev.Reason == secretAuditReasonTornTail {
			out = append(out, ev)
		}
	}
	return out
}

// reserialize returns a byte-exact copy of the event with mutate applied and
// no trailing newline, for building tampered tails.
func reserialize(t *testing.T, ev SecretAuditEvent, mutate func(*SecretAuditEvent)) []byte {
	t.Helper()
	mutate(&ev)
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestScanSecretAuditChainClassifiesTails(t *testing.T) {
	path, clean := seedAuditFile(t, t.TempDir(), "one", "two")
	events := readAuditEvents(t, path)
	if len(events) != 2 {
		t.Fatalf("seed produced %d events, want 2", len(events))
	}
	ends := lineEnds(clean)
	l1 := clean[:ends[0]-1]
	l2 := clean[ends[0] : ends[1]-1]
	h1, h2 := events[0].EventHash, events[1].EventHash

	tamperedHash := reserialize(t, events[1], func(ev *SecretAuditEvent) { ev.EventHash = strings.Repeat("d", 64) })
	brokenLink := reserialize(t, events[1], func(ev *SecretAuditEvent) {
		ev.PrevHash = strings.Repeat("0", 64)
		ev.EventHash = auditlog.HashEvent(ev.PrevHash, *ev)
	})
	huge := bytes.Repeat([]byte("x"), secretAuditMaxLineBytes+1)

	cases := []struct {
		name           string
		raw            []byte // nil means "no file"
		wantHead       string
		wantValidEnd   int64
		wantTorn       int64
		wantMissingNL  bool
		wantErrContain string
	}{
		{name: "missing file", raw: nil, wantHead: auditlog.GenesisPrevHash},
		{name: "empty file", raw: []byte{}, wantHead: auditlog.GenesisPrevHash},
		{name: "clean", raw: clean, wantHead: h2, wantValidEnd: ends[1]},
		{name: "complete final record without newline", raw: clean[:len(clean)-1], wantHead: h2, wantValidEnd: int64(len(clean) - 1), wantMissingNL: true},
		{name: "final record cut mid json", raw: append(append([]byte{}, clean[:ends[0]]...), l2[:10]...), wantHead: h1, wantValidEnd: ends[0], wantTorn: 10},
		{name: "nul filled tail after newline", raw: append(append([]byte{}, clean[:ends[0]]...), bytes.Repeat([]byte{0}, 64)...), wantHead: h1, wantValidEnd: ends[0], wantTorn: 64},
		{name: "newline itself replaced by nul", raw: append(append([]byte{}, l1...), bytes.Repeat([]byte{0}, 8)...), wantHead: auditlog.GenesisPrevHash, wantValidEnd: 0, wantTorn: int64(len(l1) + 8)},
		{name: "entire file is one partial record", raw: l1[:5], wantHead: auditlog.GenesisPrevHash, wantValidEnd: 0, wantTorn: 5},
		{name: "trailing blank line and unterminated whitespace", raw: append(append([]byte{}, clean[:ends[0]]...), []byte("\n  ")...), wantHead: h1, wantValidEnd: ends[0] + 1},
		{name: "blank line between records", raw: append(append(append([]byte{}, l1...), []byte("\n\n")...), append(append([]byte{}, l2...), '\n')...), wantHead: h2, wantValidEnd: int64(len(l1) + 2 + len(l2) + 1)},
		{name: "oversized unterminated tail is a tear", raw: append(append([]byte{}, clean[:ends[0]]...), huge...), wantHead: h1, wantValidEnd: ends[0], wantTorn: int64(len(huge))},
		{name: "terminated garbage last line", raw: append(append([]byte{}, clean[:ends[0]]...), []byte("{garbage}\n")...), wantErrContain: "line 2: malformed json"},
		{name: "terminated partial json is corruption not a tear", raw: append(append(append([]byte{}, clean[:ends[0]]...), l2[:10]...), '\n'), wantErrContain: "line 2: malformed json"},
		{name: "interior garbage", raw: append(append(append([]byte{}, l1...), []byte("\n{garbage}\n")...), append(append([]byte{}, l2...), '\n')...), wantErrContain: "line 2: malformed json"},
		{name: "unterminated valid json with wrong hash is tampering", raw: append(append([]byte{}, clean[:ends[0]]...), tamperedHash...), wantErrContain: "event_hash mismatch"},
		{name: "unterminated valid json with broken link is tampering", raw: append(append([]byte{}, clean[:ends[0]]...), brokenLink...), wantErrContain: "prev_hash mismatch"},
		{name: "oversized terminated line is corruption", raw: append(append(append([]byte{}, clean[:ends[0]]...), huge...), '\n'), wantErrContain: "exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), secretAuditFileName)
			if tc.raw != nil {
				mustWriteRaw(t, p, tc.raw)
			}
			scan, err := scanSecretAuditChain(p)
			if tc.wantErrContain != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrContain) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErrContain)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if scan.head != tc.wantHead {
				t.Errorf("head = %q, want %q", scan.head, tc.wantHead)
			}
			if scan.validEnd != tc.wantValidEnd {
				t.Errorf("validEnd = %d, want %d", scan.validEnd, tc.wantValidEnd)
			}
			if scan.tornBytes != tc.wantTorn {
				t.Errorf("tornBytes = %d, want %d", scan.tornBytes, tc.wantTorn)
			}
			if scan.missingNewline != tc.wantMissingNL {
				t.Errorf("missingNewline = %v, want %v", scan.missingNewline, tc.wantMissingNL)
			}
			// The strict read-side contract must reject exactly the torn cases.
			_, _, strictErr := RecomputeChainHead(p)
			if tc.wantTorn > 0 {
				if strictErr == nil || !strings.Contains(strictErr.Error(), "unterminated") {
					t.Fatalf("RecomputeChainHead accepted a torn tail: %v", strictErr)
				}
			} else if strictErr != nil {
				t.Fatalf("RecomputeChainHead rejected a repairable/clean file: %v", strictErr)
			}
		})
	}
}

func TestFileAuditSinkRepairsTornTailAtBoot(t *testing.T) {
	dir := t.TempDir()
	path, clean := seedAuditFile(t, dir, "one", "two", "three")
	seeded := readAuditEvents(t, path)
	ends := lineEnds(clean)
	cut := ends[1] + 17 // inside the third record
	mustWriteRaw(t, path, clean[:cut])

	repairsBefore := auditTornTailRepairsTotal.Value()
	bytesBefore := auditTornTailBytesTotal.Value()

	sink, err := newFileAuditSinkOpts(dir, 16, false)
	if err != nil {
		t.Fatalf("open after torn tail must succeed: %v", err)
	}
	if sink.bootRepair == nil {
		t.Fatal("bootRepair not recorded")
	}
	if sink.bootRepair.Offset != ends[1] || sink.bootRepair.Bytes != 17 || sink.bootRepair.Dropped != 1 {
		t.Fatalf("bootRepair = %+v, want offset %d bytes 17 dropped 1", *sink.bootRepair, ends[1])
	}
	if got := auditTornTailRepairsTotal.Value() - repairsBefore; got != 1 {
		t.Fatalf("repairs metric delta = %d, want 1", got)
	}
	if got := auditTornTailBytesTotal.Value() - bytesBefore; got != 17 {
		t.Fatalf("bytes metric delta = %d, want 17", got)
	}
	if _, err := os.Stat(filepath.Join(dir, secretAuditTornName)); !os.IsNotExist(err) {
		t.Fatalf("secrets.torn must be removed once the marker is chained (stat err=%v)", err)
	}

	got := readAuditEvents(t, path)
	if len(got) != 3 {
		t.Fatalf("retained %d events, want 2 verified + 1 marker: %+v", len(got), got)
	}
	if got[0].EventHash != seeded[0].EventHash || got[1].EventHash != seeded[1].EventHash {
		t.Fatal("verified prefix was altered by the repair")
	}
	marker := got[2]
	if marker.Kind != secretAuditKindGap || marker.Result != secretAuditResultGap || marker.Reason != secretAuditReasonTornTail {
		t.Fatalf("marker = %+v", marker)
	}
	if marker.Dropped != 1 {
		t.Fatalf("marker.Dropped = %d, want 1", marker.Dropped)
	}
	if marker.PrevHash != seeded[1].EventHash {
		t.Fatalf("marker must chain onto the last verified record: prev=%s want %s", marker.PrevHash, seeded[1].EventHash)
	}
	if marker.EventID == "" || marker.EventHash == "" {
		t.Fatal("marker lacks id/hash")
	}
	mustChainVerify(t, path)

	// The repaired head is live: a new append links to the marker.
	if err := sink.writeEvent(SecretAuditEvent{Result: secretAuditResultSuccess, Ref: "four"}); err != nil {
		t.Fatalf("append after repair: %v", err)
	}
	sink.Close()
	got = readAuditEvents(t, path)
	if len(got) != 4 || got[3].PrevHash != marker.EventHash {
		t.Fatalf("post-repair append did not chain onto the marker: %+v", got)
	}
	mustChainVerify(t, path)

	// Idempotent: a clean reopen records nothing.
	again, err := newFileAuditSinkOpts(dir, 16, false)
	if err != nil {
		t.Fatalf("clean reopen: %v", err)
	}
	again.Close()
	if again.bootRepair != nil {
		t.Fatal("clean reopen reported a repair")
	}
	if auditTornTailRepairsTotal.Value()-repairsBefore != 1 {
		t.Fatal("clean reopen incremented the repair counter")
	}
	if len(tornMarkers(readAuditEvents(t, path))) != 1 {
		t.Fatal("clean reopen chained a second marker")
	}
}

// Every byte offset inside the final record is a possible crash point. The
// classifier is checked at every one of them (cheap, no I/O beyond a read);
// the full open-repair-append cycle, which costs several fsyncs, runs at the
// three boundaries plus a stride. Each must retain the first record and chain
// exactly one marker — except the boundaries, which need no marker at all.
func TestFileAuditSinkTornTailEveryCutOffset(t *testing.T) {
	seedDir := t.TempDir()
	_, clean := seedAuditFile(t, seedDir, "alpha", "beta")
	ends := lineEnds(clean)
	first, size := ends[0], int64(len(clean))

	fullOpen := func(cut int64) bool {
		return cut == first || cut == first+1 || cut == size-2 || cut == size-1 || cut == size || (cut-first)%16 == 0
	}
	for cut := first; cut <= size; cut++ {
		dir := t.TempDir()
		path := filepath.Join(dir, secretAuditFileName)
		mustWriteRaw(t, path, clean[:cut])

		scan, err := scanSecretAuditChain(path)
		if err != nil {
			t.Fatalf("cut@%d: classifier errored: %v", cut, err)
		}
		switch cut {
		case first, size:
			if scan.tornBytes != 0 || scan.missingNewline {
				t.Fatalf("cut@%d: clean file classified as torn=%d missingNL=%v", cut, scan.tornBytes, scan.missingNewline)
			}
		case size - 1:
			if scan.tornBytes != 0 || !scan.missingNewline || scan.validEnd != cut {
				t.Fatalf("cut@%d: want missingNewline, got %+v", cut, scan)
			}
		default:
			if scan.tornBytes != cut-first || scan.validEnd != first || scan.missingNewline {
				t.Fatalf("cut@%d: want torn=%d validEnd=%d, got torn=%d validEnd=%d missingNL=%v", cut, cut-first, first, scan.tornBytes, scan.validEnd, scan.missingNewline)
			}
		}
		if !fullOpen(cut) {
			continue
		}

		sink, err := newFileAuditSinkOpts(dir, 4, false)
		if err != nil {
			t.Fatalf("cut@%d: open failed: %v", cut, err)
		}
		sink.Close()
		got := readAuditEvents(t, path)
		markers := tornMarkers(got)
		head := mustChainVerify(t, path)
		switch cut {
		case first:
			// Exact boundary: the second record is simply absent. Nothing was
			// torn, so a marker would be a lie.
			if len(got) != 1 || len(markers) != 0 || sink.bootRepair != nil {
				t.Fatalf("cut@%d (boundary): got %d events, %d markers, repair=%v", cut, len(got), len(markers), sink.bootRepair)
			}
		case size - 1:
			// Only the terminator is missing: the record is complete and
			// verified, so restore the newline and keep it.
			if len(got) != 2 || len(markers) != 0 || sink.bootRepair != nil || got[1].Ref != "beta" {
				t.Fatalf("cut@%d (missing newline): got %+v repair=%v", cut, got, sink.bootRepair)
			}
			raw, _ := os.ReadFile(path)
			if !bytes.HasSuffix(raw, []byte{'\n'}) {
				t.Fatalf("cut@%d: newline not restored", cut)
			}
		case size:
			if len(got) != 2 || len(markers) != 0 || sink.bootRepair != nil {
				t.Fatalf("cut@%d (clean): got %d events, %d markers", cut, len(got), len(markers))
			}
		default:
			if len(got) != 2 || len(markers) != 1 || got[0].Ref != "alpha" {
				t.Fatalf("cut@%d: got %+v", cut, got)
			}
			if sink.bootRepair == nil || sink.bootRepair.Offset != first || sink.bootRepair.Bytes != cut-first {
				t.Fatalf("cut@%d: repair = %+v", cut, sink.bootRepair)
			}
			if head != markers[0].EventHash {
				t.Fatalf("cut@%d: head %s is not the marker %s", cut, head, markers[0].EventHash)
			}
		}
	}
}

func TestFileAuditSinkTornTailInsideBatch(t *testing.T) {
	dir := t.TempDir()
	path, clean := seedAuditFile(t, dir, "e1", "e2", "e3", "e4", "e5")
	ends := lineEnds(clean)
	// One write carried all five; the crash landed inside the fourth.
	mustWriteRaw(t, path, clean[:ends[3]-3])
	sink, err := newFileAuditSinkOpts(dir, 4, false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sink.Close()
	got := readAuditEvents(t, path)
	if len(got) != 4 {
		t.Fatalf("retained %d, want e1..e3 + marker", len(got))
	}
	for i, ref := range []string{"e1", "e2", "e3"} {
		if got[i].Ref != ref {
			t.Fatalf("got[%d].Ref = %q, want %q", i, got[i].Ref, ref)
		}
	}
	if got[3].Reason != secretAuditReasonTornTail || got[3].Dropped != 1 || got[3].PrevHash != got[2].EventHash {
		t.Fatalf("marker = %+v", got[3])
	}
	mustChainVerify(t, path)
}

func TestFileAuditSinkNulFilledTailRepaired(t *testing.T) {
	t.Run("after newline", func(t *testing.T) {
		dir := t.TempDir()
		path, clean := seedAuditFile(t, dir, "one")
		mustWriteRaw(t, path, append(append([]byte{}, clean...), bytes.Repeat([]byte{0}, 4096)...))
		sink, err := newFileAuditSinkOpts(dir, 4, false)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		sink.Close()
		got := readAuditEvents(t, path)
		if len(got) != 2 || got[0].Ref != "one" || got[1].Reason != secretAuditReasonTornTail {
			t.Fatalf("got %+v", got)
		}
		if sink.bootRepair.Bytes != 4096 {
			t.Fatalf("bytes cut = %d, want 4096", sink.bootRepair.Bytes)
		}
		mustChainVerify(t, path)
	})
	t.Run("newline replaced", func(t *testing.T) {
		dir := t.TempDir()
		path, clean := seedAuditFile(t, dir, "one", "two")
		ends := lineEnds(clean)
		// The block holding the second record's terminator was zero-filled:
		// that record was never durable and must be treated as lost.
		raw := append(append([]byte{}, clean[:ends[1]-1]...), bytes.Repeat([]byte{0}, 16)...)
		mustWriteRaw(t, path, raw)
		sink, err := newFileAuditSinkOpts(dir, 4, false)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		sink.Close()
		got := readAuditEvents(t, path)
		if len(got) != 2 || got[0].Ref != "one" || got[1].Reason != secretAuditReasonTornTail {
			t.Fatalf("got %+v", got)
		}
		mustChainVerify(t, path)
	})
}

func TestFileAuditSinkEntireFileTornStartsFromGenesis(t *testing.T) {
	dir := t.TempDir()
	path, clean := seedAuditFile(t, dir, "only")
	mustWriteRaw(t, path, clean[:len(clean)/2])
	sink, err := newFileAuditSinkOpts(dir, 4, false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sink.Close()
	got := readAuditEvents(t, path)
	if len(got) != 1 {
		t.Fatalf("retained %d events, want only the marker", len(got))
	}
	if got[0].Reason != secretAuditReasonTornTail || got[0].PrevHash != auditlog.GenesisPrevHash {
		t.Fatalf("marker = %+v", got[0])
	}
	if sink.bootRepair.Offset != 0 || sink.bootRepair.Bytes != int64(len(clean)/2) {
		t.Fatalf("repair = %+v", sink.bootRepair)
	}
	mustChainVerify(t, path)
}

func TestFileAuditSinkMissingNewlineRestoredWithoutMarker(t *testing.T) {
	dir := t.TempDir()
	path, clean := seedAuditFile(t, dir, "one", "two")
	mustWriteRaw(t, path, clean[:len(clean)-1])
	before := auditTornTailRepairsTotal.Value()
	sink, err := newFileAuditSinkOpts(dir, 4, false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if sink.bootRepair != nil || auditTornTailRepairsTotal.Value() != before {
		t.Fatal("a missing terminator is not a tear and must not be reported as one")
	}
	if err := sink.writeEvent(SecretAuditEvent{Result: secretAuditResultSuccess, Ref: "three"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	sink.Close()
	got := readAuditEvents(t, path)
	if len(got) != 3 || got[1].Ref != "two" || got[2].Ref != "three" {
		t.Fatalf("append was glued onto the unterminated record: %+v", got)
	}
	mustChainVerify(t, path)
}

func TestFileAuditSinkStillFailsClosedOnCorruption(t *testing.T) {
	seedDir := t.TempDir()
	seedPath, clean := seedAuditFile(t, seedDir, "one", "two")
	events := readAuditEvents(t, seedPath)
	ends := lineEnds(clean)
	prefix := clean[:ends[0]]
	l2 := clean[ends[0] : ends[1]-1]

	cases := map[string][]byte{
		"terminated garbage last line": append(append([]byte{}, prefix...), []byte("{garbage}\n")...),
		"terminated partial json":      append(append(append([]byte{}, prefix...), l2[:10]...), '\n'),
		"interior garbage":             append(append([]byte{}, prefix...), append([]byte("{garbage}\n"), append(append([]byte{}, l2...), '\n')...)...),
		"unterminated tampered hash":   append(append([]byte{}, prefix...), reserialize(t, events[1], func(ev *SecretAuditEvent) { ev.EventHash = strings.Repeat("d", 64) })...),
		"unterminated broken link": append(append([]byte{}, prefix...), reserialize(t, events[1], func(ev *SecretAuditEvent) {
			ev.PrevHash = strings.Repeat("0", 64)
			ev.EventHash = auditlog.HashEvent(ev.PrevHash, *ev)
		})...),
		"terminated oversized line":        append(append(append([]byte{}, prefix...), bytes.Repeat([]byte("x"), secretAuditMaxLineBytes+1)...), '\n'),
		"legacy record without hash chain": []byte(`{"time":"2026-01-01T00:00:00Z","result":"success","ref":"env:x"}` + "\n"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, secretAuditFileName)
			mustWriteRaw(t, path, raw)
			before := auditTornTailRepairsTotal.Value()
			sink, err := newFileAuditSinkOpts(dir, 4, false)
			if err == nil {
				sink.Close()
				t.Fatal("corruption was accepted")
			}
			if !strings.Contains(err.Error(), "verify secret audit chain") {
				t.Fatalf("unexpected error class: %v", err)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, raw) {
				t.Fatal("refusing to open must not touch the evidence")
			}
			if _, statErr := os.Stat(filepath.Join(dir, secretAuditTornName)); !os.IsNotExist(statErr) {
				t.Fatal("no repair intent may be recorded for corruption")
			}
			if auditTornTailRepairsTotal.Value() != before {
				t.Fatal("repair counter moved on a refused open")
			}
		})
	}
}

func TestRecomputeChainStaysStrictOnTornTail(t *testing.T) {
	dir := t.TempDir()
	path, clean := seedAuditFile(t, dir, "one", "two")
	mustWriteRaw(t, path, clean[:len(clean)-5])
	if _, _, err := RecomputeChainHead(path); err == nil || !strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("RecomputeChainHead must refuse a torn tail (writer fallback / witness): %v", err)
	}
	if _, err := recomputeChain(path); err == nil {
		t.Fatal("recomputeChain must refuse a torn tail")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, clean[:len(clean)-5]) {
		t.Fatal("strict scan must not modify the file")
	}
}

func TestFileAuditSinkPendingTornSidecarOwesMarker(t *testing.T) {
	t.Run("clean file with sidecar", func(t *testing.T) {
		dir := t.TempDir()
		path, _ := seedAuditFile(t, dir, "one")
		if err := persistTornTailRepair(filepath.Join(dir, secretAuditTornName), secretAuditTornTailRepair{Offset: 3, Bytes: 7, Dropped: 1}); err != nil {
			t.Fatal(err)
		}
		bytesBefore := auditTornTailBytesTotal.Value()
		sink, err := newFileAuditSinkOpts(dir, 4, false)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		sink.Close()
		got := readAuditEvents(t, path)
		if len(got) != 2 || got[1].Reason != secretAuditReasonTornTail || got[1].Dropped != 1 {
			t.Fatalf("owed marker not chained: %+v", got)
		}
		if auditTornTailBytesTotal.Value()-bytesBefore != 7 {
			t.Fatal("bytes metric must reflect the owed repair")
		}
		if _, err := os.Stat(filepath.Join(dir, secretAuditTornName)); !os.IsNotExist(err) {
			t.Fatal("sidecar must be cleared after the marker lands")
		}
		mustChainVerify(t, path)
	})
	t.Run("sidecar plus fresh tear coalesce", func(t *testing.T) {
		dir := t.TempDir()
		path, clean := seedAuditFile(t, dir, "one", "two")
		ends := lineEnds(clean)
		cut := int64(len(clean) - 5) // inside the second record
		freshTorn := cut - ends[0]
		mustWriteRaw(t, path, clean[:cut])
		if err := persistTornTailRepair(filepath.Join(dir, secretAuditTornName), secretAuditTornTailRepair{Bytes: 10, Dropped: 2}); err != nil {
			t.Fatal(err)
		}
		sink, err := newFileAuditSinkOpts(dir, 4, false)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		sink.Close()
		markers := tornMarkers(readAuditEvents(t, path))
		if len(markers) != 1 || markers[0].Dropped != 3 {
			t.Fatalf("markers = %+v, want one with dropped=3", markers)
		}
		if want := freshTorn + 10; sink.bootRepair.Bytes != want {
			t.Fatalf("coalesced bytes = %d, want %d", sink.bootRepair.Bytes, want)
		}
		mustChainVerify(t, path)
	})
	t.Run("sidecar at the same offset is the same tear", func(t *testing.T) {
		dir := t.TempDir()
		path, clean := seedAuditFile(t, dir, "one", "two")
		ends := lineEnds(clean)
		cut := int64(len(clean) - 5)
		mustWriteRaw(t, path, clean[:cut])
		// An earlier open measured this exact tail and could not finish.
		if err := persistTornTailRepair(filepath.Join(dir, secretAuditTornName), secretAuditTornTailRepair{Offset: ends[0], Bytes: cut - ends[0], Dropped: 1}); err != nil {
			t.Fatal(err)
		}
		sink, err := newFileAuditSinkOpts(dir, 4, false)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		sink.Close()
		markers := tornMarkers(readAuditEvents(t, path))
		if len(markers) != 1 || markers[0].Dropped != 1 {
			t.Fatalf("one tear reported twice: %+v", markers)
		}
		if sink.bootRepair.Bytes != cut-ends[0] {
			t.Fatalf("bytes = %d, want %d (not doubled)", sink.bootRepair.Bytes, cut-ends[0])
		}
		mustChainVerify(t, path)
	})
	t.Run("garbage sidecar still owes one", func(t *testing.T) {
		dir := t.TempDir()
		path, _ := seedAuditFile(t, dir, "one")
		mustWriteRaw(t, filepath.Join(dir, secretAuditTornName), []byte("not json"))
		sink, err := newFileAuditSinkOpts(dir, 4, false)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		sink.Close()
		markers := tornMarkers(readAuditEvents(t, path))
		if len(markers) != 1 || markers[0].Dropped != 1 {
			t.Fatalf("markers = %+v", markers)
		}
	})
	t.Run("no sidecar no marker", func(t *testing.T) {
		if got := loadTornTailRepair(filepath.Join(t.TempDir(), "absent")); got != nil {
			t.Fatalf("absent sidecar returned %+v", got)
		}
	})
}

// The exact scenario from review: strict boot (the production default) after
// an unclean shutdown. This is the function pkg/daemon gates startup on.
func TestValidateSecretAuditSinkBootsAfterTornTail(t *testing.T) {
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	path, clean := seedAuditFile(t, auditDir, "one", "two")
	ends := lineEnds(clean)
	cut := int64(len(clean) - 20) // inside the second record
	mustWriteRaw(t, path, clean[:cut])

	var logBuf bytes.Buffer
	svc := &Service{
		cfg:    config.Config{DBPath: filepath.Join(dir, "state.db"), SecretAuditStrictBoot: true},
		logger: slog.New(slog.NewTextHandler(&logBuf, nil)),
	}
	t.Cleanup(svc.CloseSecretAuditSink)
	if err := svc.ValidateSecretAuditSink(); err != nil {
		t.Fatalf("strict boot must succeed after a torn tail: %v", err)
	}
	if svc.secretAuditInitErr != nil {
		t.Fatalf("init err = %v", svc.secretAuditInitErr)
	}
	if secretAuditSinkHealthy.Value() != 1 {
		t.Fatal("sink health gauge must be 1 after repair")
	}
	if _, ok := svc.secretAudit.(unavailableSecretAuditSink); ok {
		t.Fatal("sink fell back to unavailable")
	}
	if !strings.Contains(logBuf.String(), "torn tail repaired") {
		t.Fatalf("repair must be logged; got: %s", logBuf.String())
	}
	if want := fmt.Sprintf("offset=%d bytes_cut=%d dropped_at_least=1", ends[0], cut-ends[0]); !strings.Contains(logBuf.String(), want) {
		t.Fatalf("log must carry %q; got: %s", want, logBuf.String())
	}
	// The sink is live: a normal emit lands and chains.
	emitSecretAudit(svc.secretAuditSink(), "sb-1", "env:sb-1", "node-a", "", "", nil)
	if err := svc.secretAuditFile.Sync(); err != nil {
		t.Fatal(err)
	}
	got := readAuditEvents(t, path)
	if len(got) != 3 || got[1].Reason != secretAuditReasonTornTail || got[2].SandboxID != "sb-1" {
		t.Fatalf("post-boot events = %+v", got)
	}
	mustChainVerify(t, path)
}

func TestListSecretAuditLocalSurfacesTornTailGap(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	path, clean := seedAuditFile(t, filepath.Join(dir, "audit"), "env:sb-1")
	mustWriteRaw(t, path, append(append([]byte{}, clean...), []byte(`{"time":"2026-`)...))

	s := &Service{
		cfg:     config.Config{DBPath: dbPath, SecretAuditRetentionDays: 30},
		store:   st,
		cluster: cluster.NewNoop("node-a", "http://a", ""),
	}
	t.Cleanup(s.CloseSecretAuditSink)
	s.ensureSecretAuditSink()
	if s.secretAuditInitErr != nil {
		t.Fatalf("sink init: %v", s.secretAuditInitErr)
	}
	for _, sandboxID := range []string{"sb-1", "sb-unrelated"} {
		events, _, err := s.ListSecretAuditLocal(context.Background(), sandboxID, SecretAuditQuery{Limit: 100})
		if err != nil {
			t.Fatalf("list %s: %v", sandboxID, err)
		}
		if len(tornMarkers(events)) != 1 {
			t.Fatalf("%s: the torn_tail gap must be visible in every sandbox's history: %+v", sandboxID, events)
		}
	}
}

func TestVerifySecretAuditWitnessAcceptsRepairedChain(t *testing.T) {
	dir := t.TempDir()
	path, clean := seedAuditFile(t, dir, "one", "two")
	mustWriteRaw(t, path, clean[:len(clean)-9])
	sink, err := newFileAuditSinkOpts(dir, 4, false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(sink.Close)
	s := &Service{secretAudit: sink, secretAuditFile: sink}
	ok, localHead, _, err := s.VerifySecretAuditWitness()
	if err != nil || !ok {
		t.Fatalf("witness verify after repair: ok=%v err=%v", ok, err)
	}
	markers := tornMarkers(readAuditEvents(t, path))
	if len(markers) != 1 || localHead != markers[0].EventHash {
		t.Fatalf("local head %s is not the repair marker %+v", localHead, markers)
	}
}

func TestFileAuditSinkPruneAfterTornTailRepair(t *testing.T) {
	dir := t.TempDir()
	path, clean := seedAuditFile(t, dir, "one", "two", "three")
	mustWriteRaw(t, path, clean[:len(clean)-12])
	sink, err := newFileAuditSinkOpts(dir, 4, false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(sink.Close)
	// Retention verifies the chain in its own pass; a repair that left a bad
	// link would surface here. Past cutoff: nothing dropped, still verifies.
	if err := sink.Prune(time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("no-op prune: %v", err)
	}
	mustChainVerify(t, path)
	// Future cutoff: everything including the marker rotates behind a
	// checkpoint and the chain is still whole.
	if err := sink.Prune(time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("full prune: %v", err)
	}
	got := readAuditEvents(t, path)
	if len(got) != 1 || got[0].Kind != secretAuditKindRetentionCheckpoint {
		t.Fatalf("after full prune: %+v", got)
	}
	mustChainVerify(t, path)
}

func TestFileAuditSinkRepeatedCrashesAccumulateMarkers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, secretAuditFileName)
	before := auditTornTailRepairsTotal.Value()
	for i := range 3 {
		sink, err := newFileAuditSinkOpts(dir, 4, false)
		if err != nil {
			t.Fatalf("round %d open: %v", i, err)
		}
		if err := sink.writeEvent(SecretAuditEvent{Result: secretAuditResultSuccess, Ref: "r"}); err != nil {
			t.Fatalf("round %d write: %v", i, err)
		}
		sink.Close()
		raw, _ := os.ReadFile(path)
		mustWriteRaw(t, path, raw[:len(raw)-6]) // crash inside the record just written
	}
	sink, err := newFileAuditSinkOpts(dir, 4, false)
	if err != nil {
		t.Fatalf("final open: %v", err)
	}
	sink.Close()
	got := readAuditEvents(t, path)
	markers := tornMarkers(got)
	if len(markers) != 3 {
		t.Fatalf("got %d markers, want 3: %+v", len(markers), got)
	}
	for _, m := range markers {
		if m.Dropped != 1 {
			t.Fatalf("marker dropped = %d, want 1", m.Dropped)
		}
	}
	if auditTornTailRepairsTotal.Value()-before != 3 {
		t.Fatal("repair counter must count every boot repair")
	}
	mustChainVerify(t, path)
}

func TestFileAuditSinkTornTailRepairUnderEnterpriseSpill(t *testing.T) {
	dir := t.TempDir()
	path, clean := seedAuditFile(t, dir, "one", "two")
	mustWriteRaw(t, path, clean[:len(clean)-4])
	sink, err := newFileAuditSinkOpts(dir, 2, true)
	if err != nil {
		t.Fatalf("enterprise open: %v", err)
	}
	if sink.bootRepair == nil {
		t.Fatal("repair not recorded on the enterprise path")
	}
	if err := sink.EmitDurable(SecretAuditEvent{Result: secretAuditResultSuccess, Ref: "durable"}); err != nil {
		t.Fatalf("durable emit after repair: %v", err)
	}
	sink.Close()
	got := readAuditEvents(t, path)
	if len(got) != 3 || got[1].Reason != secretAuditReasonTornTail || got[2].Ref != "durable" {
		t.Fatalf("events = %+v", got)
	}
	mustChainVerify(t, path)
}

// Repair must fail closed, in order, when the durable steps it depends on
// cannot complete — and must never touch the evidence when it does.
func TestFileAuditSinkTornTailRepairErrorPaths(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based fault injection is a no-op as root")
	}
	t.Run("intent sidecar unwritable leaves file untouched", func(t *testing.T) {
		dir := t.TempDir()
		path, clean := seedAuditFile(t, dir, "one", "two")
		torn := clean[:len(clean)-7]
		mustWriteRaw(t, path, torn)
		// Read-only dir: the flock sidecar and JSONL already exist and open
		// read-only, but the durable intent record cannot be created.
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		sink, err := newFileAuditSinkOpts(dir, 4, false)
		if err == nil {
			sink.Close()
			t.Fatal("open succeeded without recording repair intent")
		}
		if !strings.Contains(err.Error(), "record secret audit torn-tail repair") {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = os.Chmod(dir, 0o700)
		after, _ := os.ReadFile(path)
		if !bytes.Equal(after, torn) {
			t.Fatal("evidence was modified before intent was durable")
		}
	})
	t.Run("unwritable jsonl fails after intent is durable", func(t *testing.T) {
		dir := t.TempDir()
		path, clean := seedAuditFile(t, dir, "one", "two")
		torn := clean[:len(clean)-7]
		mustWriteRaw(t, path, torn)
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		sink, err := newFileAuditSinkOpts(dir, 4, false)
		if err == nil {
			sink.Close()
			t.Fatal("open succeeded on an unwritable file")
		}
		if !strings.Contains(err.Error(), "repair secret audit tail") {
			t.Fatalf("unexpected error: %v", err)
		}
		// Intent survived, so the next writable open still owes the marker.
		if loadTornTailRepair(filepath.Join(dir, secretAuditTornName)) == nil {
			t.Fatal("repair intent must persist across a failed repair")
		}
		_ = os.Chmod(path, 0o600)
		sink, err = newFileAuditSinkOpts(dir, 4, false)
		if err != nil {
			t.Fatalf("retry open: %v", err)
		}
		sink.Close()
		markers := tornMarkers(readAuditEvents(t, path))
		if len(markers) != 1 || markers[0].Dropped != 1 {
			t.Fatalf("retry must chain exactly the owed marker: %+v", markers)
		}
		mustChainVerify(t, path)
	})
	t.Run("missing newline with unwritable jsonl", func(t *testing.T) {
		dir := t.TempDir()
		path, clean := seedAuditFile(t, dir, "one")
		mustWriteRaw(t, path, clean[:len(clean)-1])
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		if sink, err := newFileAuditSinkOpts(dir, 4, false); err == nil {
			sink.Close()
			t.Fatal("open succeeded without restoring the terminator")
		} else if !strings.Contains(err.Error(), "repair secret audit tail") {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, secretAuditTornName)); !os.IsNotExist(err) {
			t.Fatal("a missing terminator is not a tear and must not record intent")
		}
	})
	t.Run("unreadable path surfaces the read error", func(t *testing.T) {
		// A directory opens but cannot be read: the scan must return the I/O
		// error rather than classify it as empty or torn.
		if _, err := scanSecretAuditChain(t.TempDir()); err == nil {
			t.Fatal("scan of a directory succeeded")
		}
		if _, _, err := RecomputeChainHead(t.TempDir()); err == nil {
			t.Fatal("RecomputeChainHead of a directory succeeded")
		}
	})
}
