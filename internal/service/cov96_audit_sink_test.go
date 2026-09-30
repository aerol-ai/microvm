package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// cov96aLink links ev onto prev and returns it with its JSON line.
func cov96aLink(t *testing.T, prev string, ev SecretAuditEvent) (SecretAuditEvent, []byte) {
	t.Helper()
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	if ev.Result == "" {
		ev.Result = secretAuditResultSuccess
	}
	ensureSecretAuditEventID(&ev)
	auditlog.LinkEvent(prev, &ev)
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return ev, raw
}

// cov96aChain links events from genesis and returns one JSON line per event.
func cov96aChain(t *testing.T, events ...SecretAuditEvent) [][]byte {
	t.Helper()
	prev := auditlog.GenesisPrevHash
	lines := make([][]byte, 0, len(events))
	for _, ev := range events {
		linked, raw := cov96aLink(t, prev, ev)
		prev = linked.EventHash
		lines = append(lines, raw)
	}
	return lines
}

func cov96aJoin(lines ...[]byte) []byte {
	var out []byte
	for _, l := range lines {
		out = append(append(out, l...), '\n')
	}
	return out
}

func cov96aBig(n int) []byte {
	return bytes.Repeat([]byte{'q'}, n)
}

func cov96aWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// cov96aManualSink opens a sink the way newFileAuditSink does, minus the
// writer goroutine, so tests drive appendBatchLocked/pruneLocked directly.
func cov96aManualSink(t *testing.T) *fileAuditSink {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &fileAuditSink{
		ch:               make(chan auditWriteReq, 8),
		spillCh:          make(chan SecretAuditEvent, 8),
		done:             make(chan struct{}),
		path:             filepath.Join(dir, secretAuditFileName),
		lockPath:         filepath.Join(dir, auditlog.LockFileName),
		gapPath:          filepath.Join(dir, "secrets.gap"),
		tipPath:          filepath.Join(dir, "secrets.tip"),
		spillPath:        filepath.Join(dir, auditlog.SpillFileName),
		spillWorkingPath: filepath.Join(dir, secretAuditSpillWorking),
		tornPath:         filepath.Join(dir, secretAuditTornName),
		verifiedPath:     filepath.Join(dir, secretAuditVerifiedName),
		witnessTipPath:   filepath.Join(dir, secretAuditWitnessTipFile),
		bootVerify:       secretAuditBootVerifyFull,
	}
	if err := s.withAuditFileLock(s.openLocked); err != nil {
		t.Fatalf("open manual sink: %v", err)
	}
	t.Cleanup(func() {
		if s.file != nil {
			_ = s.file.Close()
		}
	})
	return s
}

// cov96aRawSink is a sink over an existing file with only the fields prune
// and drain need; the append handle is opened so a successful rewrite can
// swap it.
func cov96aRawSink(t *testing.T, path string) *fileAuditSink {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	s := &fileAuditSink{path: path, lockPath: path + ".lock", file: f}
	t.Cleanup(func() { _ = s.file.Close() })
	return s
}

func cov96aOpen(sandboxID string, at time.Time) SecretAuditEvent {
	return SecretAuditEvent{Time: at, SandboxID: sandboxID, IncarnationID: "inc", Kind: secretAuditKindSecretOpen,
		Result: secretAuditResultSuccess, Reason: secretAuditReasonOK}
}

func TestCov96AuditPruneLockedGuards(t *testing.T) {
	now := time.Now().UTC()

	t.Run("missing directory", func(t *testing.T) {
		dir := t.TempDir()
		s := &fileAuditSink{path: filepath.Join(dir, "gone", "secrets.jsonl"), lockPath: filepath.Join(dir, "lock")}
		if err := s.pruneLocked(now, "", ""); err != nil {
			t.Fatalf("prune under a missing directory = %v", err)
		}
	})

	t.Run("generation unreadable", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secrets.jsonl")
		cov96aWrite(t, path, append(cov96aBig(secretAuditMaxLineBytes+64), '\n'))
		s := &fileAuditSink{path: path, lockPath: path + ".lock"}
		cursor := filepath.Join(t.TempDir(), "cursor.json")
		if err := s.pruneLocked(now, cursor, ""); err == nil {
			t.Fatal("prune with an unreadable generation succeeded")
		}
	})

	t.Run("too long in first pass", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secrets.jsonl")
		lines := cov96aChain(t, cov96aOpen("sb", now.Add(-2*time.Hour)))
		cov96aWrite(t, path, append(cov96aJoin(lines...), append(cov96aBig(secretAuditMaxLineBytes+64), '\n')...))
		s := &fileAuditSink{path: path, lockPath: path + ".lock"}
		if err := s.pruneLocked(now, "", ""); err == nil || !strings.Contains(err.Error(), "over") {
			t.Fatalf("oversized record = %v", err)
		}
	})

	t.Run("checkpoint time out of range", func(t *testing.T) {
		// The checkpoint takes the cutoff as its time; a year past 9999 cannot
		// be encoded, so the rewrite aborts after creating its temp file.
		path := filepath.Join(t.TempDir(), "secrets.jsonl")
		cov96aWrite(t, path, cov96aJoin(cov96aChain(t, cov96aOpen("sb", now))...))
		s := cov96aRawSink(t, path)
		if err := s.pruneLocked(time.Date(10001, 1, 1, 0, 0, 0, 0, time.UTC), "", ""); err == nil {
			t.Fatal("unencodable checkpoint accepted")
		}
		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("temp file left behind: %v", err)
		}
	})
}

func TestCov96AuditPruneLockedWitnessedCheckpoint(t *testing.T) {
	now := time.Now().UTC()
	s := cov96aManualSink(t)
	if err := s.writeEventBatch([]SecretAuditEvent{cov96aOpen("sb-old", now.Add(-3*time.Hour)), cov96aOpen("sb-new", now)}, true, false); err != nil {
		t.Fatal(err)
	}
	if err := s.pruneLocked(now.Add(-time.Hour), "", ""); err != nil {
		t.Fatalf("first prune: %v", err)
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := bytes.Cut(raw, []byte{'\n'})
	var cp SecretAuditEvent
	if err := json.Unmarshal(first, &cp); err != nil || cp.Kind != secretAuditKindRetentionCheckpoint {
		t.Fatalf("leading record = %+v, %v", cp, err)
	}
	// The witness is parked on the checkpoint itself; nothing else expired.
	if err := s.pruneLocked(now.Add(-time.Hour), "", cp.EventHash); err != nil {
		t.Fatalf("prune witnessed at the checkpoint: %v", err)
	}
}

func TestCov96AuditPruneLockedRenormalizesWhitespace(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "secrets.jsonl")
	lines := cov96aChain(t, cov96aOpen("sb-old", now.Add(-3*time.Hour)), cov96aOpen("sb-new", now))
	data := append(append([]byte{}, lines[0]...), '\n')
	data = append(append(data, lines[1]...), []byte("   \n")...)
	cov96aWrite(t, path, data)
	s := cov96aRawSink(t, path)
	var shift secretAuditPruneShift
	s.onPruneShift = func(sh secretAuditPruneShift) { shift = sh }
	if err := s.pruneLocked(now.Add(-time.Hour), "", ""); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if shift.exact {
		t.Fatal("trimmed trailing whitespace still reported an exact shift")
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("   \n")) {
		t.Fatal("whitespace survived the rewrite")
	}
}

func TestCov96AuditDrainSpillPaths(t *testing.T) {
	gap := func(t *testing.T) []byte {
		t.Helper()
		line, err := json.Marshal(auditlog.SpillRecord{Event: SecretAuditEvent{EventID: "g", Kind: secretAuditKindGap, Result: secretAuditResultGap, Dropped: 1}})
		if err != nil {
			t.Fatal(err)
		}
		return append(line, '\n')
	}

	t.Run("blank segment with default working path", func(t *testing.T) {
		s := cov96aManualSink(t)
		s.spillWorkingPath = ""
		cov96aWrite(t, s.spillPath, []byte("\n  \n\n"))
		if !s.drainSpill() {
			t.Fatal("blank segment not drained")
		}
		if _, err := os.Stat(s.spillPath + ".working"); !os.IsNotExist(err) {
			t.Fatalf("default working segment left behind: %v", err)
		}
	})

	t.Run("spill path under a file", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "blocker")
		cov96aWrite(t, blocker, []byte("x"))
		s := &fileAuditSink{spillPath: filepath.Join(blocker, "spill.jsonl"), lockPath: filepath.Join(dir, "lock")}
		if s.drainSpill() {
			t.Fatal("drain under a regular file reported work")
		}
	})

	t.Run("rename into a missing directory", func(t *testing.T) {
		dir := t.TempDir()
		s := &fileAuditSink{
			spillPath:        filepath.Join(dir, "spill.jsonl"),
			spillWorkingPath: filepath.Join(dir, "missing", "spill.working"),
			lockPath:         filepath.Join(dir, "lock"),
		}
		cov96aWrite(t, s.spillPath, gap(t))
		if s.drainSpill() {
			t.Fatal("drain with an unrenameable segment reported work")
		}
	})

	t.Run("unreadable working segment", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads mode-0 files")
		}
		s := cov96aManualSink(t)
		cov96aWrite(t, s.spillWorkingPath, gap(t))
		if err := os.Chmod(s.spillWorkingPath, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(s.spillWorkingPath, 0o600) })
		if s.drainSpill() {
			t.Fatal("unreadable working segment drained")
		}
	})

	t.Run("working segment is a directory resumed at an offset", func(t *testing.T) {
		s := cov96aManualSink(t)
		if err := os.MkdirAll(filepath.Join(s.spillWorkingPath, "child"), 0o700); err != nil {
			t.Fatal(err)
		}
		cov96aWrite(t, s.spillWorkingPath+".off", []byte("5\n"))
		if s.drainSpill() {
			t.Fatal("directory drained as a segment")
		}
	})

	t.Run("append fails", func(t *testing.T) {
		s := cov96aManualSink(t)
		s.writePoison = errors.New("poisoned")
		cov96aWrite(t, s.spillWorkingPath, gap(t))
		if s.drainSpill() {
			t.Fatal("drain into a poisoned writer succeeded")
		}
	})

	t.Run("offset cannot be persisted", func(t *testing.T) {
		s := cov96aManualSink(t)
		cov96aWrite(t, s.spillWorkingPath, gap(t))
		off := s.spillWorkingPath + ".off"
		if err := os.MkdirAll(filepath.Join(off, "child"), 0o700); err != nil {
			t.Fatal(err)
		}
		if s.drainSpill() {
			t.Fatal("drain without a persistable offset succeeded")
		}
	})

	t.Run("full batch ending in an oversized line", func(t *testing.T) {
		s := cov96aManualSink(t)
		s.writePoison = errors.New("poisoned")
		payload := bytes.Repeat([]byte("x\n"), spillBatchMax-1)
		payload = append(append(payload, cov96aBig(auditIngestMaxBody+64)...), '\n')
		cov96aWrite(t, s.spillWorkingPath, payload)
		if s.drainSpill() {
			t.Fatal("full oversized batch drained into a poisoned writer")
		}
	})

	t.Run("full batch of malformed lines", func(t *testing.T) {
		s := cov96aManualSink(t)
		s.writePoison = errors.New("poisoned")
		cov96aWrite(t, s.spillWorkingPath, bytes.Repeat([]byte("x\n"), spillBatchMax))
		if s.drainSpill() {
			t.Fatal("full batch drained into a poisoned writer")
		}
	})
}

func TestCov96AuditAppendBatchLocked(t *testing.T) {
	t.Run("empty file starts at genesis", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secrets.jsonl")
		cov96aWrite(t, path, nil)
		s := cov96aRawSink(t, path)
		lines, err := s.appendBatchLocked([]SecretAuditEvent{cov96aOpen("sb", time.Time{})}, false)
		if err != nil || len(lines) != 1 || lines[0].ev.PrevHash != auditlog.GenesisPrevHash {
			t.Fatalf("append = %+v, %v", lines, err)
		}
	})

	t.Run("unencodable event", func(t *testing.T) {
		s := cov96aRawSink(t, filepath.Join(t.TempDir(), "secrets.jsonl"))
		s.chainHead = "head"
		ev := cov96aOpen("sb", time.Date(10001, 1, 1, 0, 0, 0, 0, time.UTC))
		if _, err := s.appendBatchLocked([]SecretAuditEvent{ev}, false); err == nil {
			t.Fatal("event with an out-of-range time appended")
		}
	})

	t.Run("closed append handle", func(t *testing.T) {
		s := cov96aRawSink(t, filepath.Join(t.TempDir(), "secrets.jsonl"))
		s.chainHead = "head"
		_ = s.file.Close()
		if _, err := s.appendBatchLocked([]SecretAuditEvent{cov96aOpen("sb", time.Time{})}, false); err == nil {
			t.Fatal("append to a closed handle succeeded")
		}
	})
}

// cov96aHookHandler runs fn once, the first time a record with msg is logged.
// The indexer logs its rebuild between snapshotting the file and committing,
// which is the window these tests perturb.
type cov96aHookHandler struct {
	msg  string
	fn   func()
	once *sync.Once
}

func (h cov96aHookHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h cov96aHookHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Message == h.msg {
		h.once.Do(h.fn)
	}
	return nil
}
func (h cov96aHookHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h cov96aHookHandler) WithGroup(string) slog.Handler      { return h }

func cov96aStore(t *testing.T) *storepkg.Store {
	t.Helper()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// cov96aReplace swaps in a new inode the way retention does, so a handle the
// indexer already holds keeps reading the old bytes.
func cov96aReplace(path string, data []byte) {
	tmp := path + ".swap"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}

const cov96aRebuildMsg = "building secret audit index from the local log"

func TestCov96AuditIndexCatchUp(t *testing.T) {
	now := time.Now().UTC()
	indexFor := func(t *testing.T, data []byte, fn func(path string)) (*secretAuditIndexer, string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "secrets.jsonl")
		cov96aWrite(t, path, data)
		sink := &fileAuditSink{path: path, lockPath: path + ".lock"}
		logger := slog.New(slog.DiscardHandler)
		if fn != nil {
			logger = slog.New(cov96aHookHandler{msg: cov96aRebuildMsg, fn: func() { fn(path) }, once: &sync.Once{}})
		}
		return newSecretAuditIndexer(cov96aStore(t), sink, logger), path
	}
	record := cov96aJoin(cov96aChain(t, cov96aOpen("sb-idx", now))...)

	t.Run("stopped", func(t *testing.T) {
		idx, _ := indexFor(t, record, nil)
		idx.Close()
		if err := idx.catchUp(); err != nil {
			t.Fatalf("stopped catch-up = %v", err)
		}
	})

	t.Run("malformed record", func(t *testing.T) {
		idx, _ := indexFor(t, []byte("not-json\n"), nil)
		if err := idx.catchUp(); err == nil {
			t.Fatal("malformed record indexed")
		}
	})

	t.Run("only a torn tail", func(t *testing.T) {
		idx, _ := indexFor(t, []byte(`{"partial":`), nil)
		if err := idx.catchUp(); err != nil {
			t.Fatalf("torn-only file = %v", err)
		}
		if !idx.isReady() {
			t.Fatal("index not ready over a torn-only file")
		}
	})

	t.Run("file removed before commit", func(t *testing.T) {
		idx, _ := indexFor(t, record, func(path string) { _ = os.Rename(path, path+".moved") })
		if err := idx.catchUp(); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("vanished file = %v", err)
		}
	})

	t.Run("replacement generation unreadable", func(t *testing.T) {
		idx, _ := indexFor(t, record, func(path string) {
			cov96aReplace(path, append(cov96aBig(secretAuditMaxLineBytes+64), '\n'))
		})
		if err := idx.catchUp(); err == nil {
			t.Fatal("unreadable replacement indexed")
		}
	})

	t.Run("generation changes then settles", func(t *testing.T) {
		other := cov96aJoin(cov96aChain(t, cov96aOpen("sb-other", now.Add(time.Second)))...)
		idx, _ := indexFor(t, record, func(path string) { cov96aReplace(path, other) })
		if err := idx.catchUp(); err != nil {
			t.Fatalf("catch-up across a generation change = %v", err)
		}
		if !idx.isReady() || idx.meta.Generation != auditGenerationOfLine(bytes.TrimSpace(other)) {
			t.Fatalf("index meta = %+v, ready %v", idx.meta, idx.isReady())
		}
	})
}
