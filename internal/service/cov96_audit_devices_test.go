package service

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// A character device accepts the append but refuses fsync, so the durable
// append rolls back and poisons the writer. Where the device also refuses the
// truncate the rollback fails one step earlier; both end poisoned.
func TestCov96AuditAppendBatchLockedDurableSyncFails(t *testing.T) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("no %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = devNull.Close() })
	if devNull.Sync() == nil {
		t.Skipf("%s accepts fsync here", os.DevNull)
	}
	s := &fileAuditSink{file: devNull, chainHead: "head"}
	if _, err := s.appendBatchLocked([]SecretAuditEvent{cov96aOpen("sb", time.Time{})}, true); err == nil {
		t.Fatal("durable append without fsync succeeded")
	}
	if s.writePoison == nil {
		t.Fatal("failed rollback did not poison the writer")
	}
}

// RLIMIT_FSIZE makes the append fail with EFBIG (Go ignores SIGXFSZ) on a
// file that still truncates and fsyncs, so the rollback succeeds and the
// original write error is returned without poisoning the writer. The limit is
// process-wide, so it is held only around the one call.
func TestCov96AuditAppendBatchLockedRollsBackOversizeWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.jsonl")
	s := cov96aRawSink(t, path)
	s.chainHead = "head"

	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Skipf("getrlimit: %v", err)
	}
	lowered := old
	lowered.Cur = 1
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lowered); err != nil {
		t.Skipf("setrlimit: %v", err)
	}
	// Process-wide. Restore even if the append panics, or later tests in
	// this process cannot create files.
	defer func() {
		if rerr := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); rerr != nil {
			t.Errorf("restore rlimit: %v", rerr)
		}
	}()
	_, err := s.appendBatchLocked([]SecretAuditEvent{cov96aOpen("sb", time.Time{})}, false)
	if err == nil {
		t.Fatal("append past RLIMIT_FSIZE succeeded")
	}
	if s.writePoison != nil {
		t.Fatalf("clean rollback poisoned the writer: %v", s.writePoison)
	}
	if st, statErr := os.Stat(path); statErr != nil || st.Size() != 0 {
		t.Fatalf("rollback left %v bytes (%v)", st, statErr)
	}
}

// A checkpoint line past bufio's 64 KiB buffer is written straight to the
// temp file. With a FIFO there whose reader has gone, that write fails
// (EPIPE; Go does not die on SIGPIPE for non-stdio fds) and the rewrite
// aborts. The oversized line comes from WitnessedThrough carried forward
// from the prior checkpoint.
func TestCov96AuditPruneLockedCheckpointWriteFails(t *testing.T) {
	now := time.Now().UTC()
	prior := SecretAuditEvent{
		Time:             now.Add(-5 * time.Hour),
		Result:           secretAuditResultSuccess,
		Reason:           "prune",
		Kind:             secretAuditKindRetentionCheckpoint,
		WitnessedThrough: strings.Repeat("w", 128*1024),
	}
	prior, cpLine := cov96aLink(t, auditlog.GenesisPrevHash, prior)
	expired, expiredLine := cov96aLink(t, prior.EventHash, cov96aOpen("sb-old", now.Add(-3*time.Hour)))
	_, freshLine := cov96aLink(t, expired.EventHash, cov96aOpen("sb-new", now))

	path := filepath.Join(t.TempDir(), "secrets.jsonl")
	cov96aWrite(t, path, cov96aJoin(cpLine, expiredLine, freshLine))
	s := cov96aRawSink(t, path)
	tmp := path + ".tmp"
	if err := syscall.Mkfifo(tmp, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}

	result := make(chan error, 1)
	go func() { result <- s.pruneLocked(now.Add(-time.Hour), "", "") }()
	opened := make(chan *os.File, 1)
	go func() {
		r, err := os.OpenFile(tmp, os.O_RDONLY, 0)
		if err != nil {
			opened <- nil
			return
		}
		opened <- r
	}()

	var err error
	select {
	case r := <-opened:
		if r == nil {
			t.Fatal("open fifo reader failed")
		}
		_ = r.Close()
		select {
		case err = <-result:
		case <-time.After(30 * time.Second):
			t.Fatal("prune did not finish")
		}
	case err = <-result:
		if w, werr := os.OpenFile(tmp, os.O_WRONLY|syscall.O_NONBLOCK, 0); werr == nil {
			_ = w.Close()
		}
		if r := <-opened; r != nil {
			_ = r.Close()
		}
		t.Fatalf("prune finished before opening its temp file: %v", err)
	}
	if err == nil {
		t.Fatal("checkpoint write into a closed pipe succeeded")
	}
	if _, statErr := os.Lstat(tmp); !os.IsNotExist(statErr) {
		t.Fatalf("temp fifo left behind: %v", statErr)
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil || !strings.Contains(string(raw), "sb-old") {
		t.Fatalf("aborted rewrite touched the log: %v", readErr)
	}
}

// Retention reads the file twice under the flock, but only writers that
// honour the flock are excluded. A FIFO at the temp path parks the rewrite
// between the passes; bytes appended there make pass 2 see a record pass 1
// never did, and the rewrite must abort and remove its temp file.
func TestCov96AuditPruneLockedFileChangesBetweenPasses(t *testing.T) {
	now := time.Now().UTC()
	events := []SecretAuditEvent{cov96aOpen("sb-old", now.Add(-3*time.Hour))}
	for range 8000 {
		events = append(events, cov96aOpen("sb-new", now))
	}
	data := cov96aJoin(cov96aChain(t, events...)...)
	long := append(cov96aBig(secretAuditMaxLineBytes+64), '\n')

	var last error
	for attempt := 0; attempt < 5; attempt++ {
		path := filepath.Join(t.TempDir(), "secrets.jsonl")
		cov96aWrite(t, path, data)
		s := cov96aRawSink(t, path)
		tmp := path + ".tmp"
		if err := syscall.Mkfifo(tmp, 0o600); err != nil {
			t.Skipf("mkfifo: %v", err)
		}

		result := make(chan error, 1)
		go func() { result <- s.pruneLocked(now.Add(-time.Hour), "", "") }()
		opened := make(chan *os.File, 1)
		go func() {
			r, err := os.OpenFile(tmp, os.O_RDONLY, 0)
			if err != nil {
				opened <- nil
				return
			}
			opened <- r
		}()

		select {
		case r := <-opened:
			if r == nil {
				t.Fatal("open fifo reader failed")
			}
			// The rewrite is past pass 1 once its temp open returned.
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.Write(long)
			_ = f.Close()
			go func() {
				_, _ = io.Copy(io.Discard, r)
				_ = r.Close()
			}()
			select {
			case last = <-result:
			case <-time.After(30 * time.Second):
				t.Fatal("prune did not finish")
			}
		case last = <-result:
			// Never reached the temp file: release the parked reader.
			if w, err := os.OpenFile(tmp, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = w.Close()
			}
			if r := <-opened; r != nil {
				_ = r.Close()
			}
		}
		if last != nil && strings.Contains(last.Error(), "over") {
			if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
				t.Fatalf("temp fifo left behind: %v", err)
			}
			return
		}
	}
	t.Fatalf("second pass never observed the appended record; last = %v", last)
}
