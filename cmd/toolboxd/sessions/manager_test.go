package sessions

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	mgr, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
		SandboxID:    "sb-test",
		RecordingDir: dir,
		BufferBytes:  1 << 14,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(mgr.Close)
	return mgr
}

func TestManagerCreatePipeSessionRunsCommand(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	sess, err := mgr.Create(ctx, models.CreateSessionRequest{
		Name:    "echoer",
		Command: "echo hello-world",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session did not exit within 5s")
	}

	code, signal := sess.ExitInfo()
	if code != 0 || signal != "" {
		t.Fatalf("unexpected exit: code=%d signal=%q", code, signal)
	}
	replay := sess.Replay()
	if !strings.Contains(string(replay), "hello-world") {
		t.Fatalf("expected replay to contain hello-world, got %q", string(replay))
	}
	snap := sess.Snapshot()
	if snap.Status != models.SessionStatusExited {
		t.Fatalf("status: %q", snap.Status)
	}
	if snap.Bytes == 0 {
		t.Fatalf("expected non-zero bytes")
	}
}

func TestManagerGetOrCreateIsIdempotent(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	first, created, err := mgr.GetOrCreate(ctx, models.CreateSessionRequest{
		Name:    "shared",
		Command: "sleep 5",
	})
	if err != nil {
		t.Fatalf("first GetOrCreate: %v", err)
	}
	if !created {
		t.Fatal("expected first call to create the session")
	}
	t.Cleanup(func() { _ = first.Signal("KILL") })

	second, created2, err := mgr.GetOrCreate(ctx, models.CreateSessionRequest{
		Name:    "shared",
		Command: "sleep 5",
	})
	if err != nil {
		t.Fatalf("second GetOrCreate: %v", err)
	}
	if created2 {
		t.Fatal("expected second call to return existing session, not create new")
	}
	if first.ID() != second.ID() {
		t.Fatalf("expected same id; got %q vs %q", first.ID(), second.ID())
	}
}

func TestManagerListSortedByCreatedAt(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	_, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "first", Command: "true"})
	if err != nil {
		t.Fatalf("Create first: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	_, err = mgr.Create(ctx, models.CreateSessionRequest{Name: "second", Command: "true"})
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}

	all := mgr.List()
	if len(all) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(all))
	}
	if all[0].Name != "first" || all[1].Name != "second" {
		t.Fatalf("unexpected order: %s, %s", all[0].Name, all[1].Name)
	}
}

func TestManagerDeleteRemovesSession(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	sess, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "doomed", Command: "sleep 5"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := mgr.Delete(sess.ID()); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := mgr.Get(sess.ID()); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestManagerSubscribeReceivesFrames(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	sess, err := mgr.Create(ctx, models.CreateSessionRequest{
		Name:    "talker",
		Command: "printf 'one\\ntwo\\nthree\\n'",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	ch, cancel := sess.Subscribe()
	defer cancel()

	deadline := time.After(5 * time.Second)
	var got []byte
collect:
	for {
		select {
		case frame, ok := <-ch:
			if !ok {
				break collect
			}
			got = append(got, frame.Data...)
		case <-deadline:
			t.Fatal("timed out waiting for frames")
		}
	}
	if !strings.Contains(string(got), "one") || !strings.Contains(string(got), "three") {
		t.Fatalf("unexpected frames: %q", string(got))
	}
}

func TestManagerRecordingFileWritten(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()

	sess, err := mgr.Create(ctx, models.CreateSessionRequest{Name: "recorded", Command: "echo cast-me"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	<-sess.Done()

	path := sess.RecordingPath()
	if path == "" {
		t.Fatal("recording path is empty; recording should be enabled by default")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}
	// asciinema v2 first line is the header JSON.
	if !strings.HasPrefix(string(body), "{\"version\":2") {
		t.Fatalf("expected asciinema v2 header, got: %q", firstLine(string(body)))
	}
	if !strings.Contains(string(body), "cast-me") {
		t.Fatalf("recording missing payload: %q", string(body))
	}
	if filepath.Dir(path) == "" {
		t.Fatalf("path: %q", path)
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}
