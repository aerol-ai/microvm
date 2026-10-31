package sessions

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestManagerCreateStartsFromBaseEnv: a session starts from Config.BaseEnv
// (toolboxd passes the sandbox env a Firecracker host pushed), and the
// session request's own env wins over it.
func TestManagerCreateStartsFromBaseEnv(t *testing.T) {
	mgr, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
		SandboxID:    "sb-base-env",
		RecordingDir: t.TempDir(),
		BaseEnv: func() []string {
			return []string{"PATH=/usr/bin:/bin", "FROM_BASE=base", "SHARED=base"}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(mgr.Close)
	sess, err := mgr.Create(context.Background(), models.CreateSessionRequest{
		Command: `printf '%s|%s' "$FROM_BASE" "$SHARED"`,
		Env:     map[string]string{"SHARED": "request"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	select {
	case <-sess.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("session did not exit")
	}
	if got := string(sess.Replay()); !strings.Contains(got, "base|request") {
		t.Fatalf("session output = %q, want base|request", got)
	}
}
