package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/service"
)

// The push workers report every sweep; the daemon logs failures, logs a
// sweep that touched rows, and stays quiet for an empty queue (the common
// case, once a tick).
func TestPushSweepLogs(t *testing.T) {
	cases := []struct {
		name string
		log  func(*slog.Logger)
		want string
	}{
		{"snapshot failure", func(l *slog.Logger) {
			logSnapshotPushSweep(l, service.SnapshotPushReconcileStats{}, errors.New("db gone"))
		}, "snapshot push reconcile sweep failed"},
		{"snapshot sweep", func(l *slog.Logger) {
			logSnapshotPushSweep(l, service.SnapshotPushReconcileStats{Scanned: 2, Succeeded: 2}, nil)
		}, "snapshot push reconcile sweep"},
		{"snapshot idle", func(l *slog.Logger) {
			logSnapshotPushSweep(l, service.SnapshotPushReconcileStats{}, nil)
		}, ""},
		{"template failure", func(l *slog.Logger) {
			logTemplatePushSweep(l, service.TemplateArtifactPushStats{}, errors.New("db gone"))
		}, "template push reconcile sweep failed"},
		{"template sweep", func(l *slog.Logger) {
			logTemplatePushSweep(l, service.TemplateArtifactPushStats{Scanned: 1, Failed: 1}, nil)
		}, "template push reconcile sweep"},
		{"template idle", func(l *slog.Logger) {
			logTemplatePushSweep(l, service.TemplateArtifactPushStats{}, nil)
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.log(slog.New(slog.NewTextHandler(&buf, nil)))
			if tc.want == "" {
				if buf.Len() != 0 {
					t.Fatalf("idle sweep logged %q", buf.String())
				}
				return
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Fatalf("log = %q, want %q", buf.String(), tc.want)
			}
		})
	}
}
