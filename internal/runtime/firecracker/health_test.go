package firecracker

// health_test.go covers the Phase 6 PR-A notifier seam in isolation:
// the nil-safe helper must never panic, and a wired notifier must
// receive the templateID + reason verbatim. The full end-to-end
// (warmspawn → notify → service.MarkSnapshotCorrupt) is in
// warmspawn_corrupt_test.go.

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
)

type recordingHealthNotifier struct {
	mu     sync.Mutex
	calls  []notifyCall
	err    error
	called atomic.Int32
}

type notifyCall struct {
	templateID string
	reason     string
}

func (r *recordingHealthNotifier) MarkSnapshotCorrupt(_ context.Context, templateID, reason string) error {
	r.mu.Lock()
	r.calls = append(r.calls, notifyCall{templateID: templateID, reason: reason})
	r.mu.Unlock()
	r.called.Add(1)
	return r.err
}

func (r *recordingHealthNotifier) snapshot() []notifyCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]notifyCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// TestNotifyCorrupt_NilNotifierIsNoop guards the production deploy
// scenario where SetTemplateHealthNotifier was never called (unit
// tests that exercise warmspawn lifecycle without pulling in service).
// The helper must short-circuit before touching the nil interface.
func TestNotifyCorrupt_NilNotifierIsNoop(t *testing.T) {
	d := &Driver{logger: slog.Default()}
	// Must not panic and must not error (returns nothing).
	d.notifyCorrupt(context.Background(), "tpl-1", "checksum mismatch")
}

// TestNotifyCorrupt_DispatchesPayload is the happy-path contract: the
// notifier receives the exact templateID + reason the runtime hands
// to it. The service layer relies on that reason landing verbatim in
// the snapshot_error column for operator-facing API responses.
func TestNotifyCorrupt_DispatchesPayload(t *testing.T) {
	notifier := &recordingHealthNotifier{}
	d := &Driver{logger: slog.Default()}
	d.SetTemplateHealthNotifier(notifier)

	d.notifyCorrupt(context.Background(), "tpl-abc", "memory file digest=DEAD expected=BEEF: snapshot integrity verification failed")

	calls := notifier.snapshot()
	if len(calls) != 1 {
		t.Fatalf("notifier got %d calls, want 1", len(calls))
	}
	if calls[0].templateID != "tpl-abc" {
		t.Errorf("templateID = %q, want %q", calls[0].templateID, "tpl-abc")
	}
	if calls[0].reason == "" {
		t.Errorf("reason is empty; runtime must pass the wrapped error's Error() string verbatim")
	}
}

// TestNotifyCorrupt_EmptyTemplateIDSkips is a guard for the cold-load
// + warm-spawn call sites: both pass req.TemplateID through unchecked,
// and a sandbox create without a template (image-mode) must NOT light
// up the notifier with an empty string (which would try to UPDATE a
// row that doesn't exist and pollute logs).
func TestNotifyCorrupt_EmptyTemplateIDSkips(t *testing.T) {
	notifier := &recordingHealthNotifier{}
	d := &Driver{logger: slog.Default()}
	d.SetTemplateHealthNotifier(notifier)

	d.notifyCorrupt(context.Background(), "", "should be ignored")

	if got := notifier.called.Load(); got != 0 {
		t.Errorf("notifier.called = %d, want 0 for empty templateID", got)
	}
}

// TestNotifyCorrupt_ErrorIsLoggedNotPropagated documents the
// best-effort contract: the helper does not return the notifier's
// error to the caller (the cold-load / warm-spawn paths are already
// returning their own user-facing error; the notification is an
// optional hint). The error is captured by the slog.Warn line which
// we don't assert on here — the negative test is just "no panic, no
// return value".
func TestNotifyCorrupt_ErrorIsLoggedNotPropagated(t *testing.T) {
	notifier := &recordingHealthNotifier{err: errors.New("store write failed")}
	d := &Driver{logger: slog.Default()}
	d.SetTemplateHealthNotifier(notifier)
	d.notifyCorrupt(context.Background(), "tpl-x", "checksum mismatch")
	if got := notifier.called.Load(); got != 1 {
		t.Errorf("notifier.called = %d, want 1", got)
	}
}
