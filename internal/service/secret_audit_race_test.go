package service

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestFileAuditSinkClosePruneNoRace guards the shutdown race: retention Prune
// must not send on a closed writer channel (repro: go test -race -count=100).
func TestFileAuditSinkClosePruneNoRace(t *testing.T) {
	dir := t.TempDir()
	sink, err := newFileAuditSink(filepath.Join(dir, "audit"), 8)
	if err != nil {
		t.Fatalf("newFileAuditSink: %v", err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = sink.Prune(time.Now().UTC().Add(-time.Hour))
				sink.Emit(SecretAuditEvent{SandboxID: "sb", Result: secretAuditResultSuccess, Reason: secretAuditReasonOK})
			}
		}
	}()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
	sink.Close()
	// Second close + late prune must be no-ops.
	sink.Close()
	if err := sink.Prune(time.Now()); err != nil {
		t.Fatalf("Prune after Close: %v", err)
	}
}
