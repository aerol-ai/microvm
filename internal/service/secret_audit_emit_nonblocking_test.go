package service

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// pinAuditWriter holds the audit flock so the writer goroutine stalls at its
// next append (or spill drain), the way a long retention rewrite or an fsync
// stall holds it in production. It returns once the channel is full and has
// stayed full, i.e. the writer is provably parked. release lets it go.
func pinAuditWriter(t *testing.T, sink *fileAuditSink) (release func()) {
	t.Helper()
	held := make(chan struct{})
	free := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = auditlog.WithFileLock(sink.lockPath, func() error {
			close(held)
			<-free
			return nil
		})
	}()
	<-held
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; ; i++ {
		for len(sink.ch) < cap(sink.ch) {
			sink.Emit(SecretAuditEvent{EventID: fmt.Sprintf("fill-%d", i), SandboxID: "sb", Result: secretAuditResultSuccess})
			i++
		}
		// The writer consumes at most one request before it meets the lock;
		// a buffer that stays full means it is parked behind it.
		time.Sleep(50 * time.Millisecond)
		if len(sink.ch) == cap(sink.ch) {
			break
		}
		if time.Now().After(deadline) {
			close(free)
			<-done
			t.Fatal("could not park the audit writer behind the flock")
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			close(free)
			<-done
		})
	}
}

// Sync, EmitDurable and Prune legitimately wait for a slot when the writer is
// busy — retention on a large file holds it for a long time. That wait must
// never be taken while excluding Emit, or every secret open on StartSandbox
// stalls behind a blocked witness ship or worker ingest for the whole prune.
// Emit takes the overflow path (spill or gap) and returns at once.
func TestFileAuditSinkEmitNeverWaitsBehindBlockedSenders(t *testing.T) {
	blockers := map[string]func(*fileAuditSink) error{
		"sync": func(s *fileAuditSink) error { return s.Sync() },
		"emit_durable": func(s *fileAuditSink) error {
			return s.EmitDurable(SecretAuditEvent{EventID: "durable", SandboxID: "sb", Result: secretAuditResultSuccess})
		},
		"prune": func(s *fileAuditSink) error { return s.Prune(time.Now().UTC().Add(-time.Hour)) },
	}
	for name, block := range blockers {
		t.Run(name, func(t *testing.T) {
			sink, err := newFileAuditSink(t.TempDir(), 2)
			if err != nil {
				t.Fatal(err)
			}
			release := pinAuditWriter(t, sink)
			t.Cleanup(func() {
				release()
				sink.Close()
			})

			blocked := make(chan error, 1)
			go func() { blocked <- block(sink) }()
			time.Sleep(50 * time.Millisecond) // let the sender reach its wait for a slot

			dropped := auditEventsDroppedTotal.Value()
			returned := make(chan struct{})
			go func() {
				defer close(returned)
				sink.Emit(SecretAuditEvent{EventID: "request-path", SandboxID: "sb", Result: secretAuditResultSuccess})
			}()
			select {
			case <-returned:
			case <-time.After(500 * time.Millisecond):
				t.Fatalf("Emit waited behind a blocked %s sender: the request path stalled for the writer's whole outage", name)
			}
			if auditEventsDroppedTotal.Value() != dropped+1 {
				t.Fatalf("a full buffer must take the overflow path (dropped +%d)", auditEventsDroppedTotal.Value()-dropped)
			}

			release()
			select {
			case err := <-blocked:
				if err != nil {
					t.Fatalf("%s after the writer resumed: %v", name, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s never completed after the writer resumed", name)
			}
		})
	}
}

// Every sender racing Close: none may send on the closed channel (the reason
// sendMu exists) and none may deadlock with Close waiting for it.
// Repro under -race -count=50.
func TestFileAuditSinkAllSendersRaceClose(t *testing.T) {
	sink, err := newFileAuditSinkOpts(t.TempDir(), 4, true)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				ev := SecretAuditEvent{EventID: fmt.Sprintf("g%d-%d", i, n), SandboxID: "sb", Result: secretAuditResultSuccess}
				switch n % 4 {
				case 0:
					sink.Emit(ev)
				case 1:
					_ = sink.EmitDurable(ev)
				case 2:
					_ = sink.Sync()
				default:
					_ = sink.Prune(time.Now().UTC().Add(-time.Hour))
				}
			}
		}(i)
	}
	time.Sleep(30 * time.Millisecond)
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		sink.Close()
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close deadlocked against in-flight senders")
	}
	close(stop)
	wg.Wait()
	if err := sink.EmitDurable(SecretAuditEvent{EventID: "late"}); err == nil {
		t.Fatal("EmitDurable after Close must fail, not hang or panic")
	}
	if err := sink.Sync(); err != nil {
		t.Fatalf("Sync after Close must be a no-op: %v", err)
	}
}
