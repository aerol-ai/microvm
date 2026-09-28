package sessions

import (
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestInterpretWaitProcessResultBranches(t *testing.T) {
	code, sig := interpretWaitProcessResult(nil)
	if code != 0 || sig != "" {
		t.Fatalf("nil = (%d, %q)", code, sig)
	}
	code, sig = interpretWaitProcessResult(syscall.ECHILD)
	if code != 0 || sig != "" {
		t.Fatalf("ECHILD = (%d, %q)", code, sig)
	}
	code, sig = interpretWaitProcessResult(errors.New("wait boom"))
	if code != -1 || sig != "wait boom" {
		t.Fatalf("generic = (%d, %q)", code, sig)
	}
}

func TestSubscribeCancelAfterExit(t *testing.T) {
	s := &Session{
		buf:    newRing(8),
		doneCh: make(chan struct{}),
	}
	_, _ = s.buf.Write([]byte("replay"))
	s.exited.Store(true)
	ch, cancel := s.Subscribe()
	cancel() // subscribed=false → early return
	// Exited sessions still deliver replay then close.
	got, ok := <-ch
	if !ok || string(got.Data) != "replay" {
		t.Fatalf("replay = (%q, %v)", string(got.Data), ok)
	}
	if _, ok := <-ch; ok {
		t.Fatal("expected channel closed after replay")
	}

	s2 := &Session{
		buf:    newRing(8),
		doneCh: make(chan struct{}),
	}
	ch2, cancel2 := s2.Subscribe()
	cancel2()
	cancel2() // once.Do no-op on second call
	select {
	case <-ch2:
	case <-time.After(time.Second):
		t.Fatal("expected subscriber channel closed after cancel")
	}
}
