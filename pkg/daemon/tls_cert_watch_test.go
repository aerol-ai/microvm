package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// C25: a renewed certificate makes Caddy reload, once per change; a failed
// reload is tried again; an unreadable file is reported and changes nothing.
func TestWatchTLSCertificate(t *testing.T) {
	orig := tlsCertWatchInterval
	tlsCertWatchInterval = 10 * time.Millisecond
	t.Cleanup(func() { tlsCertWatchInterval = orig })

	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(cert, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	calls, failNext := 0, 1
	reload := func(context.Context) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if failNext > 0 {
			failNext--
			return false, errors.New("caddy busy")
		}
		return true, nil
	}
	var logs syncBuf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { watchTLSCertificate(ctx, cert, reload, slog.New(slog.NewTextHandler(&logs, nil))); close(done) }()
	count := func() int { mu.Lock(); defer mu.Unlock(); return calls }

	time.Sleep(60 * time.Millisecond)
	if n := count(); n != 0 {
		t.Fatalf("%d reloads with no change", n)
	}
	// A renewal: the first reload fails, the next tick succeeds, then no more.
	if err := os.WriteFile(cert, []byte("renewed"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { return count() >= 2 })
	time.Sleep(60 * time.Millisecond)
	if n := count(); n != 2 {
		t.Fatalf("%d reloads for one change (one failed), want 2", n)
	}
	// The file gone for a moment: reported, no reload.
	if err := os.Remove(cert); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { return strings.Contains(logs.String(), "cannot read the certificate") })
	if n := count(); n != 2 {
		t.Fatalf("a missing file caused a reload (%d)", n)
	}
	cancel()
	<-done
	for _, want := range []string{"trying again", "caddy reloaded its certificates"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("logs lack %q: %s", want, logs.String())
		}
	}
}

func TestWatchTLSCertificateStartsWithoutTheFile(t *testing.T) {
	var logs syncBuf
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	watchTLSCertificate(ctx, filepath.Join(t.TempDir(), "missing.crt"), func(context.Context) (bool, error) {
		t.Fatal("reloaded with no certificate")
		return false, nil
	}, slog.New(slog.NewTextHandler(&logs, nil)))
	if !strings.Contains(logs.String(), "cannot read the certificate yet") {
		t.Fatalf("logs: %s", logs.String())
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func waitUntil(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
