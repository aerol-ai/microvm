package netstats

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestNewReader(t *testing.T) {
	if NewReader() == nil {
		t.Fatal("NewReader returned nil")
	}
}

func TestNonNegative(t *testing.T) {
	if nonNegative(-5) != 0 {
		t.Fatal("negative should clamp to 0")
	}
	if nonNegative(7) != 7 {
		t.Fatal("positive should pass through")
	}
}

func TestPollerStartRejectsNonPositiveInterval(t *testing.T) {
	p := NewPoller(slog.Default(), NewReaderFS(fstest.MapFS{}), &fakeLookup{}, &fakeLister{}, &fakeSink{}, 0)
	if err := p.Start(context.Background()); err == nil {
		t.Fatal("Start should reject interval <= 0")
	}
}

func TestPollerStartRunsAndStops(t *testing.T) {
	mfs := fstest.MapFS{
		"100/net/dev": &fstest.MapFile{Data: []byte(sampleProcNetDev)},
	}
	reader := NewReaderFS(mfs)
	lookup := &fakeLookup{pids: map[string]int{"sb-1": 100}}
	lister := &fakeLister{targets: []Target{{SandboxID: "sb-1", ContainerRef: "sb-1"}}}
	sink := &fakeSink{}

	p := NewPoller(slog.Default(), reader, lookup, lister, sink, 5*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Give the run loop time to fire at least one tick.
	deadline := time.After(2 * time.Second)
	for {
		sink.mu.Lock()
		n := len(sink.batches)
		sink.mu.Unlock()
		if n > 0 {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("poll loop never produced a sample")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
}

type errorReader struct{}

func (errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}
func (errorReader) Close() error {
	return nil
}

type errorCloser struct {
	readCloser
}

func (e errorCloser) Close() error {
	return errors.New("close error")
}

func TestReaderErrors(t *testing.T) {
	r := NewReader()
	_, err := r.Read(9999999)
	if err != ErrNotRunning {
		t.Fatalf("expected ErrNotRunning, got %v", err)
	}

	_, err = parseNetDev(errorReader{})
	if err == nil {
		t.Fatal("expected error")
	}

	_, err = parseProcNetTCP(errorReader{})
	if err == nil {
		t.Fatal("expected error")
	}
}

type errorFS struct{}

func (errorFS) Open(name string) (fs.File, error) {
	return nil, errors.New("fs error")
}

func TestTick_Coverage(t *testing.T) {
	reader := NewReaderFS(errorFS{})

	lister1 := &fakeLister{targets: []Target{{SandboxID: "", ContainerRef: "ref"}}}
	p1 := NewPoller(slog.Default(), reader, &fakeLookup{err: errors.New("err")}, lister1, &fakeSink{}, 5*time.Millisecond)
	p1.tick(context.Background(), time.Now())

	lister2 := &fakeLister{targets: []Target{{SandboxID: "sb-1", ContainerRef: "ref"}}}
	p2 := NewPoller(slog.Default(), reader, &fakeLookup{err: errors.New("err")}, lister2, &fakeSink{}, 5*time.Millisecond)
	p2.tick(context.Background(), time.Now())

	// ErrNotRunning test
	rNotRunning := NewReader() // pointing to nonexistent proc
	p3 := NewPoller(slog.Default(), rNotRunning, &fakeLookup{pids: map[string]int{"ref": 9999999}}, lister2, &fakeSink{}, 5*time.Millisecond)
	p3.tick(context.Background(), time.Now())

	// Generic read failed
	rGenericErr := NewReaderFS(errorFS{})
	p4 := NewPoller(slog.Default(), rGenericErr, &fakeLookup{pids: map[string]int{"ref": 100}}, lister2, &fakeSink{}, 5*time.Millisecond)
	p4.tick(context.Background(), time.Now())

	// Parse bad data
	badData := "header\nheader\neth0: bad 2 3 4 5 6 7 bad 9 10 11\neth1: 1 2 3 4 5 6 7 bad 9 10 11"
	parseNetDev(stringReadCloser{strings.NewReader(badData)})
}

type stringReadCloser struct {
	io.Reader
}

func (stringReadCloser) Close() error { return nil }
