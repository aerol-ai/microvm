package netstats

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

const sampleProcNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:    1234       12    0    0    0     0          0         0     1234       12    0    0    0     0       0          0
  eth0:    9000       18    0    0    0     0          0         0     5000       11    0    0    0     0       0          0
`

func TestParseNetDevExcludesLoopback(t *testing.T) {
	fsys := fstest.MapFS{
		"42/net/dev": &fstest.MapFile{Data: []byte(sampleProcNetDev)},
	}
	r := NewReaderFS(fsys)
	got, err := r.Read(42)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.BytesIn != 9000 || got.BytesOut != 5000 {
		t.Fatalf("unexpected counters: %+v", got)
	}
}

func TestReadMissingPIDReturnsNotRunning(t *testing.T) {
	r := NewReaderFS(fstest.MapFS{})
	_, err := r.Read(99)
	if !errors.Is(err, ErrNotRunning) {
		t.Fatalf("expected ErrNotRunning, got %v", err)
	}
	if _, err := r.Read(0); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("pid 0 should be ErrNotRunning, got %v", err)
	}
}

type fakeLookup struct {
	mu   sync.Mutex
	pids map[string]int
	err  error
}

func (f *fakeLookup) ContainerPID(_ context.Context, ref string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	return f.pids[ref], nil
}

type fakeLister struct {
	targets []Target
}

func (f *fakeLister) NetstatsTargets(_ context.Context) []Target { return f.targets }

type fakeSink struct {
	mu      sync.Mutex
	batches [][]Sample
}

func (f *fakeSink) HandleSamples(_ context.Context, samples []Sample) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]Sample, len(samples))
	copy(cp, samples)
	f.batches = append(f.batches, cp)
}

func TestPollerEstablishesBaselineThenEmitsDelta(t *testing.T) {
	mfs := fstest.MapFS{
		"100/net/dev": &fstest.MapFile{Data: []byte(sampleProcNetDev)},
	}
	reader := NewReaderFS(mfs)
	lookup := &fakeLookup{pids: map[string]int{"sb-1": 100}}
	lister := &fakeLister{targets: []Target{{SandboxID: "sb-1", ContainerRef: "sb-1"}}}
	sink := &fakeSink{}

	p := NewPoller(slog.Default(), reader, lookup, lister, sink, time.Second)

	// First tick: baseline only — Sample with zero deltas.
	p.tick(context.Background(), time.Unix(1000, 0))
	if len(sink.batches) != 1 || len(sink.batches[0]) != 1 {
		t.Fatalf("expected 1 sample on first tick, got %#v", sink.batches)
	}
	first := sink.batches[0][0]
	if first.BytesIn != 0 || first.BytesOut != 0 {
		t.Fatalf("first tick should have zero deltas, got %+v", first)
	}

	// Second tick after counters grow.
	growing := []byte(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:    1234       12    0    0    0     0          0         0     1234       12    0    0    0     0       0          0
  eth0:   12000       18    0    0    0     0          0         0     7500       11    0    0    0     0       0          0
`)
	mfs["100/net/dev"] = &fstest.MapFile{Data: growing}

	p.tick(context.Background(), time.Unix(1001, 0))
	if len(sink.batches) != 2 {
		t.Fatalf("expected 2 batches, got %d", len(sink.batches))
	}
	second := sink.batches[1][0]
	if second.BytesIn != 3000 || second.BytesOut != 2500 {
		t.Fatalf("expected delta 3000/2500, got %+v", second)
	}
}

func TestPollerResetsBaselineOnPIDChange(t *testing.T) {
	mfs := fstest.MapFS{
		"100/net/dev": &fstest.MapFile{Data: []byte(sampleProcNetDev)},
	}
	reader := NewReaderFS(mfs)
	lookup := &fakeLookup{pids: map[string]int{"sb-1": 100}}
	lister := &fakeLister{targets: []Target{{SandboxID: "sb-1", ContainerRef: "sb-1"}}}
	sink := &fakeSink{}

	p := NewPoller(slog.Default(), reader, lookup, lister, sink, time.Second)
	p.tick(context.Background(), time.Unix(1000, 0)) // baseline @ pid 100

	// Container restarts: new PID, fresh procfs entry with smaller cumulative.
	delete(mfs, "100/net/dev")
	smaller := []byte(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:       0        0    0    0    0     0          0         0        0        0    0    0    0     0       0          0
  eth0:     500        2    0    0    0     0          0         0      300        1    0    0    0     0       0          0
`)
	mfs["200/net/dev"] = &fstest.MapFile{Data: smaller}
	lookup.pids["sb-1"] = 200

	p.tick(context.Background(), time.Unix(1001, 0))
	if len(sink.batches) != 2 {
		t.Fatalf("expected 2 batches, got %d", len(sink.batches))
	}
	got := sink.batches[1][0]
	if got.BytesIn != 0 || got.BytesOut != 0 {
		t.Fatalf("PID change should reset baseline (zero delta), got %+v", got)
	}
}

func TestPollerSkipsStoppedContainers(t *testing.T) {
	reader := NewReaderFS(fstest.MapFS{}) // no procfs entries
	lookup := &fakeLookup{pids: map[string]int{"sb-stopped": 0}}
	lister := &fakeLister{targets: []Target{{SandboxID: "sb-stopped", ContainerRef: "sb-stopped"}}}
	sink := &fakeSink{}
	p := NewPoller(slog.Default(), reader, lookup, lister, sink, time.Second)

	p.tick(context.Background(), time.Unix(1000, 0))
	if len(sink.batches) != 0 {
		t.Fatalf("expected no samples for stopped container, got %#v", sink.batches)
	}
}

func TestPollerGarbageCollectsBaselines(t *testing.T) {
	mfs := fstest.MapFS{
		"100/net/dev": &fstest.MapFile{Data: []byte(sampleProcNetDev)},
	}
	reader := NewReaderFS(mfs)
	lookup := &fakeLookup{pids: map[string]int{"sb-1": 100}}
	lister := &fakeLister{targets: []Target{{SandboxID: "sb-1", ContainerRef: "sb-1"}}}
	sink := &fakeSink{}
	p := NewPoller(slog.Default(), reader, lookup, lister, sink, time.Second)
	p.tick(context.Background(), time.Unix(1000, 0))
	if len(p.baselines) != 1 {
		t.Fatalf("expected baseline stored, got %d", len(p.baselines))
	}

	// Sandbox disappears from target list (Destroy path).
	lister.targets = nil
	p.tick(context.Background(), time.Unix(1001, 0))
	if len(p.baselines) != 0 {
		t.Fatalf("expected baselines pruned, got %d", len(p.baselines))
	}
}

// guard — the test fixture must conform to fs.FS, surface errors that aren't
// ErrNotExist as plain errors so we don't accidentally silence real bugs.
var _ fs.FS = fstest.MapFS{}
