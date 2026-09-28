package netstats

import (
	"context"
	"log/slog"
	"testing"
	"testing/fstest"
	"time"
)

func TestTickEmptyContainerRefDropsBaseline(t *testing.T) {
	mfs := fstest.MapFS{
		"100/net/dev": &fstest.MapFile{Data: []byte(sampleProcNetDev)},
	}
	reader := NewReaderFS(mfs)
	lookup := &fakeLookup{pids: map[string]int{"ref": 100}}
	lister := &fakeLister{targets: []Target{{SandboxID: "sb-1", ContainerRef: "ref"}}}
	sink := &fakeSink{}
	p := NewPoller(slog.Default(), reader, lookup, lister, sink, time.Second)

	p.tick(context.Background(), time.Unix(1000, 0))
	if len(p.baselines) != 1 {
		t.Fatalf("expected baseline after first tick, got %d", len(p.baselines))
	}

	lister.targets = []Target{{SandboxID: "sb-1", ContainerRef: ""}}
	p.tick(context.Background(), time.Unix(1001, 0))
	if len(p.baselines) != 0 {
		t.Fatalf("expected baseline dropped on empty container ref, got %d", len(p.baselines))
	}
}
