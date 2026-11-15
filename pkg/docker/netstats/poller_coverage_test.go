package netstats

import (
	"context"
	"log/slog"
	"testing"
	"testing/fstest"
	"time"
)

// TestTickEmptyContainerRefKeepsTheReading: a sandbox with no container this
// tick is skipped, and its stored reading is left for the next one.
func TestTickEmptyContainerRefKeepsTheReading(t *testing.T) {
	mfs := fstest.MapFS{"100/net/dev": netDev(9000, 5000)}
	st := newSeenStore()
	st.refs["sb-1"] = ""
	st.seen["sb-1"] = Seen{PID: 100, BytesIn: 8000, BytesOut: 4000}
	p := NewPoller(slog.Default(), NewReaderFS(mfs), &fakeLookup{pids: map[string]int{"c-1": 100}}, st, st, time.Second)

	before := mapValue(pollDroppedTotal, "empty_container_ref")
	p.tick(context.Background(), time.Unix(1000, 0))
	if got := mapValue(pollDroppedTotal, "empty_container_ref") - before; got != 1 {
		t.Fatalf("dropped empty_container_ref delta = %d, want 1", got)
	}

	st.refs["sb-1"] = "c-1"
	p.tick(context.Background(), time.Unix(1001, 0))
	if got := st.total("sb-1"); got != [2]int64{1000, 1000} {
		t.Fatalf("credited %v, want 1000/1000 measured from the kept reading", got)
	}
}
