package store

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// seenOf returns a sandbox's stored netstats reading through the poller's
// own query.
func seenOf(t *testing.T, st *Store, id string) (NetSeen, bool) {
	t.Helper()
	targets, err := st.ListNetstatsTargets(context.Background())
	if err != nil {
		t.Fatalf("ListNetstatsTargets: %v", err)
	}
	for _, tg := range targets {
		if tg.ID == id {
			return tg.Seen, true
		}
	}
	return NetSeen{}, false
}

// TestNetSeenOldRowsAreUnknownNewRowsAreNew is the upgrade half of issue
// #69: a row the previous release wrote must be baselined (the old poller
// already credited its counters), and only a row Create makes may have its
// first reading credited whole.
func TestNetSeenOldRowsAreUnknownNewRowsAreNew(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Create(ctx, sampleSandbox("sb-old")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Back to the previous release's shape: no columns, no record of 14.
	raw := rawDB(t, path)
	for _, stmt := range []string{
		`ALTER TABLE sandboxes DROP COLUMN net_seen_pid`,
		`ALTER TABLE sandboxes DROP COLUMN net_seen_in_offset`,
		`ALTER TABLE sandboxes DROP COLUMN net_seen_out_offset`,
		`DELETE FROM schema_migrations WHERE number = 14`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	st, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if got, ok := seenOf(t, st, "sb-old"); !ok || got != (NetSeen{PID: NetSeenUnknown}) {
		t.Fatalf("old row seen = %+v (listed %v), want unknown", got, ok)
	}
	if err := st.Create(ctx, sampleSandbox("sb-new")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, ok := seenOf(t, st, "sb-new"); !ok || got != (NetSeen{PID: NetSeenNew}) {
		t.Fatalf("new row seen = %+v (listed %v), want new", got, ok)
	}
}

func TestListNetstatsTargetsListsStartedSandboxesOnly(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	for id, status := range map[string]models.SandboxStatus{
		"sb-started": models.SandboxStatusStarted,
		"sb-stopped": models.SandboxStatusStopped,
	} {
		sb := sampleSandbox(id)
		sb.Status = status
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	if _, err := st.ApplyNetCounterDeltas(ctx, []NetCounterDelta{
		{SandboxID: "sb-started", BytesIn: 5, Seen: &NetSeen{PID: 42, BytesIn: 9000, BytesOut: 5000}},
	}); err != nil {
		t.Fatalf("ApplyNetCounterDeltas: %v", err)
	}
	got, err := st.ListNetstatsTargets(ctx)
	if err != nil {
		t.Fatalf("ListNetstatsTargets: %v", err)
	}
	want := []NetstatsTarget{{ID: "sb-started", ContainerID: "container-sb-started", Seen: NetSeen{PID: 42, BytesIn: 9000, BytesOut: 5000}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %+v, want %+v", got, want)
	}

	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := st.ListNetstatsTargets(ctx); err == nil {
		t.Fatal("ListNetstatsTargets on a closed store: want an error")
	}
}

// TestApplyNetCounterDeltasStoresSeen: the reading is written by the same
// UPDATE as the bytes, a zero delta can still move it, nil leaves it, Upsert
// never touches it, and a reading that would re-arm "credit everything" is
// refused.
func TestApplyNetCounterDeltasStoresSeen(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.Create(ctx, sampleSandbox("sb-1")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	check := func(step string, wantIn, wantOut int64, wantSeen NetSeen) {
		t.Helper()
		sb, err := st.Get(ctx, "sb-1")
		if err != nil {
			t.Fatalf("%s: Get: %v", step, err)
		}
		if sb.NetworkBytesIn != wantIn || sb.NetworkBytesOut != wantOut {
			t.Fatalf("%s: counters = %d/%d, want %d/%d", step, sb.NetworkBytesIn, sb.NetworkBytesOut, wantIn, wantOut)
		}
		if got, _ := seenOf(t, st, "sb-1"); got != wantSeen {
			t.Fatalf("%s: seen = %+v, want %+v", step, got, wantSeen)
		}
	}

	if _, err := st.ApplyNetCounterDeltas(ctx, []NetCounterDelta{
		{SandboxID: "sb-1", BytesIn: 9000, BytesOut: 5000, Seen: &NetSeen{PID: 100, BytesIn: 9000, BytesOut: 5000}},
	}); err != nil {
		t.Fatalf("bytes with seen: %v", err)
	}
	check("bytes with seen", 9000, 5000, NetSeen{PID: 100, BytesIn: 9000, BytesOut: 5000})

	// A restarted container with nothing sent: the reading moves, the
	// counters do not, and the totals still come back.
	totals, err := st.ApplyNetCounterDeltas(ctx, []NetCounterDelta{
		{SandboxID: "sb-1", Seen: &NetSeen{PID: 200}},
	})
	if err != nil || len(totals) != 1 || totals[0].BytesIn != 9000 {
		t.Fatalf("zero bytes with seen: totals %+v, %v", totals, err)
	}
	check("zero bytes with seen", 9000, 5000, NetSeen{PID: 200})

	// Bytes credited with no reading (the previous release after a
	// rollback, or the WASM mediator) raise the reading with them, so the
	// poller never credits them a second time.
	if _, err := st.ApplyNetCounterDeltas(ctx, []NetCounterDelta{{SandboxID: "sb-1", BytesIn: 1}}); err != nil {
		t.Fatalf("bytes without seen: %v", err)
	}
	check("bytes without seen", 9001, 5000, NetSeen{PID: 200, BytesIn: 1})

	sb, err := st.Get(ctx, "sb-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	sb.Status = models.SandboxStatusStarted
	sb.LastError = "touched"
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	check("after upsert", 9001, 5000, NetSeen{PID: 200, BytesIn: 1})

	for _, bad := range []NetSeen{{PID: NetSeenNew}, {PID: NetSeenUnknown}, {PID: 7, BytesIn: -1}, {PID: 7, BytesOut: -1}} {
		if _, err := st.ApplyNetCounterDeltas(ctx, []NetCounterDelta{
			{SandboxID: "sb-1", BytesIn: 10},
			{SandboxID: "sb-1", Seen: &bad},
		}); err == nil {
			t.Fatalf("seen %+v: want the call rejected", bad)
		}
	}
	check("after rejected calls", 9001, 5000, NetSeen{PID: 200, BytesIn: 1})

	// A batch that fails keeps the old reading with the old counters.
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER poison_net BEFORE UPDATE OF net_bytes_in ON sandboxes
		BEGIN SELECT RAISE(ABORT, 'poisoned'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	if _, err := st.ApplyNetCounterDeltas(ctx, []NetCounterDelta{
		{SandboxID: "sb-1", BytesIn: 50, Seen: &NetSeen{PID: 200, BytesIn: 50}},
	}); err == nil {
		t.Fatal("want the poisoned batch to fail")
	}
	check("after a failed batch", 9001, 5000, NetSeen{PID: 200, BytesIn: 1})
}
