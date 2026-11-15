package netstats

import (
	"context"
	"errors"
	"expvar"
	"io/fs"
	"log/slog"
	"strconv"
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

const sampleProcNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0200000A:BEEF 01 00000000:00000000 00:00000000 00000000   100        0 12345 1 0000000000000000 20 4 30 10 -1
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

func TestReadMarksEstablishedTCPActive(t *testing.T) {
	fsys := fstest.MapFS{
		"42/net/dev": &fstest.MapFile{Data: []byte(sampleProcNetDev)},
		"42/net/tcp": &fstest.MapFile{Data: []byte(sampleProcNetTCP)},
	}
	r := NewReaderFS(fsys)
	got, err := r.Read(42)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !got.ActiveTCP {
		t.Fatalf("ActiveTCP = false, want true")
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

// netDev renders a /proc/<pid>/net/dev with eth0 at the given counters
// (and some loopback traffic the reader must ignore).
func netDev(in, out int64) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:    1234       12    0    0    0     0          0         0     1234       12    0    0    0     0       0          0
  eth0: ` + strconv.FormatInt(in, 10) + `       18    0    0    0     0          0         0 ` + strconv.FormatInt(out, 10) + `       11    0    0    0     0       0          0
`)}
}

// seenStore is the store side of the poller contract: it lists targets with
// their stored reading, and the sink stores each Sample.Seen with its bytes.
// Credited holds the cumulative counters, as the sandboxes row would.
type seenStore struct {
	mu       sync.Mutex
	refs     map[string]string
	seen     map[string]Seen
	credited map[string][2]int64
	batches  [][]Sample
	// dropWrites makes the sink lose everything it is given, as a failed
	// store batch does.
	dropWrites bool
}

func newSeenStore() *seenStore {
	return &seenStore{refs: map[string]string{}, seen: map[string]Seen{}, credited: map[string][2]int64{}}
}

func (f *seenStore) NetstatsTargets(context.Context) []Target {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Target, 0, len(f.refs))
	for id, ref := range f.refs {
		out = append(out, Target{SandboxID: id, ContainerRef: ref, Seen: f.seen[id]})
	}
	return out
}

func (f *seenStore) HandleSamples(_ context.Context, samples []Sample) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = append(f.batches, append([]Sample(nil), samples...))
	if f.dropWrites {
		return
	}
	for _, s := range samples {
		c := f.credited[s.SandboxID]
		f.credited[s.SandboxID] = [2]int64{c[0] + s.BytesIn, c[1] + s.BytesOut}
		if s.Seen != nil {
			f.seen[s.SandboxID] = *s.Seen
		}
	}
}

func (f *seenStore) total(id string) [2]int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.credited[id]
}

func (f *seenStore) last() Sample {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := f.batches[len(f.batches)-1]
	if len(b) != 1 {
		panic("want one sample per batch")
	}
	return b[0]
}

// TestCreditCases is issue #69's table: which part of a reading is credited
// for each thing the stored reading can say.
func TestCreditCases(t *testing.T) {
	for _, tc := range []struct {
		name    string
		seen    Seen
		pid     int
		cur     Counters
		in, out int64
	}{
		{"new sandbox credits its whole first reading", Seen{PID: SeenNew}, 100, Counters{BytesIn: 9000, BytesOut: 5000}, 9000, 5000},
		{"unknown row is a baseline only", Seen{PID: SeenUnknown}, 100, Counters{BytesIn: 9000, BytesOut: 5000}, 0, 0},
		{"a value no build writes is a baseline only", Seen{PID: -7, BytesIn: 1, BytesOut: 1}, 100, Counters{BytesIn: 9000, BytesOut: 5000}, 0, 0},
		{"same process credits the growth", Seen{PID: 100, BytesIn: 9000, BytesOut: 5000}, 100, Counters{BytesIn: 12000, BytesOut: 7500}, 3000, 2500},
		{"same process with no traffic credits nothing", Seen{PID: 100, BytesIn: 9000, BytesOut: 5000}, 100, Counters{BytesIn: 9000, BytesOut: 5000}, 0, 0},
		{"same process, counter went down, credits nothing for it", Seen{PID: 100, BytesIn: 9000, BytesOut: 5000}, 100, Counters{BytesIn: 100, BytesOut: 6000}, 0, 1000},
		{"new process below the old reading is a new namespace", Seen{PID: 100, BytesIn: 9000, BytesOut: 5000}, 200, Counters{BytesIn: 500, BytesOut: 300}, 500, 300},
		{"new process with one counter below is a new namespace", Seen{PID: 100, BytesIn: 9000, BytesOut: 5000}, 200, Counters{BytesIn: 500, BytesOut: 8000}, 500, 8000},
		{"new process above the old reading carries the namespace on", Seen{PID: 100, BytesIn: 9000, BytesOut: 5000}, 200, Counters{BytesIn: 9500, BytesOut: 5100}, 500, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, out := credit(tc.seen, tc.pid, tc.cur)
			if in != tc.in || out != tc.out {
				t.Fatalf("credit = %d/%d, want %d/%d", in, out, tc.in, tc.out)
			}
		})
	}
}

// TestPollerCountsANewSandboxsFirstReading is issue #69: the traffic a new
// sandbox moves before the first poll used to be a baseline and never
// counted.
func TestPollerCountsANewSandboxsFirstReading(t *testing.T) {
	mfs := fstest.MapFS{"100/net/dev": netDev(9000, 5000)}
	st := newSeenStore()
	st.refs["sb-1"] = "c-1"
	st.seen["sb-1"] = Seen{PID: SeenNew}
	p := NewPoller(slog.Default(), NewReaderFS(mfs), &fakeLookup{pids: map[string]int{"c-1": 100}}, st, st, time.Second)

	p.tick(context.Background(), time.Unix(1000, 0))
	if got := st.total("sb-1"); got != [2]int64{9000, 5000} {
		t.Fatalf("first reading credited %v, want the whole 9000/5000", got)
	}

	mfs["100/net/dev"] = netDev(12000, 7500)
	p.tick(context.Background(), time.Unix(1001, 0))
	if got := st.last(); got.BytesIn != 3000 || got.BytesOut != 2500 {
		t.Fatalf("second tick = %+v, want the 3000/2500 growth", got)
	}

	// No traffic: no new reading, so the sink has nothing to write.
	p.tick(context.Background(), time.Unix(1002, 0))
	if got := st.last(); got.BytesIn != 0 || got.BytesOut != 0 || got.Seen != nil {
		t.Fatalf("idle tick = %+v, want zero bytes and no reading to store", got)
	}
	if got := st.total("sb-1"); got != [2]int64{12000, 7500} {
		t.Fatalf("credited %v, want the counters exactly", got)
	}
}

// TestPollerAcrossASandboxdRestart: a new Poller (sandboxd restarted) over
// the same store measures from the stored reading, so it neither credits
// the counters again nor drops what moved while it was down.
func TestPollerAcrossASandboxdRestart(t *testing.T) {
	mfs := fstest.MapFS{"100/net/dev": netDev(9000, 5000)}
	st := newSeenStore()
	st.refs["sb-1"] = "c-1"
	st.seen["sb-1"] = Seen{PID: SeenNew}
	lookup := &fakeLookup{pids: map[string]int{"c-1": 100}}
	NewPoller(slog.Default(), NewReaderFS(mfs), lookup, st, st, time.Second).tick(context.Background(), time.Unix(1000, 0))

	mfs["100/net/dev"] = netDev(20000, 6000) // traffic while sandboxd was down
	NewPoller(slog.Default(), NewReaderFS(mfs), lookup, st, st, time.Second).tick(context.Background(), time.Unix(2000, 0))
	if got := st.total("sb-1"); got != [2]int64{20000, 6000} {
		t.Fatalf("credited %v after the restart, want 20000/6000", got)
	}
}

// TestPollerAcrossAContainerRestart: Docker gives a restarted container a new
// namespace whose counters begin again, and the containerd engine keeps the
// namespace, so its counters carry on. Both are counted exactly.
func TestPollerAcrossAContainerRestart(t *testing.T) {
	for _, tc := range []struct {
		name        string
		afterIn     int64
		afterOut    int64
		wantIn      int64
		wantOut     int64
		description string
	}{
		{"docker: new namespace", 500, 300, 9500, 5300, "the new counters are all new traffic"},
		{"containerd: kept namespace", 9700, 5400, 9700, 5400, "only the growth is new traffic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mfs := fstest.MapFS{"100/net/dev": netDev(9000, 5000)}
			st := newSeenStore()
			st.refs["sb-1"] = "c-1"
			st.seen["sb-1"] = Seen{PID: SeenNew}
			lookup := &fakeLookup{pids: map[string]int{"c-1": 100}}
			p := NewPoller(slog.Default(), NewReaderFS(mfs), lookup, st, st, time.Second)
			p.tick(context.Background(), time.Unix(1000, 0))

			// Stopped for a tick: nothing credited, the reading stays.
			lookup.pids["c-1"] = 0
			p.tick(context.Background(), time.Unix(1001, 0))

			delete(mfs, "100/net/dev")
			mfs["200/net/dev"] = netDev(tc.afterIn, tc.afterOut)
			lookup.pids["c-1"] = 200
			p.tick(context.Background(), time.Unix(1002, 0))
			if got := st.total("sb-1"); got != [2]int64{tc.wantIn, tc.wantOut} {
				t.Fatalf("credited %v, want %d/%d: %s", got, tc.wantIn, tc.wantOut, tc.description)
			}
		})
	}
}

// TestPollerRestartWithNoTrafficStoresTheNewReading: a restarted container
// that has sent nothing yet still has its reading stored, so traffic that
// later passes the old reading is not mistaken for a carried-on counter.
func TestPollerRestartWithNoTrafficStoresTheNewReading(t *testing.T) {
	mfs := fstest.MapFS{"100/net/dev": netDev(9000, 5000)}
	st := newSeenStore()
	st.refs["sb-1"] = "c-1"
	st.seen["sb-1"] = Seen{PID: 100, BytesIn: 9000, BytesOut: 5000}
	lookup := &fakeLookup{pids: map[string]int{"c-1": 200}}
	mfs["200/net/dev"] = netDev(0, 0)
	p := NewPoller(slog.Default(), NewReaderFS(mfs), lookup, st, st, time.Second)
	p.tick(context.Background(), time.Unix(1000, 0))
	got := st.last()
	if got.BytesIn != 0 || got.BytesOut != 0 || got.Seen == nil || *got.Seen != (Seen{PID: 200}) {
		t.Fatalf("restart with no traffic = %+v, want zero bytes and reading {200 0 0} to store", got)
	}

	mfs["200/net/dev"] = netDev(10000, 6000)
	p.tick(context.Background(), time.Unix(1001, 0))
	if got := st.total("sb-1"); got != [2]int64{10000, 6000} {
		t.Fatalf("credited %v, want all 10000/6000 of the new namespace", got)
	}
}

// TestPollerUnknownRowIsBaselinedOnce: a row from before readings were
// stored is baselined on its first reading (it was credited by the old
// poller), then counted from there.
func TestPollerUnknownRowIsBaselinedOnce(t *testing.T) {
	mfs := fstest.MapFS{"100/net/dev": netDev(9000, 5000)}
	st := newSeenStore()
	st.refs["sb-1"] = "c-1" // st.seen has no entry: SeenUnknown
	p := NewPoller(slog.Default(), NewReaderFS(mfs), &fakeLookup{pids: map[string]int{"c-1": 100}}, st, st, time.Second)
	p.tick(context.Background(), time.Unix(1000, 0))
	if got := st.last(); got.BytesIn != 0 || got.BytesOut != 0 || got.Seen == nil {
		t.Fatalf("unknown row's first tick = %+v, want a stored baseline and zero bytes", got)
	}
	mfs["100/net/dev"] = netDev(9100, 5050)
	p.tick(context.Background(), time.Unix(1001, 0))
	if got := st.total("sb-1"); got != [2]int64{100, 50} {
		t.Fatalf("credited %v, want 100/50 after the baseline", got)
	}
}

// TestPollerLostWriteIsCountedNextTick: the poller keeps no reading of its
// own, so bytes a failed store write lost come back on the next tick.
func TestPollerLostWriteIsCountedNextTick(t *testing.T) {
	mfs := fstest.MapFS{"100/net/dev": netDev(9000, 5000)}
	st := newSeenStore()
	st.refs["sb-1"] = "c-1"
	st.seen["sb-1"] = Seen{PID: SeenNew}
	p := NewPoller(slog.Default(), NewReaderFS(mfs), &fakeLookup{pids: map[string]int{"c-1": 100}}, st, st, time.Second)
	st.dropWrites = true
	p.tick(context.Background(), time.Unix(1000, 0))
	st.dropWrites = false
	mfs["100/net/dev"] = netDev(9500, 5200)
	p.tick(context.Background(), time.Unix(1001, 0))
	if got := st.total("sb-1"); got != [2]int64{9500, 5200} {
		t.Fatalf("credited %v, want 9500/5200 with nothing lost", got)
	}
}

func TestPollerPublishesActiveTCPWithoutBytes(t *testing.T) {
	mfs := fstest.MapFS{
		"100/net/dev": &fstest.MapFile{Data: []byte(sampleProcNetDev)},
		"100/net/tcp": &fstest.MapFile{Data: []byte(sampleProcNetTCP)},
	}
	reader := NewReaderFS(mfs)
	lookup := &fakeLookup{pids: map[string]int{"sb-1": 100}}
	lister := &fakeLister{targets: []Target{{SandboxID: "sb-1", ContainerRef: "sb-1", Seen: Seen{PID: 100, BytesIn: 9000, BytesOut: 5000}}}}
	sink := &fakeSink{}

	p := NewPoller(slog.Default(), reader, lookup, lister, sink, time.Second)
	p.tick(context.Background(), time.Unix(1000, 0))
	if len(sink.batches) != 1 || len(sink.batches[0]) != 1 {
		t.Fatalf("expected 1 sample, got %#v", sink.batches)
	}
	first := sink.batches[0][0]
	if first.BytesIn != 0 || first.BytesOut != 0 || !first.ActiveTCP || first.Seen != nil {
		t.Fatalf("tick = %+v, want zero deltas with ActiveTCP and no reading to store", first)
	}
}

func TestPollerSkipsStoppedContainers(t *testing.T) {
	reader := NewReaderFS(fstest.MapFS{}) // no procfs entries
	lookup := &fakeLookup{pids: map[string]int{"sb-stopped": 0}}
	lister := &fakeLister{targets: []Target{{SandboxID: "sb-stopped", ContainerRef: "sb-stopped"}}}
	sink := &fakeSink{}
	p := NewPoller(slog.Default(), reader, lookup, lister, sink, time.Second)

	p.tick(context.Background(), time.Unix(1000, 0))
	if len(sink.batches) != 1 || len(sink.batches[0]) != 0 {
		t.Fatalf("expected one empty sink batch for stopped container, got %#v", sink.batches)
	}
}

func TestPollerPublishesScaleMetrics(t *testing.T) {
	reader := NewReaderFS(fstest.MapFS{})
	lookup := &fakeLookup{pids: map[string]int{"sb-stopped": 0}}
	lister := &fakeLister{targets: []Target{{SandboxID: "sb-stopped", ContainerRef: "sb-stopped"}}}
	sink := &fakeSink{}
	p := NewPoller(slog.Default(), reader, lookup, lister, sink, time.Second)

	beforePolls := pollTotal.Value()
	beforeDropped := mapValue(pollDroppedTotal, "not_running")
	p.tick(context.Background(), time.Unix(1000, 0))

	if got := pollTotal.Value() - beforePolls; got != 1 {
		t.Fatalf("poll total delta = %d, want 1", got)
	}
	if got := pollTargetsLast.Value(); got != 1 {
		t.Fatalf("targets last = %d, want 1", got)
	}
	if got := pollSamplesLast.Value(); got != 0 {
		t.Fatalf("samples last = %d, want 0", got)
	}
	if got := mapValue(pollDroppedTotal, "not_running") - beforeDropped; got != 1 {
		t.Fatalf("dropped not_running delta = %d, want 1", got)
	}
}

func mapValue(m interface{ Get(string) expvar.Var }, key string) int64 {
	v := m.Get(key)
	if v == nil {
		return 0
	}
	n, _ := strconv.ParseInt(v.String(), 10, 64)
	return n
}

// guard — the test fixture must conform to fs.FS, surface errors that aren't
// ErrNotExist as plain errors so we don't accidentally silence real bugs.
var _ fs.FS = fstest.MapFS{}
