package worker

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPostOrSpillWorkerEgressUsesIngest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:")
	gotCh := make(chan map[string]string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/audit/egress", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Aerol-Audit-Capability") != "cap" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var m map[string]string
		_ = json.Unmarshal(raw, &m)
		gotCh <- m
		w.WriteHeader(http.StatusAccepted)
	})
	go http.Serve(ln, mux)

	postOrSpillWorkerEgress(egressAuditJob{
		port: port, capability: "cap", node: "n1",
		sandboxID: "sb-1", network: "tcp", address: "example.com:443",
		eventTime: time.Now().UTC(),
	})
	select {
	case m := <-gotCh:
		if m["destination"] != "example.com:443" || m["kind"] != "" || m["sandbox_id"] != "" {
			t.Fatalf("got %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ingest not called")
	}
}

func readWorkerSpill(t *testing.T, dir string) []workerEgressAuditEvent {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, workerEgressSpillFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	defer f.Close()
	var out []workerEgressAuditEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var ev workerEgressAuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("spill line does not parse: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

func TestPostOrSpillWorkerEgressFallsBackToSpill(t *testing.T) {
	dir := t.TempDir()
	spill := newWorkerEgressSpiller(dir, "n1") // not started: drained by hand
	postOrSpillWorkerEgress(egressAuditJob{
		port: "1", capability: "cap", spill: spill, node: "n1",
		sandboxID: "sb-1", network: "tcp", address: "host:9",
	})
	if got := readWorkerSpill(t, dir); len(got) != 0 {
		t.Fatalf("IPC failure wrote synchronously: %+v", got)
	}
	if n, err := spill.drainOnce(nil); err != nil || n != 1 {
		t.Fatalf("drain = %d, %v", n, err)
	}
	got := readWorkerSpill(t, dir)
	if len(got) != 1 || got[0].Kind != "egress" || got[0].SandboxID != "sb-1" || got[0].Destination != "host:9" || got[0].EventID == "" {
		t.Fatalf("spill event = %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("worker must not write secrets.jsonl, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets.tip")); !os.IsNotExist(err) {
		t.Fatalf("worker must not write secrets.tip, err=%v", err)
	}
	// No spill writer at all: the drop is counted, nothing panics.
	before := workerEgressDropped.Load()
	postOrSpillWorkerEgress(egressAuditJob{port: "1", capability: "cap", sandboxID: "sb-1", address: "host:9"})
	if workerEgressDropped.Load() != before+1 {
		t.Fatal("IPC failure without a spill writer must count a drop")
	}
}

func TestInstallDefaultEgressObserverRespectsFlag(t *testing.T) {
	t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "false")
	t.Setenv("SB_AUDIT_SPILL_DIR", filepath.Join(t.TempDir(), "audit"))
	t.Setenv("SB_AUDIT_INGEST_PORT", "21215")
	t.Setenv("SB_AUDIT_INGEST_TOKEN", "tok")
	m := newNetMediator()
	installDefaultEgressObserver(m)
	if m.egressObserver() != nil {
		t.Fatal("expected no observer when disabled")
	}

	t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "true")
	t.Setenv("SB_AUDIT_SPILL_DIR", "")
	t.Setenv("SB_AUDIT_INGEST_PORT", "")
	t.Setenv("SB_AUDIT_INGEST_TOKEN", "")
	m2 := newNetMediator()
	installDefaultEgressObserver(m2)
	if m2.egressObserver() != nil {
		t.Fatal("expected no observer without ingest or spill path")
	}

	dir := t.TempDir()
	t.Setenv("SB_AUDIT_SPILL_DIR", filepath.Join(dir, "audit"))
	t.Setenv("SB_NODE_ID", "n1")
	m3 := newNetMediator()
	installDefaultEgressObserver(m3)
	t.Cleanup(func() {
		if s := workerEgressSpill.Swap(nil); s != nil {
			s.Close()
		}
	})
	if m3.egressObserver() == nil {
		t.Fatal("expected observer when enabled + DB path (spill fallback)")
	}
	m3.egressObserver()("sb-x", "tcp", "host:9")
	deadline := time.Now().Add(2 * time.Second)
	path := filepath.Join(dir, "audit", workerEgressSpillFile)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("spill file not written")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestInstalledObserverSpillsWhenConfiguredIngestFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "true")
	t.Setenv("SB_AUDIT_INGEST_PORT", "1")
	t.Setenv("SB_AUDIT_SPILL_DIR", dir)
	t.Setenv("SB_NODE_ID", "node-a")

	m := newNetMediator()
	installDefaultEgressObserver(m, func(sandboxID string) (egressAuditBinding, bool) {
		return egressAuditBinding{capability: "cap", incarnationID: "inc-1"}, sandboxID == "sb-fallback"
	})
	t.Cleanup(func() {
		if s := workerEgressSpill.Swap(nil); s != nil {
			s.Close()
		}
	})
	observer := m.egressObserver()
	if observer == nil {
		t.Fatal("expected egress observer")
	}
	observer("sb-fallback", "tcp", "example.com:443")

	deadline := time.Now().Add(3 * time.Second)
	for {
		if got := readWorkerSpill(t, dir); len(got) > 0 {
			ev := got[0]
			if ev.SandboxID != "sb-fallback" || ev.IncarnationID != "inc-1" || ev.Destination != "example.com:443" || ev.NodeID != "node-a" {
				t.Fatalf("spill event = %+v", ev)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("spill file not written after ingest failure")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The dial-path overflow branch must do no I/O: no directory, file, lock, or
// fsync — only counters and a kick. The writer later turns the count into
// ONE marker.
func TestObserverOverflowDoesNoIOOnDialPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spill-not-created")
	spill := newWorkerEgressSpiller(dir, "n-ovf") // not started
	prev := workerEgressSpill.Swap(spill)
	t.Cleanup(func() { workerEgressSpill.Store(prev) })
	before := workerEgressDropped.Load()
	for range 37 {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("overflow touched the filesystem on the dial path (stat err=%v)", err)
		}
		noteWorkerEgressOverflow()
	}
	if got := workerEgressDropped.Load() - before; got != 37 {
		t.Fatalf("dropped counter delta = %d, want 37", got)
	}
	if spill.pending.Load() != 37 {
		t.Fatalf("pending gap = %d, want 37", spill.pending.Load())
	}
	select {
	case <-spill.kick:
	default:
		t.Fatal("overflow must kick the writer")
	}
	markers := workerEgressGapMarkers.Value()
	if n, err := spill.drainOnce(nil); err != nil || n != 1 {
		t.Fatalf("drain = %d, %v (want exactly one marker)", n, err)
	}
	got := readWorkerSpill(t, dir)
	if len(got) != 1 || got[0].Kind != "gap" || got[0].Reason != "overflow" || got[0].Dropped != 37 || got[0].NodeID != "n-ovf" {
		t.Fatalf("marker = %+v", got)
	}
	if workerEgressGapMarkers.Value() != markers+1 {
		t.Fatal("marker not counted")
	}
	if n, err := spill.drainOnce(nil); err != nil || n != 0 {
		t.Fatalf("nothing pending: drain = %d, %v", n, err)
	}
	// Without a spill writer the counter is the only evidence; no panic.
	workerEgressSpill.Store(nil)
	before = workerEgressDropped.Load()
	noteWorkerEgressOverflow()
	if workerEgressDropped.Load() != before+1 {
		t.Fatal("overflow without a spill writer must still count")
	}
	if newWorkerEgressSpiller("  ", "n") != nil {
		t.Fatal("blank spill dir must yield no writer")
	}
	var none *workerEgressSpiller
	none.start()
	none.noteDrop(1)
}

func TestWorkerEgressSpillerBatchesAndCoalesces(t *testing.T) {
	dir := t.TempDir()
	spill := newWorkerEgressSpiller(dir, "n-batch")
	for i := range 300 {
		spill.enqueue(workerEgressAuditEvent{SandboxID: fmt.Sprintf("sb-%d", i%7), Kind: "egress", Destination: fmt.Sprintf("d:%d", i), Result: "success"})
	}
	spill.noteDrop(5)
	batches := workerEgressSpillBatches.Value()
	// One marker plus one full batch; the remainder next time. Two lock
	// acquisitions and two fsyncs for 301 records.
	if n, err := spill.drainOnce(nil); err != nil || n != workerEgressSpillBatch+1 {
		t.Fatalf("first drain = %d, %v", n, err)
	}
	if n, err := spill.drainOnce(nil); err != nil || n != 300-workerEgressSpillBatch {
		t.Fatalf("second drain = %d, %v", n, err)
	}
	if workerEgressSpillBatches.Value() != batches+2 {
		t.Fatalf("batches counted = %d, want +2", workerEgressSpillBatches.Value()-batches)
	}
	got := readWorkerSpill(t, dir)
	if len(got) != 301 || got[0].Kind != "gap" || got[0].Dropped != 5 {
		t.Fatalf("spill = %d records, first %+v", len(got), got[0])
	}
	for i, ev := range got[1:] {
		if ev.Destination != fmt.Sprintf("d:%d", i) {
			t.Fatalf("record %d out of order: %+v", i, ev)
		}
	}
	// first is written ahead of the queue.
	head := workerEgressAuditEvent{SandboxID: "sb-head", Kind: "egress", Destination: "head", Result: "success"}
	spill.enqueue(workerEgressAuditEvent{SandboxID: "sb-tail", Kind: "egress", Destination: "tail", Result: "success"})
	if n, err := spill.drainOnce(&head); err != nil || n != 2 {
		t.Fatalf("drain with first = %d, %v", n, err)
	}
	got = readWorkerSpill(t, dir)
	if got[301].Destination != "head" || got[302].Destination != "tail" {
		t.Fatalf("first not written ahead: %+v %+v", got[301], got[302])
	}
}

func TestWorkerEgressSpillerOverflowAndFailureKeepTheLossOwed(t *testing.T) {
	// A tiny queue: the third record overflows and is owed as a gap.
	small := &workerEgressSpiller{file: newWorkerEgressSpiller(t.TempDir(), "n").file, node: "n", ch: make(chan workerEgressAuditEvent, 2), kick: make(chan struct{}, 1), sleep: time.Sleep}
	before := workerEgressDropped.Load()
	for i := range 3 {
		small.enqueue(workerEgressAuditEvent{SandboxID: "sb", Destination: fmt.Sprint(i)})
	}
	if workerEgressDropped.Load() != before+1 || small.pending.Load() != 1 {
		t.Fatalf("overflow: dropped delta %d pending %d", workerEgressDropped.Load()-before, small.pending.Load())
	}
	if n, err := small.drainOnce(nil); err != nil || n != 3 {
		t.Fatalf("drain = %d, %v (marker + 2)", n, err)
	}

	// The spill path is a directory: the append fails, every record in the
	// batch is a drop, and the owed count grows by the batch so the next
	// successful marker reports it.
	bad := t.TempDir()
	if err := os.Mkdir(filepath.Join(bad, workerEgressSpillFile), 0o700); err != nil {
		t.Fatal(err)
	}
	broken := newWorkerEgressSpiller(bad, "n")
	broken.enqueue(workerEgressAuditEvent{SandboxID: "a"})
	broken.enqueue(workerEgressAuditEvent{SandboxID: "b"})
	broken.noteDrop(4)
	before = workerEgressDropped.Load()
	fails := workerEgressSpillFail.Value()
	n, err := broken.drainOnce(nil)
	if err == nil || n != 0 {
		t.Fatalf("drain on a broken spill = %d, %v", n, err)
	}
	if workerEgressDropped.Load() != before+2 {
		t.Fatalf("failed batch dropped delta = %d, want 2 (the marker is not an event)", workerEgressDropped.Load()-before)
	}
	if broken.pending.Load() != 6 {
		t.Fatalf("owed after failure = %d, want 4 + 2", broken.pending.Load())
	}
	if workerEgressSpillFail.Value() != fails+1 {
		t.Fatal("spill failure not counted")
	}
	// Once the disk is back, one marker reports the whole loss.
	broken.file = newWorkerEgressSpiller(t.TempDir(), "n").file
	if n, err := broken.drainOnce(nil); err != nil || n != 1 {
		t.Fatalf("drain after recovery = %d, %v", n, err)
	}
	got := readWorkerSpill(t, filepath.Dir(broken.file.Path))
	if len(got) != 1 || got[0].Dropped != 6 {
		t.Fatalf("recovery marker = %+v", got)
	}
}

func TestWorkerEgressSpillerRunBacksOffInsteadOfRetryingPerEvent(t *testing.T) {
	bad := t.TempDir()
	if err := os.Mkdir(filepath.Join(bad, workerEgressSpillFile), 0o700); err != nil {
		t.Fatal(err)
	}
	spill := newWorkerEgressSpiller(bad, "n")
	slept := make(chan time.Duration, 8)
	// Sleep must not block Close: the writer retries immediately after
	// recording the backoff, so the next send can fill the buffer.
	spill.sleep = func(d time.Duration) {
		select {
		case slept <- d:
		case <-spill.stop:
		}
	}
	spill.start()
	spill.start() // idempotent
	t.Cleanup(spill.Close)
	wait := func(want time.Duration) {
		t.Helper()
		select {
		case d := <-slept:
			if d != want {
				t.Fatalf("backoff = %v, want %v", d, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("writer did not back off")
		}
	}
	spill.enqueue(workerEgressAuditEvent{SandboxID: "a"})
	wait(workerEgressSpillBackoffMin)
	spill.enqueue(workerEgressAuditEvent{SandboxID: "b"})
	wait(2 * workerEgressSpillBackoffMin)
	spill.noteDrop(1) // a kick alone also drives a (failing) flush
	wait(4 * workerEgressSpillBackoffMin)
	// Sleeping never blocks producers: the queue and counters keep working.
	before := workerEgressDropped.Load()
	for range 10 {
		spill.enqueue(workerEgressAuditEvent{SandboxID: "c"})
	}
	if workerEgressDropped.Load() < before {
		t.Fatal("unreachable")
	}
}

// 429 is the daemon saying "over budget, already counted": the record must not
// be spilled — the spill file is a path into the log, not around the budget —
// and it is not an IPC failure.
func TestPostOrSpillWorkerEgressTreatsThrottleAsFinal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:")
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/audit/egress", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "sandbox egress audit budget exhausted", http.StatusTooManyRequests)
	})
	go http.Serve(ln, mux)

	spill := newWorkerEgressSpiller(t.TempDir(), "n1") // not started: anything enqueued stays visible
	throttled, ipcFail := workerEgressThrottled.Value(), workerEgressIPCFail.Value()
	postOrSpillWorkerEgress(egressAuditJob{
		port: port, capability: "cap", node: "n1", spill: spill,
		sandboxID: "sb-1", network: "tcp", address: "example.com:443",
	})
	if len(spill.ch) != 0 {
		t.Fatalf("throttled record was spilled (%d queued)", len(spill.ch))
	}
	if workerEgressThrottled.Value()-throttled != 1 || workerEgressIPCFail.Value() != ipcFail {
		t.Fatalf("throttled +%d ipc_fail +%d, want 1/0", workerEgressThrottled.Value()-throttled, workerEgressIPCFail.Value()-ipcFail)
	}
}
