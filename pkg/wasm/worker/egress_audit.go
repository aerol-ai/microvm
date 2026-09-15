package worker

import (
	"bytes"
	"encoding/json"
	"expvar"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// Worker subprocesses cannot call internal/service.emitEgressAudit. They POST
// egress events to the daemon's loopback audit ingest
// (SB_AUDIT_INGEST_PORT + per-sandbox capability). Workers never write
// secrets.jsonl or its tip. When IPC is unavailable they append to the audit
// directory's shared spill file (auditlog.SpillFile — the same writer, lock
// and format the daemon's own sink uses) for the daemon's drain path.
//
// Nothing here runs on a sandbox's dial path except a non-blocking channel
// send. A full queue costs two atomics and a kick; a full spill queue costs
// the same. The spill file is written by exactly one goroutine, in batches,
// one flock and one fsync per batch, with backoff when the disk misbehaves —
// so audit backpressure can slow evidence down, but it can never stall a
// tenant's egress, and one tenant's burst can never hold the audit lock
// against another's.

const (
	workerEgressSpillFile  = auditlog.SpillFileName
	workerEgressWorkers    = 8
	workerEgressQueue      = 1024
	workerEgressIngestPath = "/internal/audit/egress"
	workerEgressCapHdr     = "X-Aerol-Audit-Capability"
	// workerEgressSpillQueue is how many IPC-failed events may wait for the
	// spill writer before they are counted as dropped (and reported by one
	// coalesced gap marker). Sized for a daemon restart, not an outage: an
	// outage is what the marker is for.
	workerEgressSpillQueue = 4096
	// workerEgressSpillBatch bounds one group-committed append.
	workerEgressSpillBatch      = 256
	workerEgressSpillBackoffMin = time.Second
	workerEgressSpillBackoffMax = 30 * time.Second
)

type workerEgressAuditEvent = auditlog.Event

type egressAuditJob struct {
	port, capability, node                     string
	spill                                      *workerEgressSpiller
	sandboxID, incarnationID, network, address string
	eventTime                                  time.Time
}

type egressAuditBinding struct {
	capability    string
	incarnationID string
}

type egressAuditBindingResolver func(sandboxID string) (egressAuditBinding, bool)

var (
	workerEgressOnce    sync.Once
	workerEgressCh      chan egressAuditJob
	workerEgressDropped atomic.Int64
	workerEgressIPCFail = expvar.NewInt("aerolvm_wasm_egress_audit_ipc_fail_total")
	workerEgressHTTP    = &http.Client{Timeout: 2 * time.Second}
	// workerEgressSpill is the installed spill writer; the dial-path overflow
	// branch only needs it to count.
	workerEgressSpill atomic.Pointer[workerEgressSpiller]
	// workerEgressGapMarkers counts coalesced markers written (not drops).
	workerEgressGapMarkers   = expvar.NewInt("aerolvm_wasm_egress_audit_gap_markers_total")
	workerEgressSpillBatches = expvar.NewInt("aerolvm_wasm_egress_audit_spill_batches_total")
	workerEgressSpillFail    = expvar.NewInt("aerolvm_wasm_egress_audit_spill_fail_total")
	// workerEgressThrottled counts records the daemon refused under the
	// sandbox's egress evidence budget (429). They are not spilled: the daemon
	// already owes them to the sandbox's coalesced rate_limited record, and
	// the spill file is a path into the log, not around the budget.
	workerEgressThrottled = expvar.NewInt("aerolvm_wasm_egress_audit_throttled_total")
)

// installDefaultEgressObserver wires destination attribution when
// SB_EGRESS_ATTRIBUTION_ENABLED is unset/true. Prefers SB_AUDIT_INGEST_PORT
// and always carries the spill writer as the durable fallback when IPC is
// unavailable or temporarily fails.
func installDefaultEgressObserver(m *NetMediator, resolvers ...egressAuditBindingResolver) {
	if m == nil || !envBoolDefaultTrue("SB_EGRESS_ATTRIBUTION_ENABLED") {
		return
	}
	port := strings.TrimSpace(os.Getenv("SB_AUDIT_INGEST_PORT"))
	var resolve egressAuditBindingResolver
	if len(resolvers) > 0 {
		resolve = resolvers[0]
	}
	spillDir := workerEgressSpillDir()
	if port == "" && spillDir == "" {
		return
	}
	node := strings.TrimSpace(os.Getenv("SB_NODE_ID"))
	spill := newWorkerEgressSpiller(spillDir, node)
	if spill != nil {
		spill.start()
	}
	workerEgressSpill.Store(spill)
	ensureWorkerEgressPool()
	m.SetEgressObserver(func(sandboxID, network, address string) {
		binding := egressAuditBinding{}
		if resolve != nil {
			binding, _ = resolve(sandboxID)
		}
		job := egressAuditJob{
			port: port, capability: binding.capability, spill: spill, node: node,
			sandboxID: sandboxID, incarnationID: binding.incarnationID, network: network, address: address,
			eventTime: time.Now().UTC(),
		}
		select {
		case workerEgressCh <- job:
		default:
			noteWorkerEgressOverflow()
		}
	})
}

// noteWorkerEgressOverflow is the entire dial-path cost of a full queue: two
// atomics and a non-blocking kick. The spill writer turns the count into one
// gap marker.
func noteWorkerEgressOverflow() {
	workerEgressSpill.Load().noteDrop(1)
}

func ensureWorkerEgressPool() {
	workerEgressOnce.Do(func() {
		workerEgressCh = make(chan egressAuditJob, workerEgressQueue)
		for i := 0; i < workerEgressWorkers; i++ {
			go func() {
				for job := range workerEgressCh {
					postOrSpillWorkerEgress(job)
				}
			}()
		}
	})
}

func workerEgressSpillDir() string {
	return strings.TrimSpace(os.Getenv("SB_AUDIT_SPILL_DIR"))
}

func postOrSpillWorkerEgress(job egressAuditJob) {
	sandboxID := strings.TrimSpace(job.sandboxID)
	address := strings.TrimSpace(job.address)
	if sandboxID == "" || address == "" {
		return
	}
	if job.eventTime.IsZero() {
		job.eventTime = time.Now().UTC()
	}
	if job.port != "" && job.capability != "" {
		if err := postWorkerEgressAudit(job); err == nil {
			return
		}
		workerEgressIPCFail.Add(1)
	}
	// IPC unavailable — hand the record to the spill writer; never touch
	// secrets.jsonl. A nil writer (no spill dir) counts a drop.
	job.spill.enqueue(workerEgressAuditEvent{
		Time:          job.eventTime,
		Actor:         job.node,
		SandboxID:     sandboxID,
		Result:        "success",
		Reason:        "ok",
		NodeID:        job.node,
		Kind:          "egress",
		Destination:   address,
		Network:       strings.TrimSpace(job.network),
		IncarnationID: strings.TrimSpace(job.incarnationID),
	})
}

func postWorkerEgressAudit(job egressAuditJob) error {
	body, err := json.Marshal(map[string]any{
		"network":     strings.TrimSpace(job.network),
		"destination": job.address,
	})
	if err != nil {
		return err
	}
	url := "http://127.0.0.1:" + job.port + workerEgressIngestPath
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if job.capability != "" {
		req.Header.Set(workerEgressCapHdr, job.capability)
	}
	resp, err := workerEgressHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		// Terminal: the daemon counted this record toward the sandbox's
		// coalesced rate_limited entry. Spilling it would re-submit the load
		// the budget refused.
		workerEgressThrottled.Add(1)
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errStatus(resp.StatusCode)
	}
	return nil
}

type statusError int

func (e statusError) Error() string { return "audit ingest status " + strconv.Itoa(int(e)) }

func errStatus(code int) error { return statusError(code) }

// workerEgressSpiller is the single writer of this process's spill records.
// Producers (the IPC pool on failure, the dial path on overflow) only touch
// its channel and counters; the goroutine behind run does every byte of I/O.
type workerEgressSpiller struct {
	file auditlog.SpillFile
	node string
	ch   chan workerEgressAuditEvent
	kick chan struct{}
	// pending is the coalesced drop count the next batch reports as one gap
	// marker. It is never reset by a failed write: the loss stays owed until
	// the disk takes it.
	pending atomic.Int64
	once    sync.Once
	// sleep is the retry pause after a failed append (tests replace it).
	sleep func(time.Duration)
	// stop/done let Close park the writer so tests can release t.TempDir
	// without racing a flock or a recreate-after-unlink. Workers just exit.
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

func newWorkerEgressSpiller(dir, node string) *workerEgressSpiller {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	return &workerEgressSpiller{
		file:  auditlog.SpillFileIn(dir),
		node:  node,
		ch:    make(chan workerEgressAuditEvent, workerEgressSpillQueue),
		kick:  make(chan struct{}, 1),
		sleep: time.Sleep,
		stop:  make(chan struct{}),
	}
}

func (s *workerEgressSpiller) start() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		s.done = make(chan struct{})
		go s.run()
	})
}

// Close stops the writer and waits for it. Safe on a nil or never-started
// spiller. Tests must call this before t.TempDir cleanup: a live writer
// holds the audit flock and recreates files under the temp dir.
func (s *workerEgressSpiller) Close() {
	if s == nil || s.stop == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stop) })
	if s.done != nil {
		<-s.done
	}
}

// noteDrop accounts n lost events. Safe on a nil spiller (no spill dir):
// the counter is then the only evidence.
func (s *workerEgressSpiller) noteDrop(n int64) {
	workerEgressDropped.Add(n)
	if s == nil {
		return
	}
	s.pending.Add(n)
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// enqueue hands one record to the writer without blocking. A full spill
// queue is a drop, reported by the next gap marker.
func (s *workerEgressSpiller) enqueue(ev workerEgressAuditEvent) {
	if s == nil {
		workerEgressDropped.Add(1)
		return
	}
	select {
	case s.ch <- ev:
	default:
		s.noteDrop(1)
	}
}

// drainOnce group-commits one batch: a gap marker for every drop owed, then
// first (if any) and whatever else is queued, up to workerEgressSpillBatch.
// One lock, one write, one fsync. On failure every record in the batch is
// a drop and the owed count grows by the batch, so nothing is lost silently.
func (s *workerEgressSpiller) drainOnce(first *workerEgressAuditEvent) (written int, err error) {
	batch := make([]workerEgressAuditEvent, 0, workerEgressSpillBatch+1)
	gap := s.pending.Swap(0)
	if gap > 0 {
		batch = append(batch, auditlog.GapMarker(s.node, gap, time.Now().UTC()))
	}
	if first != nil {
		batch = append(batch, *first)
	}
	for len(batch) < cap(batch) {
		select {
		case ev := <-s.ch:
			batch = append(batch, ev)
			continue
		default:
		}
		break
	}
	if len(batch) == 0 {
		return 0, nil
	}
	if err := s.file.Append(batch); err != nil {
		workerEgressSpillFail.Add(1)
		lost := int64(len(batch))
		if gap > 0 {
			lost-- // the marker itself is not an event
		}
		workerEgressDropped.Add(lost)
		s.pending.Add(gap + lost)
		return 0, err
	}
	workerEgressSpillBatches.Add(1)
	if gap > 0 {
		workerEgressGapMarkers.Add(1)
	}
	return len(batch), nil
}

// run is the writer loop. After a failed append it backs off (1s doubling
// to 30s) rather than retrying per event: a dead disk must cost the node
// one warning per backoff, not one per dial. Records that arrive meanwhile
// queue up to the spill queue's capacity and are counted beyond it.
func (s *workerEgressSpiller) run() {
	if s.done != nil {
		defer close(s.done)
	}
	var backoff time.Duration
	for {
		var first *workerEgressAuditEvent
		select {
		case <-s.stop:
			return
		case ev := <-s.ch:
			first = &ev
		case <-s.kick:
		}
		if _, err := s.drainOnce(first); err != nil {
			if backoff == 0 {
				backoff = workerEgressSpillBackoffMin
			} else {
				backoff = min(backoff*2, workerEgressSpillBackoffMax)
			}
			slog.Warn("wasm egress audit spill append failed; backing off",
				"err", err, "retry_in", backoff, "dropped_total", workerEgressDropped.Load())
			s.sleep(backoff)
			continue
		}
		backoff = 0
	}
}

func envBoolDefaultTrue(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return true
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return true
	}
	return b
}
