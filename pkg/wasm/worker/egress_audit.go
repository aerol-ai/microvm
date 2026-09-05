package worker

import (
	"bytes"
	"encoding/json"
	"expvar"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"golang.org/x/sys/unix"
)

// Worker subprocesses cannot call internal/service.emitEgressAudit. They POST
// egress events to the daemon's loopback audit ingest
// (SB_AUDIT_INGEST_PORT + per-sandbox capability). Workers never write
// secrets.jsonl tip. When IPC is unavailable they durable-append to
// secrets.spill.jsonl for the parent drain path (or count a gap drop).

const (
	workerEgressLockFile   = "secrets.jsonl.lock"
	workerEgressSpillFile  = "secrets.spill.jsonl"
	workerEgressWorkers    = 8
	workerEgressQueue      = 1024
	workerEgressIngestPath = "/internal/audit/egress"
	workerEgressCapHdr     = "X-Aerol-Audit-Capability"
)

type workerEgressAuditEvent = auditlog.Event

type egressAuditJob struct {
	port, capability, spillDir, node           string
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
)

// installDefaultEgressObserver wires destination attribution when
// SB_EGRESS_ATTRIBUTION_ENABLED is unset/true. Prefers SB_AUDIT_INGEST_PORT
// and always carries the spill directory as the durable fallback when IPC is
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
	ensureWorkerEgressPool()
	m.SetEgressObserver(func(sandboxID, network, address string) {
		binding := egressAuditBinding{}
		if resolve != nil {
			binding, _ = resolve(sandboxID)
		}
		job := egressAuditJob{
			port: port, capability: binding.capability, spillDir: spillDir, node: node,
			sandboxID: sandboxID, incarnationID: binding.incarnationID, network: network, address: address,
			eventTime: time.Now().UTC(),
		}
		select {
		case workerEgressCh <- job:
		default:
			workerEgressDropped.Add(1)
			slog.Warn("wasm egress audit queue full; writing gap marker",
				"sandbox_id", sandboxID, "destination", address, "dropped_total", workerEgressDropped.Load())
			appendWorkerEgressGap(spillDir, node, sandboxID, binding.incarnationID)
		}
	})
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
	// IPC unavailable — durable spill for parent import; never touch secrets.jsonl tip.
	if job.spillDir != "" {
		appendWorkerEgressSpill(job.spillDir, workerEgressAuditEvent{
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
		return
	}
	workerEgressDropped.Add(1)
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errStatus(resp.StatusCode)
	}
	return nil
}

type statusError int

func (e statusError) Error() string { return "audit ingest status " + strconv.Itoa(int(e)) }

func errStatus(code int) error { return statusError(code) }

func appendWorkerEgressGap(spillDir, node, sandboxID, incarnationID string) {
	if spillDir == "" {
		workerEgressDropped.Add(1)
		return
	}
	appendWorkerEgressSpill(spillDir, workerEgressAuditEvent{
		Time:          time.Now().UTC(),
		Actor:         node,
		SandboxID:     strings.TrimSpace(sandboxID),
		Result:        "gap",
		Reason:        "overflow",
		NodeID:        node,
		Kind:          "gap",
		IncarnationID: strings.TrimSpace(incarnationID),
	})
}

// appendWorkerEgressSpill durable-appends under flock + fsync to the parent
// spill file. Does not update secrets.tip or secrets.jsonl.
func appendWorkerEgressSpill(spillDir string, ev workerEgressAuditEvent) {
	if spillDir == "" {
		return
	}
	auditlog.EnsureEventID(&ev)
	if err := os.MkdirAll(spillDir, 0o700); err != nil {
		slog.Warn("wasm egress spill mkdir failed", "dir", spillDir, "err", err)
		workerEgressDropped.Add(1)
		return
	}
	lockPath := filepath.Join(spillDir, workerEgressLockFile)
	spillPath := filepath.Join(spillDir, workerEgressSpillFile)
	// The lock sidecar carries no data. Open it read-only so close cannot hide
	// a buffered-write failure; flock only needs a stable file descriptor.
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		slog.Warn("wasm egress spill lock open failed", "path", lockPath, "err", err)
		workerEgressDropped.Add(1)
		return
	}
	defer lf.Close()
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX); err != nil {
		slog.Warn("wasm egress spill flock failed", "path", lockPath, "err", err)
		workerEgressDropped.Add(1)
		return
	}
	defer func() { _ = unix.Flock(int(lf.Fd()), unix.LOCK_UN) }()

	line, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("wasm egress spill marshal failed", "err", err)
		workerEgressDropped.Add(1)
		return
	}
	line = append(line, '\n')
	f, err := os.OpenFile(spillPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Warn("wasm egress spill open failed", "path", spillPath, "err", err)
		workerEgressDropped.Add(1)
		return
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		slog.Warn("wasm egress spill write failed", "path", spillPath, "err", err)
		workerEgressDropped.Add(1)
		return
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		slog.Warn("wasm egress spill sync failed", "path", spillPath, "err", err)
		workerEgressDropped.Add(1)
		return
	}
	if err := f.Close(); err != nil {
		slog.Warn("wasm egress spill close failed", "path", spillPath, "err", err)
		workerEgressDropped.Add(1)
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
