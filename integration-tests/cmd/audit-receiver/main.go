// audit-receiver is the off-node sink the security scenarios export to
// (plans/integration-test-security.md §6.4). Webhook audit export and the
// audit-chain witness both need something listening; this is that something.
//
// It is a TEST FIXTURE. It lives under integration-tests/ and never under
// pkg/, it keeps everything in memory plus one append-only file, and it is
// deliberately not hardened for anything but a throwaway scenario box.
//
// Two things make it more than a bit bucket:
//
//   - it verifies what the daemon actually signed, using
//     auditexport.VerifySignature — the same function the exporter signs with,
//     exported for exactly this purpose. A receiver that accepted anything
//     would let a broken signature pass as a green test.
//   - /_chaos/fail makes it return 503 for the next N requests, so a scenario
//     can prove the exporter's backoff and at-least-once redelivery
//     (pkg/auditexport/backoff.go) instead of only the happy path. 503 is
//     chosen deliberately: the exporter classifies 429 and 5xx as Temporary
//     and retries them, while a 4xx is a receiver-config error. Returning the
//     wrong class would test the wrong path.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func main() {
	var (
		addr     = flag.String("addr", ":9099", "listen address")
		token    = flag.String("token", "", "expected Authorization: Bearer token (empty disables the check)")
		hmacKey  = flag.String("hmac-key", "", "shared key for X-Aerol-Signature (empty disables the check)")
		logPath  = flag.String("audit-log", "/var/log/aerol-audit-webhook.jsonl", "append received audit NDJSON here")
		failNext = flag.Int("fail-next", 0, "return 503 for the first N /audit requests")
	)
	flag.Parse()

	// Secrets come from the environment when the flag is empty. systemd
	// EXPANDS ${VAR} inside ExecStart, so passing them as flags would put the
	// bearer token and HMAC key straight into argv, where every process on the
	// box — including sandboxes — can read them from `ps`. /proc/<pid>/environ
	// is root-only, so the environment is the right place for them.
	if *token == "" {
		*token = os.Getenv("AEROL_RECEIVER_TOKEN")
	}
	if *hmacKey == "" {
		*hmacKey = os.Getenv("AEROL_RECEIVER_HMAC")
	}

	srv, err := newReceiver(*token, *hmacKey, *logPath, *failNext)
	if err != nil {
		log.Fatalf("audit-receiver: %v", err)
	}
	log.Printf("audit-receiver listening on %s (log=%s, auth=%t, hmac=%t)",
		*addr, *logPath, *token != "", *hmacKey != "")
	// No timeouts beyond these: a scenario box is the only client.
	hs := &http.Server{
		Addr:              *addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := hs.ListenAndServe(); err != nil {
		log.Fatalf("audit-receiver: %v", err)
	}
}

// receiver holds everything the scenario can assert on afterwards.
type receiver struct {
	token   string
	hmacKey string

	mu sync.Mutex
	// seen dedupes on Idempotency-Key (== the batch id). At-least-once
	// delivery means a retried batch arrives twice; counting duplicates
	// separately is what lets a scenario prove redelivery happened AND that it
	// was idempotent, which one counter alone cannot show.
	seen       map[string]int
	records    []json.RawMessage
	batches    int
	duplicates int
	rejected   int
	failNext   int
	// heads is the witness store: node id -> most recent head, mirroring
	// controlplane.Witness.LastWitnessedHead.
	heads map[string]controlplane.AuditHead

	logFile *os.File
}

func newReceiver(token, hmacKey, logPath string, failNext int) (*receiver, error) {
	r := &receiver{
		token:    token,
		hmacKey:  hmacKey,
		seen:     map[string]int{},
		heads:    map[string]controlplane.AuditHead{},
		failNext: failNext,
	}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open audit log: %w", err)
		}
		r.logFile = f
	}
	return r, nil
}

func (r *receiver) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /audit", r.handleAudit)
	mux.HandleFunc("POST /witness", r.handleWitness)
	mux.HandleFunc("GET /witness/{node}", r.handleLastHead)
	mux.HandleFunc("GET /_probe/{n}", r.handleProbe)
	mux.HandleFunc("POST /_chaos/fail", r.handleChaos)
	mux.HandleFunc("GET /_stats", r.handleStats)
	mux.HandleFunc("GET /_health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// authorized checks the bearer token in constant time. An empty configured
// token disables the check so a scenario can exercise the unauthenticated
// shape on purpose.
func (r *receiver) authorized(req *http.Request) bool {
	if r.token == "" {
		return true
	}
	got := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(r.token)) == 1
}

func (r *receiver) handleAudit(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 32<<20))
	if err != nil {
		r.countRejected()
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	// Chaos BEFORE auth and signature: the point is to exercise the exporter's
	// retry path, and a 503 must not depend on the request being otherwise
	// perfect. Counted as neither accepted nor rejected — it never got that
	// far.
	if r.takeFailure() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	if !r.authorized(req) {
		r.countRejected()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.hmacKey != "" {
		if !auditexport.VerifySignature(r.hmacKey, body, req.Header.Get(auditexport.HeaderSignature)) {
			r.countRejected()
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
	}

	// Idempotency-Key is the batch id; the exporter sets both.
	key := req.Header.Get("Idempotency-Key")
	if key == "" {
		key = req.Header.Get(auditexport.HeaderBatchID)
	}

	r.mu.Lock()
	r.batches++
	dup := false
	if key != "" {
		r.seen[key]++
		dup = r.seen[key] > 1
		if dup {
			r.duplicates++
		}
	}
	// A duplicate is still a 2xx — that is what at-least-once delivery
	// requires — but its events are not appended twice, so a scenario can
	// assert both redelivery and no double-counting.
	if !dup {
		for _, line := range splitNDJSON(body) {
			r.records = append(r.records, line)
		}
		if r.logFile != nil {
			_, _ = r.logFile.Write(body)
		}
	}
	r.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// splitNDJSON returns each non-empty line as a raw JSON message.
func splitNDJSON(body []byte) []json.RawMessage {
	var out []json.RawMessage
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, json.RawMessage(line))
	}
	return out
}

func (r *receiver) handleWitness(w http.ResponseWriter, req *http.Request) {
	if !r.authorized(req) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var heads []controlplane.AuditHead
	if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&heads); err != nil {
		http.Error(w, "decode heads", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	r.mu.Lock()
	for _, h := range heads {
		if h.NodeID == "" {
			continue
		}
		r.heads[h.NodeID] = h
	}
	n := len(r.heads)
	r.mu.Unlock()

	writeJSON(w, http.StatusOK, controlplane.WitnessReceipt{
		RecordedAt: now,
		ReceiptID:  fmt.Sprintf("rcpt-%d-%d", now.UnixNano(), n),
	})
}

// handleLastHead mirrors controlplane.Witness.LastWitnessedHead: 404 means the
// witness has never recorded a head for that node, which is distinct from a
// transport error and is what a scenario asserts before the first interval.
func (r *receiver) handleLastHead(w http.ResponseWriter, req *http.Request) {
	node := req.PathValue("node")
	r.mu.Lock()
	h, ok := r.heads[node]
	r.mu.Unlock()
	if !ok {
		http.Error(w, "no head for node", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (r *receiver) handleProbe(w http.ResponseWriter, req *http.Request) {
	n, err := strconv.Atoi(req.PathValue("n"))
	if err != nil || n < 0 {
		http.Error(w, "bad count", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	if n > len(r.records) {
		n = len(r.records)
	}
	out := append([]json.RawMessage(nil), r.records[len(r.records)-n:]...)
	r.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (r *receiver) handleChaos(w http.ResponseWriter, req *http.Request) {
	n, err := strconv.Atoi(req.URL.Query().Get("n"))
	if err != nil || n < 0 {
		http.Error(w, "bad n", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.failNext = n
	r.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]int{"fail_next": n})
}

func (r *receiver) handleStats(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	stats := map[string]int{
		"batches":    r.batches,
		"records":    len(r.records),
		"duplicates": r.duplicates,
		"rejected":   r.rejected,
		"fail_next":  r.failNext,
		"nodes":      len(r.heads),
	}
	r.mu.Unlock()
	writeJSON(w, http.StatusOK, stats)
}

func (r *receiver) takeFailure() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failNext <= 0 {
		return false
	}
	r.failNext--
	return true
}

func (r *receiver) countRejected() {
	r.mu.Lock()
	r.rejected++
	r.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
