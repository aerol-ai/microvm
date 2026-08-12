package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

const (
	auditIngestPath        = "/internal/audit/egress"
	auditIngestMaxBody     = 64 << 10
	auditIngestHeaderToken = "X-Aerol-Audit-Token"
	auditIngestHeaderCap   = "X-Aerol-Audit-Capability"
)

var (
	auditIngestAcceptedTotal = expvar.NewInt("aerolvm_audit_ingest_accepted_total")
	auditIngestRejectedTotal = expvar.NewInt("aerolvm_audit_ingest_rejected_total")
)

// auditIngestServer is a loopback-only HTTP listener that accepts egress audit
// events from wasm worker subprocesses. Workers must never write secrets.jsonl
// tip themselves — they POST here (or spill for parent drain).
type auditIngestServer struct {
	svc    *Service
	token  string
	server *http.Server
	ln     net.Listener
	mu     sync.Mutex
}

type auditIngestRequest struct {
	SandboxID     string    `json:"sandbox_id"`
	Network       string    `json:"network,omitempty"`
	Destination   string    `json:"destination"`
	NodeID        string    `json:"node_id,omitempty"`
	IncarnationID string    `json:"incarnation_id,omitempty"`
	Kind          string    `json:"kind,omitempty"`
	Result        string    `json:"result,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	Capability    string    `json:"capability,omitempty"`
	EventTime     time.Time `json:"event_time,omitempty"`
	Time          time.Time `json:"time,omitempty"`
}

// StartAuditIngestServer binds 127.0.0.1:SB_AUDIT_INGEST_PORT (0 = ephemeral)
// and publishes SB_AUDIT_INGEST_PORT / SB_AUDIT_INGEST_TOKEN into the process
// environment so wasm workers inherit them on spawn.
func (s *Service) StartAuditIngestServer(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if !s.cfg.EgressAttributionEnabled {
		return nil
	}
	port := s.cfg.AuditIngestPort
	if port < 0 {
		port = 0
	}
	token := strings.TrimSpace(s.cfg.AuditIngestToken)
	if token == "" {
		var err error
		token, err = newAuditIngestToken()
		if err != nil {
			return fmt.Errorf("audit ingest token entropy: %w", err)
		}
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("audit ingest listen %s: %w", addr, err)
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port
	_ = os.Setenv("SB_AUDIT_INGEST_PORT", strconv.Itoa(actualPort))
	_ = os.Setenv("SB_AUDIT_INGEST_TOKEN", token)

	mux := http.NewServeMux()
	ing := &auditIngestServer{svc: s, token: token}
	mux.HandleFunc("POST "+auditIngestPath, ing.handleEgress)
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	ing.server = srv
	ing.ln = ln
	s.auditIngestMu.Lock()
	s.auditIngest = ing
	s.auditIngestMu.Unlock()

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			if s.logger != nil {
				s.logger.Error("audit ingest server stopped", "error", err)
			}
		}
	}()
	if ctx != nil {
		go func() {
			<-ctx.Done()
			s.StopAuditIngestServer()
		}()
	}
	if s.logger != nil {
		s.logger.Info("audit ingest listening", "addr", ln.Addr().String())
	}
	return nil
}

// StopAuditIngestServer shuts down the loopback ingest listener.
func (s *Service) StopAuditIngestServer() {
	if s == nil {
		return
	}
	s.auditIngestMu.Lock()
	ing := s.auditIngest
	s.auditIngest = nil
	s.auditIngestMu.Unlock()
	if ing == nil || ing.server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = ing.server.Shutdown(ctx)
}

// IssueEgressAuditCapability mints a per-sandbox HMAC capability for wasm
// workers. Scoped so a capability for sandbox A cannot forge events for B.
func (s *Service) IssueEgressAuditCapability(sandboxID, incarnationID string, ttl time.Duration) (string, error) {
	if s == nil {
		return "", errors.New("nil service")
	}
	key := s.auditIngestToken()
	if key == "" {
		return "", errors.New("audit ingest token unavailable")
	}
	if ttl <= 0 {
		ttl = auditlog.DefaultCapabilityTTL
	}
	return auditlog.MintEgressCapability(key, sandboxID, incarnationID, time.Now().UTC().Add(ttl))
}

func (s *Service) auditIngestToken() string {
	if s == nil {
		return ""
	}
	s.auditIngestMu.Lock()
	ing := s.auditIngest
	s.auditIngestMu.Unlock()
	if ing != nil && ing.token != "" {
		return ing.token
	}
	return strings.TrimSpace(s.cfg.AuditIngestToken)
}

func (ing *auditIngestServer) handleEgress(w http.ResponseWriter, r *http.Request) {
	if ing == nil || ing.svc == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			auditIngestRejectedTotal.Add(1)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, auditIngestMaxBody+1))
	if err != nil || len(body) > auditIngestMaxBody {
		auditIngestRejectedTotal.Add(1)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req auditIngestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		auditIngestRejectedTotal.Add(1)
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	capability := strings.TrimSpace(req.Capability)
	if capability == "" {
		capability = strings.TrimSpace(r.Header.Get(auditIngestHeaderCap))
	}
	// Prefer per-sandbox capability. Fall back to shared ingest token only when
	// no capability is presented (legacy tests / in-process callers).
	sandboxID := ""
	incarnationID := ""
	if capability != "" {
		sid, inc, err := auditlog.ParseAndVerifyEgressCapability(ing.token, capability, time.Now().UTC())
		if err != nil {
			auditIngestRejectedTotal.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sandboxID, incarnationID = sid, inc
	} else {
		if !secureTokenEqual(r.Header.Get(auditIngestHeaderToken), ing.token) {
			auditIngestRejectedTotal.Add(1)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sandboxID = strings.TrimSpace(req.SandboxID)
		// Do not trust client incarnation / placement lookup at process time
		// when a capability is present; without capability, leave incarnation
		// empty rather than resolving from live placement.
		incarnationID = ""
	}
	destination := strings.TrimSpace(req.Destination)
	if sandboxID == "" || destination == "" {
		auditIngestRejectedTotal.Add(1)
		http.Error(w, "sandbox_id and destination required", http.StatusBadRequest)
		return
	}
	kind := strings.TrimSpace(req.Kind)
	if kind == "" {
		kind = secretAuditKindEgress
	}
	// Reject anything other than egress (and gap when explicitly allowed).
	if kind != secretAuditKindEgress && kind != secretAuditKindGap {
		auditIngestRejectedTotal.Add(1)
		http.Error(w, "kind not allowed", http.StatusBadRequest)
		return
	}
	eventTime := req.EventTime
	if eventTime.IsZero() {
		eventTime = req.Time
	}
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}
	actor := ing.svc.auditActor()
	result := secretAuditResultSuccess
	reason := secretAuditReasonOK
	if kind == secretAuditKindGap {
		result = secretAuditResultGap
		reason = secretAuditReasonOverflow
	}
	// Ignore/overwrite client-supplied NodeID/Result/Reason/Incarnation.
	sink := ing.svc.secretAuditSink()
	if sink != nil {
		sink.Emit(SecretAuditEvent{
			Time:          eventTime.UTC(),
			Actor:         actor,
			SandboxID:     sandboxID,
			Result:        result,
			Reason:        reason,
			NodeID:        actor,
			Kind:          kind,
			Destination:   destination,
			Network:       strings.TrimSpace(req.Network),
			IncarnationID: incarnationID,
		})
	}
	auditIngestAcceptedTotal.Add(1)
	w.WriteHeader(http.StatusAccepted)
}

func newAuditIngestToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func secureTokenEqual(got, want string) bool {
	got = strings.TrimSpace(got)
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	if len(got) != len(want) {
		return false
	}
	var v byte
	for i := 0; i < len(want); i++ {
		v |= got[i] ^ want[i]
	}
	return v == 0
}
