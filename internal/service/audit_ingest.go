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
)

const (
	auditIngestPath        = "/internal/audit/egress"
	auditIngestDefaultPort = 21215
	auditIngestMaxBody     = 64 << 10
	auditIngestHeaderToken = "X-Aerol-Audit-Token"
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
	SandboxID     string `json:"sandbox_id"`
	Network       string `json:"network,omitempty"`
	Destination   string `json:"destination"`
	NodeID        string `json:"node_id,omitempty"`
	IncarnationID string `json:"incarnation_id,omitempty"`
	Kind          string `json:"kind,omitempty"`
	Result        string `json:"result,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// StartAuditIngestServer binds 127.0.0.1:SB_AUDIT_INGEST_PORT (default 21215)
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
	if port <= 0 {
		port = auditIngestDefaultPort
	}
	token := strings.TrimSpace(s.cfg.AuditIngestToken)
	if token == "" {
		token = newAuditIngestToken()
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
	if !secureTokenEqual(r.Header.Get(auditIngestHeaderToken), ing.token) {
		auditIngestRejectedTotal.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
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
	sandboxID := strings.TrimSpace(req.SandboxID)
	destination := strings.TrimSpace(req.Destination)
	if sandboxID == "" || destination == "" {
		auditIngestRejectedTotal.Add(1)
		http.Error(w, "sandbox_id and destination required", http.StatusBadRequest)
		return
	}
	kind := strings.TrimSpace(req.Kind)
	if kind == "" || kind == secretAuditKindEgress {
		ing.svc.emitEgressAudit(sandboxID, req.Network, destination)
	} else {
		actor := strings.TrimSpace(req.NodeID)
		if actor == "" {
			actor = ing.svc.auditActor()
		}
		inc := strings.TrimSpace(req.IncarnationID)
		if inc == "" {
			inc = ing.svc.secretIncarnationForSeal(sandboxID)
		}
		result := strings.TrimSpace(req.Result)
		if result == "" {
			result = secretAuditResultSuccess
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = secretAuditReasonOK
		}
		sink := ing.svc.secretAuditSink()
		if sink != nil {
			sink.Emit(SecretAuditEvent{
				Time:          time.Now().UTC(),
				Actor:         actor,
				SandboxID:     sandboxID,
				Result:        result,
				Reason:        reason,
				NodeID:        actor,
				Kind:          kind,
				Destination:   destination,
				Network:       strings.TrimSpace(req.Network),
				IncarnationID: inc,
			})
		}
	}
	auditIngestAcceptedTotal.Add(1)
	w.WriteHeader(http.StatusAccepted)
}

func newAuditIngestToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("audit-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
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
