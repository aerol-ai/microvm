package service

import (
	"bytes"
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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

const (
	auditIngestPath      = "/internal/audit/egress"
	auditIngestMaxBody   = 64 << 10
	auditIngestHeaderCap = "X-Aerol-Audit-Capability"
)

var (
	auditIngestAcceptedTotal = expvar.NewInt("aerolvm_audit_ingest_accepted_total")
	auditIngestRejectedTotal = expvar.NewInt("aerolvm_audit_ingest_rejected_total")
)

var errAuditIngestBindingStale = errors.New("audit ingest capability no longer belongs to an active local sandbox")

// auditIngestServer is a loopback-only HTTP listener that accepts egress audit
// events from wasm worker subprocesses. Workers must never write secrets.jsonl
// tip themselves — they POST here (or spill for parent drain).
type auditIngestServer struct {
	svc      *Service
	token    string
	port     string
	spillDir string
	server   *http.Server
	ln       net.Listener
	mu       sync.Mutex
}

type auditIngestRequest struct {
	Network     string `json:"network,omitempty"`
	Destination string `json:"destination"`
}

// StartAuditIngestServer binds 127.0.0.1:SB_AUDIT_INGEST_PORT (0 = ephemeral)
// and publishes only SB_AUDIT_INGEST_PORT. The master signing token remains in
// the daemon; workers receive sandbox-scoped capabilities over IPC.
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
	spillDir := ""
	if dataDir := secretAuditDataDir(s.cfg.DBPath); dataDir != "" {
		spillDir = filepath.Join(dataDir, "audit")
	}
	_ = os.Setenv("SB_AUDIT_INGEST_PORT", strconv.Itoa(actualPort))
	if spillDir != "" {
		_ = os.Setenv("SB_AUDIT_SPILL_DIR", spillDir)
	}

	mux := http.NewServeMux()
	ing := &auditIngestServer{svc: s, token: token, port: strconv.Itoa(actualPort), spillDir: spillDir}
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
	if os.Getenv("SB_AUDIT_INGEST_PORT") == ing.port {
		_ = os.Unsetenv("SB_AUDIT_INGEST_PORT")
	}
	if os.Getenv("SB_AUDIT_SPILL_DIR") == ing.spillDir {
		_ = os.Unsetenv("SB_AUDIT_SPILL_DIR")
	}
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

// IssueEgressAuditCapabilityForSandbox resolves the current placement
// incarnation and returns only the scoped capability needed by a worker.
func (s *Service) IssueEgressAuditCapabilityForSandbox(sandboxID string, ttl time.Duration) (string, string, error) {
	incarnationID := s.secretIncarnationForSeal(sandboxID)
	capability, err := s.IssueEgressAuditCapability(sandboxID, incarnationID, ttl)
	return capability, incarnationID, err
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
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		auditIngestRejectedTotal.Add(1)
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		auditIngestRejectedTotal.Add(1)
		http.Error(w, "single json object required", http.StatusBadRequest)
		return
	}
	capability := strings.TrimSpace(r.Header.Get(auditIngestHeaderCap))
	if capability == "" {
		auditIngestRejectedTotal.Add(1)
		http.Error(w, "sandbox capability required", http.StatusUnauthorized)
		return
	}
	sandboxID, incarnationID, err := auditlog.ParseAndVerifyEgressCapability(ing.token, capability, time.Now().UTC())
	if err != nil {
		auditIngestRejectedTotal.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := ing.svc.validateEgressAuditBinding(r.Context(), sandboxID, incarnationID); err != nil {
		auditIngestRejectedTotal.Add(1)
		if errors.Is(err, errAuditIngestBindingStale) {
			http.Error(w, "stale sandbox capability", http.StatusUnauthorized)
		} else {
			http.Error(w, "sandbox validation unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	destination := strings.TrimSpace(req.Destination)
	if sandboxID == "" || destination == "" {
		auditIngestRejectedTotal.Add(1)
		http.Error(w, "sandbox_id and destination required", http.StatusBadRequest)
		return
	}
	// Receipt time is authoritative. A worker capability authenticates the
	// sandbox identity, but it must not let a compromised worker backdate or
	// future-date records to influence retention ordering.
	eventTime := time.Now().UTC()
	actor := ing.svc.auditActor()
	// Actor, result, reason, sandbox, and incarnation are server-controlled.
	sink := ing.svc.secretAuditSink()
	event := SecretAuditEvent{
		Time:          eventTime.UTC(),
		Actor:         actor,
		SandboxID:     sandboxID,
		Result:        secretAuditResultSuccess,
		Reason:        secretAuditReasonOK,
		NodeID:        actor,
		Kind:          secretAuditKindEgress,
		Destination:   destination,
		Network:       strings.TrimSpace(req.Network),
		IncarnationID: incarnationID,
	}
	if durable, ok := sink.(DurableSecretAuditSink); ok {
		if err := durable.EmitDurable(event); err != nil {
			auditIngestRejectedTotal.Add(1)
			http.Error(w, "audit persistence unavailable", http.StatusServiceUnavailable)
			return
		}
	} else if ing.svc.cfg.EnterpriseMode {
		auditIngestRejectedTotal.Add(1)
		http.Error(w, "durable audit sink unavailable", http.StatusServiceUnavailable)
		return
	} else if sink != nil {
		sink.Emit(event)
	}
	auditIngestAcceptedTotal.Add(1)
	w.WriteHeader(http.StatusAccepted)
}

// validateEgressAuditBinding prevents a capability retained by a terminated or
// reassigned worker from continuing to append evidence under its old sandbox.
// Cluster placement is authoritative when enabled; standalone mode uses the
// local sandbox row. Incarnation and owner checks also fence failover races.
func (s *Service) validateEgressAuditBinding(ctx context.Context, sandboxID, incarnationID string) error {
	if s == nil || strings.TrimSpace(sandboxID) == "" {
		return errAuditIngestBindingStale
	}
	if s.cfg.EnableCluster {
		c := s.Cluster()
		if c == nil {
			return errAuditIngestBindingStale
		}
		p, ok := c.PlacementOf(sandboxID)
		if !ok || (strings.TrimSpace(p.OwnerNodeID) != "" && strings.TrimSpace(p.OwnerNodeID) != strings.TrimSpace(c.SelfNodeID())) || strings.TrimSpace(p.IncarnationID) != strings.TrimSpace(incarnationID) {
			return errAuditIngestBindingStale
		}
		return nil
	}
	if s.store == nil {
		return errAuditIngestBindingStale
	}
	sandbox, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errAuditIngestBindingStale
		}
		return err
	}
	current := auditlog.LocalIncarnationID(sandbox.ID, sandbox.ToolboxToken)
	if current == "" {
		current, err = s.store.CurrentSandboxAuditIncarnation(ctx, sandboxID)
		if err != nil {
			return err
		}
	}
	if strings.TrimSpace(current) == "" || strings.TrimSpace(current) != strings.TrimSpace(incarnationID) {
		return errAuditIngestBindingStale
	}
	return nil
}

func newAuditIngestToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
