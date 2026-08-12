package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
)

func TestEmitEgressAuditNilSinkNoPanic(t *testing.T) {
	var s *Service
	s.emitEgressAudit("sb", "tcp", "example.com:443")

	s = &Service{cfg: config.Config{EgressAttributionEnabled: true}}
	s.emitEgressAudit("sb", "tcp", "example.com:443") // no sink yet — ensureSecretAuditSink → noop
}

func TestEmitEgressAuditWritesKindEgress(t *testing.T) {
	mem := &memSecretAuditSink{}
	s := &Service{
		cfg:         config.Config{EgressAttributionEnabled: true},
		secretAudit: mem,
		cluster:     cluster.NewNoop("node-a", "", ""),
	}
	s.emitEgressAudit("sb-1", "tcp", "api.example.com:443")
	evs := mem.Events()
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Kind != secretAuditKindEgress || ev.Destination != "api.example.com:443" ||
		ev.Network != "tcp" || ev.SandboxID != "sb-1" || ev.Result != secretAuditResultSuccess ||
		ev.Ref != "" || ev.BytesIn != 0 || ev.BytesOut != 0 {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Actor != "node-a" || ev.NodeID != "node-a" {
		t.Fatalf("actor/node = %q/%q", ev.Actor, ev.NodeID)
	}
}

func TestEmitEgressAuditDisabledNoOp(t *testing.T) {
	mem := &memSecretAuditSink{}
	s := &Service{
		cfg:         config.Config{EgressAttributionEnabled: false},
		secretAudit: mem,
	}
	s.emitEgressAudit("sb-1", "tcp", "api.example.com")
	if len(mem.Events()) != 0 {
		t.Fatalf("expected no events when disabled, got %+v", mem.Events())
	}
}

func TestListSecretAuditIncludesEgressEvents(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	s := &Service{
		cfg: config.Config{
			DBPath:                   dbPath,
			EgressAttributionEnabled: true,
			SecretAuditRetentionDays: 30,
		},
		store:   st,
		cluster: cluster.NewNoop("node-a", "http://a", ""),
	}
	t.Cleanup(s.CloseSecretAuditSink)

	emitSecretAudit(s.secretAuditSink(), "sb-1", "env:sb-1", "node-a", "corr-open", "", nil)
	s.emitEgressAudit("sb-1", "tcp", "cdn.example.com")
	if f := s.secretAuditFile; f != nil {
		f.Sync()
	}

	page, err := s.ListSecretAudit(context.Background(), "sb-1", SecretAuditQuery{Limit: 100})
	if err != nil {
		t.Fatalf("ListSecretAudit: %v", err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("events = %d, want 2: %+v", len(page.Events), page.Events)
	}
	var sawOpen, sawEgress bool
	for _, ev := range page.Events {
		if ev.Kind == "" || ev.Kind == secretAuditKindSecretOpen {
			sawOpen = true
		}
		if ev.Kind == secretAuditKindEgress && ev.Destination == "cdn.example.com" {
			sawEgress = true
		}
	}
	if !sawOpen || !sawEgress {
		t.Fatalf("missing kinds in %+v", page.Events)
	}

	egressOnly, _, err := s.ListSecretAuditLocal(context.Background(), "sb-1", SecretAuditQuery{Kind: secretAuditKindEgress})
	if err != nil {
		t.Fatalf("ListSecretAuditLocal kind=egress: %v", err)
	}
	if len(egressOnly) != 1 || egressOnly[0].Destination != "cdn.example.com" {
		t.Fatalf("egress filter = %+v", egressOnly)
	}
}

func TestEgressAuditObserverNoCreatePath(t *testing.T) {
	// Observer is dial-path only; constructing Service / Create must not call it.
	mem := &memSecretAuditSink{}
	s := &Service{
		cfg:         config.Config{EgressAttributionEnabled: true},
		secretAudit: mem,
		cluster:     cluster.NewNoop("node-a", "", ""),
	}
	obs := s.EgressAuditObserver()
	if obs == nil {
		t.Fatal("nil observer")
	}
	if len(mem.Events()) != 0 {
		t.Fatalf("observer construction must not emit: %+v", mem.Events())
	}
	// Explicit dial-path call still works.
	obs("sb", "tcp", "host:1")
	deadline := time.Now().Add(time.Second)
	for len(mem.Events()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(mem.Events()) != 1 || mem.Events()[0].Kind != secretAuditKindEgress {
		t.Fatalf("events = %+v", mem.Events())
	}
}

func TestSecretAuditKindMatches(t *testing.T) {
	if !secretAuditKindMatches("", "") {
		t.Fatal("empty filter should match")
	}
	if !secretAuditKindMatches("", secretAuditKindSecretOpen) {
		t.Fatal("empty stored kind matches secret_open filter")
	}
	if secretAuditKindMatches("", secretAuditKindEgress) {
		t.Fatal("empty stored kind must not match egress filter")
	}
	if !secretAuditKindMatches(secretAuditKindEgress, secretAuditKindEgress) {
		t.Fatal("egress should match")
	}
}
