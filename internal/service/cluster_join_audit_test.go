package service

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

func TestRecordClusterJoinWritesAuditRecord(t *testing.T) {
	audit := &memSecretAuditSink{}
	svc := &Service{
		cfg:         config.Config{},
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		cluster:     cluster.NewNoop("srv-1", "", ""),
		secretAudit: audit,
	}
	var _ cluster.JoinAuditRecorder = svc
	svc.RecordClusterJoin(cluster.JoinAuditEvent{Route: cluster.JoinPath, Result: "success", Reason: "ok", Source: "10.0.0.9", TokenID: "abcdef", NodeID: "wkr-1", Role: "worker"})
	svc.RecordClusterJoin(cluster.JoinAuditEvent{Route: cluster.JoinClusterInfoPath, Result: "failure", Reason: "token_invalid", Source: "10.0.0.8"})
	var got []SecretAuditEvent
	for _, ev := range audit.Events() {
		if ev.Kind == auditKindClusterJoin {
			got = append(got, ev)
		}
	}
	if len(got) != 2 {
		t.Fatalf("records = %d, want 2", len(got))
	}
	ok, refused := got[0], got[1]
	if ok.Result != secretAuditResultSuccess || ok.Reason != "ok" || ok.Destination != "route=/v1/join source=10.0.0.9 token=abcdef node=wkr-1 role=worker" || ok.EventID == "" || ok.NodeID != "srv-1" {
		t.Fatalf("success record = %+v", ok)
	}
	if refused.Result != secretAuditResultFailure || refused.Reason != "token_invalid" || strings.Contains(refused.Destination, "token=") {
		t.Fatalf("failure record = %+v", refused)
	}
	if ok.Caller == nil || ok.Caller.ID != "system:"+auditSubsystemJoin {
		t.Fatalf("caller = %+v", ok.Caller)
	}
	var nilSvc *Service
	nilSvc.RecordClusterJoin(cluster.JoinAuditEvent{})
	(&Service{logger: svc.logger}).RecordClusterJoin(cluster.JoinAuditEvent{})
}
