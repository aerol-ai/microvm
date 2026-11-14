package service

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

// Every upgrade write and node step is audited with the caller from the
// committed rollout record (plans/kubectl-style-cluster-ops.md §6.3).
func TestRecordClusterUpgradeWritesAuditRecord(t *testing.T) {
	audit := &memSecretAuditSink{}
	svc := &Service{
		cfg:         config.Config{},
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		cluster:     cluster.NewNoop("wkr-1", "", ""),
		secretAudit: audit,
	}
	var _ cluster.UpgradeAuditRecorder = svc
	svc.RecordClusterUpgrade(cluster.UpgradeAuditEvent{Route: "node-step", Step: "apply", RolloutID: "r1", Caller: "pat:tok_7", NodeID: "wkr-1", Result: "success"})
	svc.RecordClusterUpgrade(cluster.UpgradeAuditEvent{Route: "apply", Result: "failure", Reason: "skipped_nodes"})
	var got []SecretAuditEvent
	for _, ev := range audit.Events() {
		if ev.Kind == auditKindClusterUpgrade {
			got = append(got, ev)
		}
	}
	if len(got) != 2 {
		t.Fatalf("records = %d, want 2", len(got))
	}
	ok, refused := got[0], got[1]
	if ok.Result != secretAuditResultSuccess || ok.Destination != "route=node-step step=apply rollout=r1 node=wkr-1 caller=pat:tok_7" || ok.EventID == "" {
		t.Fatalf("success record = %+v", ok)
	}
	if ok.Caller == nil || ok.Caller.Kind != "pat" || ok.Caller.ID != "tok_7" {
		t.Fatalf("caller = %+v, want the rollout's caller", ok.Caller)
	}
	if refused.Result != secretAuditResultFailure || refused.Reason != "skipped_nodes" || strings.Contains(refused.Destination, "rollout=") {
		t.Fatalf("failure record = %+v", refused)
	}
	if refused.Caller == nil || refused.Caller.Kind != "system" {
		t.Fatalf("no-caller record = %+v", refused.Caller)
	}
	var nilSvc *Service
	nilSvc.RecordClusterUpgrade(cluster.UpgradeAuditEvent{})
	(&Service{logger: svc.logger}).RecordClusterUpgrade(cluster.UpgradeAuditEvent{})
}
