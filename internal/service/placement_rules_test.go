package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Single-node placement rules (plans/placement-rules.md P1.6): a rule this
// node's labels do not satisfy is the same 409 a cluster gives, refused
// before anything is created. In a cluster the same check is the worker's
// own guard against a router on an older build.
func TestCreateSandboxRefusesPlacementRuleThisNodeMisses(t *testing.T) {
	cases := []struct {
		name      string
		labels    map[string]string
		placement *models.PlacementRule
		wantErr   error
	}{
		{name: "unlabelled node, zone rule", placement: &models.PlacementRule{Zone: "zone-a"}, wantErr: models.ErrPlacementUnsatisfiable},
		{name: "wrong zone", labels: map[string]string{"zone": "zone-b"}, placement: &models.PlacementRule{Zone: "zone-a"}, wantErr: models.ErrPlacementUnsatisfiable},
		{name: "missing label", labels: map[string]string{"zone": "zone-a"}, placement: &models.PlacementRule{Zone: "zone-a", Labels: map[string]string{"gpu": "a10"}}, wantErr: models.ErrPlacementUnsatisfiable},
		{name: "malformed rule", placement: &models.PlacementRule{Labels: map[string]string{"bad key": "v"}}, wantErr: models.ErrInvalidPlacement},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := New(config.Config{NodeLabels: tc.labels}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, nil, nil, nil, nil)
			_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine", Placement: tc.placement})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("CreateSandbox err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestCheckPlacementRule(t *testing.T) {
	svc := &Service{cfg: config.Config{NodeLabels: map[string]string{"zone": "zone-a", "gpu": "a10"}}}
	req := models.CreateSandboxRequest{Placement: &models.PlacementRule{Labels: map[string]string{"zone": " zone-a ", "gpu": "a10"}}}
	if err := svc.checkPlacementRule(&req); err != nil {
		t.Fatalf("matching rule: %v", err)
	}
	// The rule is stored canonical, so the spec this node records and
	// replicates is the same whichever way the caller wrote the zone.
	if req.Placement.Zone != "zone-a" || req.Placement.Labels["zone"] != "" || req.Placement.Labels["gpu"] != "a10" {
		t.Fatalf("rule not normalized: %+v", req.Placement)
	}
	empty := models.CreateSandboxRequest{Placement: &models.PlacementRule{}}
	if err := svc.checkPlacementRule(&empty); err != nil || empty.Placement != nil {
		t.Fatalf("an empty rule must be no rule: %+v err=%v", empty.Placement, err)
	}
	none := models.CreateSandboxRequest{}
	if err := (&Service{}).checkPlacementRule(&none); err != nil {
		t.Fatalf("no rule on an unlabelled node: %v", err)
	}
	miss := models.CreateSandboxRequest{Placement: &models.PlacementRule{Zone: "zone-b"}}
	err := svc.checkPlacementRule(&miss)
	if !errors.Is(err, models.ErrPlacementUnsatisfiable) || !strings.Contains(err.Error(), "zone=zone-b") {
		t.Fatalf("miss = %v, want a 409 naming the rule", err)
	}
}

func TestRecordFailoverRefusedWritesAuditRecord(t *testing.T) {
	audit := &memSecretAuditSink{}
	svc := &Service{
		cfg:         config.Config{},
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		cluster:     cluster.NewNoop("node-a", "", ""),
		secretAudit: audit,
	}
	svc.RecordFailoverRefused(cluster.FailoverRefusal{SandboxID: "sb-1", IncarnationID: "inc-1", OwnerRef: "team:risk",
		FromNodeID: "node-dead", Reason: cluster.FailoverRefusalReasonPlacement, Rule: "zone=zone-a"})
	var got []SecretAuditEvent
	for _, ev := range audit.Events() {
		if ev.Kind == auditKindFailoverRefused {
			got = append(got, ev)
		}
	}
	if len(got) != 1 {
		t.Fatalf("records = %d, want 1", len(got))
	}
	ev := got[0]
	if ev.SandboxID != "sb-1" || ev.IncarnationID != "inc-1" || ev.OwnerRef != "team:risk" || ev.Result != secretAuditResultFailure ||
		ev.Reason != cluster.FailoverRefusalReasonPlacement || ev.Destination != "from=node-dead rule=zone=zone-a" || ev.EventID == "" || ev.NodeID != "node-a" {
		t.Fatalf("record = %+v", ev)
	}
	if ev.Caller == nil || ev.Caller.ID != "system:"+auditSubsystemFailover {
		t.Fatalf("caller = %+v", ev.Caller)
	}
	// No sink (tests, no data dir) is a no-op, never a panic.
	var nilSvc *Service
	nilSvc.RecordFailoverRefused(cluster.FailoverRefusal{})
}
