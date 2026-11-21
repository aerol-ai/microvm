package service

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// TestRecordRootRefusal: one record per refusal, naming the call, the
// reason and the node, and attributed to whoever led the node to make the
// call: the request's principal, else the subsystem, else the daemon. It
// carries nothing a tenant sent.
func TestRecordRootRefusal(t *testing.T) {
	refusal := rootclient.Refusal{Call: "Containers.Create", Reason: "mount"}
	for _, tc := range []struct {
		name       string
		ctx        context.Context
		cluster    bool
		wantCaller string // "" means no caller field
	}{
		{"an API request", controlplane.ContextWithAccess(context.Background(), controlplane.OperatorAccess()), false, "operator"},
		{"a background job", withAuditSubsystem(context.Background(), auditSubsystemReconcile), false, "system:" + auditSubsystemReconcile},
		{"nothing in the context", context.Background(), false, "system:" + controlplane.SystemDaemon},
		// A cluster member that cannot prove every peer reads the caller
		// field still writes the record, unattributed (§5.8).
		{"caller writes gated off", controlplane.ContextWithAccess(context.Background(), controlplane.OperatorAccess()), true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit := &memSecretAuditSink{}
			svc := &Service{
				cfg:         config.Config{EnableCluster: tc.cluster},
				logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
				cluster:     cluster.NewNoop("wkr-7", "", ""),
				secretAudit: audit,
			}
			var hook rootclient.RefusalFunc = svc.RecordRootRefusal
			hook(tc.ctx, refusal)
			events := audit.Events()
			if len(events) != 1 {
				t.Fatalf("records = %d, want 1", len(events))
			}
			ev := events[0]
			if ev.Kind != auditKindRootdRefusal || ev.Result != secretAuditResultFailure || ev.Reason != "mount" ||
				ev.Destination != "call=Containers.Create" || ev.NodeID != "wkr-7" || ev.Actor != "wkr-7" || ev.EventID == "" || ev.Time.IsZero() {
				t.Fatalf("record = %+v", ev)
			}
			if ev.SandboxID != "" || ev.OwnerRef != "" || ev.IncarnationID != "" || ev.Ref != "" {
				t.Fatalf("the record names a sandbox or owner: %+v", ev)
			}
			switch {
			case tc.wantCaller == "" && ev.Caller != nil:
				t.Fatalf("caller %+v, want none", ev.Caller)
			case tc.wantCaller != "" && (ev.Caller == nil || ev.Caller.ID != tc.wantCaller):
				t.Fatalf("caller %+v, want %s", ev.Caller, tc.wantCaller)
			}
			// The fields an auditor reads, as they land in the JSONL.
			raw, err := json.Marshal(ev)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"kind":"rootd_refusal"`, `"reason":"mount"`, `"destination":"call=Containers.Create"`, `"node_id":"wkr-7"`} {
				if !strings.Contains(string(raw), want) {
					t.Fatalf("record %s lacks %s", raw, want)
				}
			}
		})
	}
}

// TestRecordRootRefusalWithoutASink: a node with no audit sink, or no
// service, drops the record quietly; the client's metric still counts it.
func TestRecordRootRefusalWithoutASink(t *testing.T) {
	var nilSvc *Service
	nilSvc.RecordRootRefusal(context.Background(), rootclient.Refusal{Call: "Tasks.Create", Reason: "device"})
	(&Service{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).RecordRootRefusal(context.Background(), rootclient.Refusal{Call: "Tasks.Create", Reason: "device"})
}
