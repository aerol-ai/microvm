package clustercreate

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestOverlapCreateAndPromoteNilClusterSequentialPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, st := newCreateService(t, nil, true)
	resp, err := OverlapCreateAndPromote(context.Background(), svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-seq-nil-cluster", OverlapOptions{})
	if err != nil {
		t.Fatalf("OverlapCreateAndPromote: %v", err)
	}
	if resp.Sandbox.ID != "sb-seq-nil-cluster" {
		t.Fatalf("id = %q", resp.Sandbox.ID)
	}
	if _, err := st.Get(context.Background(), "sb-seq-nil-cluster"); err != nil {
		t.Fatalf("store.Get: %v", err)
	}
}

func TestRetractFailedPromoteDeletePlacementFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &clusterStub{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		deleteErr: errors.New("raft delete failed"),
	}
	svc, _ := newCreateService(t, stub, true)
	seedReservedPlacement(stub, "sb-del-fail")
	if _, err := svc.CreateSandboxWithID(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-del-fail"); err != nil {
		t.Fatalf("CreateSandboxWithID: %v", err)
	}
	retractFailedPromote(context.Background(), svc, logger, "sb-del-fail")
	if stub.deletes != 1 {
		t.Fatalf("DeletePlacement calls = %d, want 1", stub.deletes)
	}
}

func TestRetractReservedCreateDeleteSecretsFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	svc, st := newCreateService(t, stub, true)
	if _, err := svc.CreateSandboxWithID(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-secrets-del"); err != nil {
		t.Fatalf("CreateSandboxWithID: %v", err)
	}
	_ = st.Close()
	retractReservedCreate(context.Background(), svc, stub, logger, "sb-secrets-del", nil)
	if stub.cancels != 0 {
		t.Fatalf("CancelReservation calls = %d, want 0 while exact secret cleanup is not durable", stub.cancels)
	}
}

func TestRetractFailedPromoteDeleteSecretsFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	svc, st := newCreateService(t, stub, true)
	if _, err := svc.CreateSandboxWithID(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-secrets-fail"); err != nil {
		t.Fatalf("CreateSandboxWithID: %v", err)
	}
	_ = st.Close()
	retractFailedPromote(context.Background(), svc, logger, "sb-secrets-fail")
	if stub.deletes != 0 {
		t.Fatalf("DeletePlacement calls = %d, want 0 while exact secret cleanup is not durable", stub.deletes)
	}
}
