package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestCoverage97CreateRejectsDisabledPlatformVolumes(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{
		Image:           "alpine:3",
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/data"}},
	})
	if !errors.Is(err, models.ErrPlatformVolumesDisabled) {
		t.Fatalf("CreateSandbox = %v", err)
	}
}

func TestCoverage97CreateUsesExistingIncarnation(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.logger = slog.New(slog.DiscardHandler)
	svc.cluster = &placementOnlyCluster{
		Noop:      cluster.NewNoop("node-a", "http://node-a", ""),
		placement: cluster.Placement{SandboxID: "placed", IncarnationID: "inc-cov97"},
	}
	created, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine:3"})
	if err != nil || created == nil || created.ID == "" {
		t.Fatalf("CreateSandbox = %v %v", created, err)
	}
}

type cov97SecretPusher struct {
	*cluster.Noop
	pushErr error
	pushAck []string
}

func (p cov97SecretPusher) PushSecretBlobToPeers(context.Context, secrets.SecretBlob, []string) ([]string, error) {
	if p.pushErr != nil {
		return p.pushAck, p.pushErr
	}
	return p.pushAck, nil
}
func (cov97SecretPusher) DeleteSecretOnPeers(context.Context, string, string, []string, int64) ([]string, error) {
	return nil, nil
}
func (cov97SecretPusher) ProbeSecretOnPeers(context.Context, string, string, []string, int64) ([]string, error) {
	return nil, nil
}

func TestCoverage97SecretPeerPusherFromCluster(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cluster = &cov97SecretPusher{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	if svc.secretPeerPusher() == nil {
		t.Fatal("cluster pusher was not visible to the service")
	}
}

func TestCoverage97ReconcileUnmountWithoutManager(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.logger = slog.New(slog.DiscardHandler)
	if _, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine:3"}); err != nil {
		t.Fatalf("CreateSandbox = %v", err)
	}
	svc.mounts = nil
	svc.testForceUnmountErr = errors.New("fuse busy")
	svc.cfg.EnableCluster = true
	rt.managed = map[string]*models.SandboxRuntimeState{}
	// Authoritative placement lookup fails closed before the end-of-pass
	// mount sweep, which cannot run with a nil manager.
	if err := svc.Reconcile(context.Background()); err == nil {
		t.Fatal("reconcile with cluster enabled and no client succeeded")
	}
}
