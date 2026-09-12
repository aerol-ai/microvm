package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestStartLiveUsageSamplerWithDockerAux(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.SetUsageReporter(&captureReporter{})
	svc.cfg.FleetLiveSampleInterval = time.Millisecond // below floor → clamped
	svc.SetDockerAuxClient(&docker.Client{})
	// Empty store → sampler ticks without calling ContainerStats (nil httpClient).
	svc.StartLiveUsageSampler(ctx)
	time.Sleep(30 * time.Millisecond)
}

func TestUsageLiveListAndStatsFailWave20(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.SetUsageReporter(&captureReporter{})
	_ = st.Close()
	svc.sampleLiveUsageOnce(context.Background(), time.Now().UTC(), func(context.Context, string) (docker.ContainerStat, error) {
		return docker.ContainerStat{}, nil
	})

	svc2, st2, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc2.SetUsageReporter(&captureReporter{})
	now := time.Now().UTC()
	_ = st2.Create(context.Background(), &models.Sandbox{
		ID: "sb-live", Image: "a", Status: models.SandboxStatusStarted, ContainerID: "ctr",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	svc2.sampleLiveUsageOnce(context.Background(), now, func(context.Context, string) (docker.ContainerStat, error) {
		return docker.ContainerStat{}, errors.New("stats boom")
	})
}
