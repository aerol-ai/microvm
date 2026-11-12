package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/internal/usagemetrics"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// cgroupRuntime is a containerd-like runtime: it names each sandbox's
// cgroup as /aerolvm/<container id>.
type cgroupRuntime struct{ *recordingRuntime }

func (cgroupRuntime) SandboxCgroup(ref string) string { return "/aerolvm/" + ref }

// usageValue returns family name's series for owner and whether it exists.
func usageValue(m *usagemetrics.Meter, name, owner string) (float64, bool) {
	for _, f := range m.Collect() {
		if f.Name != name {
			continue
		}
		for _, s := range f.Samples {
			for _, l := range s.Labels {
				if l.Name == "owner" && l.Value == owner {
					return s.Value, true
				}
			}
		}
	}
	return 0, false
}

func fakeCgroup(t *testing.T, root, ref string, usageUsec, memBytes int) {
	t.Helper()
	dir := filepath.Join(root, "aerolvm", ref)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"cpu.stat":       "usage_usec " + strconv.Itoa(usageUsec) + "\n",
		"memory.current": strconv.Itoa(memBytes) + "\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// newUsageMetricsService is a service with a real store, a Docker-engine runtime
// and a containerd-engine runtime that names cgroups, and the exporter's
// meter already in place (as StartUsageMetrics leaves it), started at t0.
func newUsageMetricsService(t *testing.T, t0 time.Time) (*Service, *storepkg.Store, *usagemetrics.Meter) {
	t.Helper()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := &Service{
		cfg:             config.Config{Runtime: models.RuntimeDocker, UsageMetricsEnabled: true},
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:           st,
		docker:          &recordingRuntime{},
		containerd:      cgroupRuntime{&recordingRuntime{}},
		usageCgroupRoot: t.TempDir(),
	}
	m := usagemetrics.NewMeter("inc-test", t0)
	svc.usageMeter.Store(m)
	return svc, st, m
}

func putUsageRow(t *testing.T, st *storepkg.Store, sb models.Sandbox) {
	t.Helper()
	if sb.Image == "" {
		sb.Image = "ubuntu:22.04"
	}
	if sb.UpdatedAt.IsZero() {
		sb.UpdatedAt = sb.CreatedAt
	}
	if err := st.Create(context.Background(), &sb); err != nil {
		t.Fatalf("Create(%s): %v", sb.ID, err)
	}
}

func TestUsageMetricsSample(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		row   models.Sandbox
		setup func(t *testing.T, svc *Service)
		// After samples at t0+15s and t0+30s, for owner "acme".
		wantReservedCPU float64
		wantConsumedCPU float64
		wantFailures    float64
		wantOwner       bool
	}{
		{
			name: "containerd: reserved from the row, consumed from the cgroup files",
			row: models.Sandbox{ID: "sb-c", ContainerID: "sb-c", OwnerRef: "acme", Status: models.SandboxStatusStarted,
				CPU: 2, MemoryMB: 512, Engine: models.ContainerEngineContainerd, Runtime: models.RuntimeGvisor, CreatedAt: t0.Add(5 * time.Second)},
			setup: func(t *testing.T, svc *Service) {
				fakeCgroup(t, svc.usageCgroupRoot, "sb-c", 4_000_000, 64<<20)
			},
			wantReservedCPU: 2 * 25, wantConsumedCPU: 4, wantOwner: true,
		},
		{
			name: "containerd: a cgroup that cannot be read is a counted failure, and the charge still runs",
			row: models.Sandbox{ID: "sb-gone", OwnerRef: "acme", Status: models.SandboxStatusStarted,
				CPU: 1, MemoryMB: 256, Engine: models.ContainerEngineContainerd, CreatedAt: t0},
			wantReservedCPU: 30, wantConsumedCPU: 0, wantFailures: 2, wantOwner: true,
		},
		{
			name: "docker: consumed from the Docker stats call",
			row: models.Sandbox{ID: "sb-d", ContainerID: "abc123", OwnerRef: "acme", Status: models.SandboxStatusStarted,
				CPU: 1, MemoryMB: 256, Engine: models.ContainerEngineDocker, CreatedAt: t0},
			setup: func(t *testing.T, svc *Service) {
				svc.usageDockerStats = func(_ context.Context, ref string) (docker.ContainerStat, error) {
					if ref != "abc123" {
						t.Errorf("stats for %q, want the container id abc123", ref)
					}
					return docker.ContainerStat{CPUTotalNanos: 9e9, MemBytes: 32 << 20}, nil
				}
			},
			// Made at the process start, so its whole count is this
			// process's.
			wantReservedCPU: 30, wantConsumedCPU: 9, wantOwner: true,
		},
		{
			name: "docker: a failed stats call is a counted failure",
			row: models.Sandbox{ID: "sb-d", OwnerRef: "acme", Status: models.SandboxStatusStarted,
				CPU: 1, MemoryMB: 256, CreatedAt: t0},
			setup: func(t *testing.T, svc *Service) {
				svc.usageDockerStats = func(context.Context, string) (docker.ContainerStat, error) {
					return docker.ContainerStat{}, errors.New("no such container")
				}
			},
			wantReservedCPU: 30, wantFailures: 2, wantOwner: true,
		},
		{
			name: "docker: the real Docker client is used when no test hook is set",
			row: models.Sandbox{ID: "sb-d", OwnerRef: "acme", Status: models.SandboxStatusStarted,
				CPU: 1, MemoryMB: 256, CreatedAt: t0},
			setup: func(t *testing.T, svc *Service) {
				// A socket that is not there: each read fails, offline.
				t.Setenv("DOCKER_HOST", "unix://"+filepath.Join(t.TempDir(), "no-docker.sock"))
				c, err := docker.New(svc.logger, config.Config{ToolboxBinaryPath: "toolboxd", HTTPClientTimeout: time.Second}, nil)
				if err != nil {
					t.Fatal(err)
				}
				svc.dockerAux = c
			},
			wantReservedCPU: 30, wantFailures: 2, wantOwner: true,
		},
		{
			name: "containerd: the default cgroup root is /sys/fs/cgroup",
			row: models.Sandbox{ID: "sb-not-on-this-machine", OwnerRef: "acme", Status: models.SandboxStatusStarted,
				CPU: 1, MemoryMB: 256, Engine: models.ContainerEngineContainerd, CreatedAt: t0},
			setup: func(t *testing.T, svc *Service) {
				// No such group under the real mount (or no mount at all,
				// off Linux): each read fails, and is counted.
				svc.usageCgroupRoot = ""
			},
			wantReservedCPU: 30, wantFailures: 2, wantOwner: true,
		},
		{
			name: "docker: no Docker client reads nothing, and charges the reservation",
			row: models.Sandbox{ID: "sb-d", OwnerRef: "acme", Status: models.SandboxStatusStarted,
				CPU: 1, MemoryMB: 256, CreatedAt: t0},
			wantReservedCPU: 30, wantOwner: true,
		},
		{
			name: "firecracker: no cgroup of its own, so reserved only",
			row: models.Sandbox{ID: "sb-fc", OwnerRef: "acme", Status: models.SandboxStatusStarted,
				CPU: 2, MemoryMB: 256, Runtime: models.RuntimeFirecracker, CreatedAt: t0},
			setup: func(t *testing.T, svc *Service) {
				svc.firecracker = &recordingRuntime{}
				svc.usageDockerStats = func(context.Context, string) (docker.ContainerStat, error) {
					t.Error("a Firecracker sandbox must not be read through Docker")
					return docker.ContainerStat{}, nil
				}
			},
			wantReservedCPU: 60, wantOwner: true,
		},
		{
			name: "a runtime this node does not have reads nothing and is still charged",
			row: models.Sandbox{ID: "sb-w", OwnerRef: "acme", Status: models.SandboxStatusStarted,
				CPU: 1, MemoryMB: 256, Runtime: models.RuntimeWasm, CreatedAt: t0},
			wantReservedCPU: 30, wantOwner: true,
		},
		{
			name: "an owner whose only sandbox is stopped is not exported",
			row: models.Sandbox{ID: "sb-s", OwnerRef: "acme", Status: models.SandboxStatusStopped,
				CPU: 1, MemoryMB: 256, CreatedAt: t0},
			wantOwner: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, m := newUsageMetricsService(t, t0)
			putUsageRow(t, st, tc.row)
			if tc.setup != nil {
				tc.setup(t, svc)
			}
			ctx := context.Background()
			svc.sampleUsageMetricsOnce(ctx, t0.Add(15*time.Second))
			svc.sampleUsageMetricsOnce(ctx, t0.Add(30*time.Second))

			cpu, ok := usageValue(m, usagemetrics.MetricReservedCPU, "acme")
			if ok != tc.wantOwner {
				t.Fatalf("owner acme exported = %v, want %v", ok, tc.wantOwner)
			}
			if !ok {
				return
			}
			consumed, _ := usageValue(m, usagemetrics.MetricConsumedCPU, "acme")
			if cpu != tc.wantReservedCPU || consumed != tc.wantConsumedCPU {
				t.Fatalf("reserved, consumed CPU = %v, %v; want %v, %v", cpu, consumed, tc.wantReservedCPU, tc.wantConsumedCPU)
			}
			var failures float64
			for _, f := range m.Collect() {
				if f.Name == usagemetrics.MetricReadFailures {
					failures = f.Samples[0].Value
				}
			}
			if failures != tc.wantFailures {
				t.Fatalf("read failures = %v, want %v", failures, tc.wantFailures)
			}
		})
	}
}

// A sandbox destroyed between two samples is charged up to its removal,
// not up to the next sample.
func TestUsageMetricsChargesUntilDestroy(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	m := usagemetrics.NewMeter("inc-test", time.Now().UTC().Add(-time.Minute))
	svc.usageMeter.Store(m)
	ctx := context.Background()

	id := createOwned(t, svc, "acme", "sb-usage-destroy")
	svc.sampleUsageMetricsOnce(ctx, time.Now().UTC())
	if err := svc.DestroySandbox(ctx, id); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}
	charged, ok := usageValue(m, usagemetrics.MetricReservedCPU, "acme")
	if !ok {
		t.Fatal("no reserved series for acme")
	}
	// The next sample is half an hour on (inside the owner's retention): a
	// charge running to it would be about half an hour of CPU.
	svc.sampleUsageMetricsOnce(ctx, time.Now().UTC().Add(30*time.Minute))
	after, ok := usageValue(m, usagemetrics.MetricReservedCPU, "acme")
	if !ok || after != charged {
		t.Fatalf("reserved CPU moved from %v to %v after the destroy", charged, after)
	}
	if charged > 60 {
		t.Fatalf("reserved CPU = %v, more than the sandbox lived", charged)
	}
}

func TestUsageMetricsOff(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	ctx := context.Background()
	svc.StartUsageMetrics(ctx) // SB_USAGE_METRICS_ENABLED is off
	if svc.UsageMeter() != nil {
		t.Fatal("UsageMeter() is set with the exporter off")
	}
	id := createOwned(t, svc, "acme", "sb-usage-off")
	// Neither the sampler nor the delete hook does anything, and neither
	// panics.
	svc.sampleUsageMetricsOnce(ctx, time.Now())
	if err := svc.DestroySandbox(ctx, id); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}
	if svc.UsageMeter() != nil {
		t.Fatal("UsageMeter() appeared with the exporter off")
	}
}

func TestStartUsageMetrics(t *testing.T) {
	orig := usageMetricsInterval
	usageMetricsInterval = 10 * time.Millisecond
	t.Cleanup(func() { usageMetricsInterval = orig })

	svc, st, _ := newUsageMetricsService(t, time.Now())
	svc.usageMeter.Store(nil) // as at boot: StartUsageMetrics makes it
	putUsageRow(t, st, models.Sandbox{ID: "sb-1", OwnerRef: "acme", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 128, Runtime: models.RuntimeWasm, CreatedAt: time.Now().UTC().Add(-time.Hour)})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartUsageMetrics(ctx)
	m := svc.UsageMeter()
	if m == nil || m.Incarnation() == "" {
		t.Fatalf("UsageMeter() = %v after StartUsageMetrics", m)
	}
	svc.StartUsageMetrics(ctx)
	if svc.UsageMeter() != m {
		t.Fatal("a second StartUsageMetrics replaced the counters")
	}
	// The loop samples at once and then on its ticker: the charge grows.
	deadline := time.Now().Add(5 * time.Second)
	var first float64
	for {
		v, ok := usageValue(m, usagemetrics.MetricReservedCPU, "acme")
		if ok && first == 0 {
			first = v
		}
		if ok && v > first {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reserved CPU did not grow: first %v, now %v", first, v)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
}

// Without a store there is nothing to sample, so the exporter stays off.
func TestStartUsageMetricsNoStore(t *testing.T) {
	svc := &Service{cfg: config.Config{UsageMetricsEnabled: true}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	svc.StartUsageMetrics(context.Background())
	if svc.UsageMeter() != nil {
		t.Fatal("UsageMeter() is set with no store")
	}
}

// A store that cannot be read skips the sample: the last-sample time stops
// moving, which is what the stale-exporter alert watches.
func TestUsageMetricsStoreError(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	svc, st, m := newUsageMetricsService(t, t0)
	svc.sampleUsageMetricsOnce(context.Background(), t0.Add(15*time.Second))
	_ = st.Close()
	svc.sampleUsageMetricsOnce(context.Background(), t0.Add(30*time.Second))
	for _, f := range m.Collect() {
		if f.Name == usagemetrics.MetricLastSample {
			if got := f.Samples[0].Value; got != float64(t0.Add(15*time.Second).Unix()) {
				t.Fatalf("last sample = %v, want the sample before the store failed", got)
			}
			return
		}
	}
	t.Fatal("no last-sample series")
}
