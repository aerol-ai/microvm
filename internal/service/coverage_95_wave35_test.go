package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWave35IsolateAndUsageGuards(t *testing.T) {
	ctx := context.Background()
	if err := ValidateClusterIsolateBundleRef(models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "bare-name"}); err == nil {
		t.Fatal("cluster isolate requires node-bound ref")
	}
	if err := ValidateClusterIsolateBundleRef(models.CreateSandboxRequest{Runtime: models.RuntimeDocker}); err != nil {
		t.Fatal(err)
	}

	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: cluster.NewNoop("self", "", "")}
	if _, err := svc.createIsolateSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "bare-name",
	}, ""); err == nil {
		t.Fatal("unbound cluster isolate create")
	}
	bound := models.JSBundleRefForNode("sha256:abc", "other-node")
	if _, err := svc.createIsolateSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: bound,
	}, ""); err == nil {
		t.Fatal("wrong-node isolate create")
	}

	if got := appendReservedSamples(nil, nil, time.Now(), time.Now().Add(time.Second)); len(got) != 0 {
		t.Fatalf("nil sandbox samples = %d", len(got))
	}
	if got := appendReservedSamples(nil, &models.Sandbox{ID: "sb"}, time.Now(), time.Now()); len(got) != 0 {
		t.Fatalf("zero window samples = %d", len(got))
	}
	if allowPublicTrafficEnabled(nil) {
		t.Fatal("nil public flag")
	}
	if sandboxAllowsPublicTraffic(nil) {
		t.Fatal("nil sandbox public")
	}
	if (*Service)(nil).sandboxPublicURL("id", boolPtr(true)) != "" {
		t.Fatal("nil service public url")
	}
	if err := (*Service)(nil).syncSandboxPublicRoute(ctx, &models.Sandbox{ID: "sb"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Service{}).createIsolateSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "bare-name", Durability: models.DurabilityPassivatable,
	}, ""); err == nil {
		t.Fatal("passivatable isolate must fail")
	}
	pub := true
	if err := (&Service{}).enableSandboxPublicTraffic(ctx, &models.Sandbox{ID: "sb", AllowPublicTraffic: &pub}); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{}).enableSandboxPublicTraffic(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{}).cleanupPublicTrafficDisabledIngressState(ctx, &models.Sandbox{ID: "sb", AllowPublicTraffic: &pub}); err != nil {
		t.Fatal(err)
	}

	start := time.Now().UTC()
	if got := appendReservedSamples(nil, &models.Sandbox{ID: "sb", DiskGB: 1}, start, start); len(got) != 0 {
		t.Fatalf("zero-length window = %d", len(got))
	}
	if got := appendReservedSamples(nil, &models.Sandbox{ID: "sb", DiskGB: 1}, start, start.Add(-time.Second)); len(got) != 0 {
		t.Fatalf("negative window = %d", len(got))
	}

	usage := newUsageService(&captureReporter{})
	usage.emitReservedUsageAt(ctx, nil, start)
	usage.emitReservedUsageAt(ctx, []*models.Sandbox{nil, {ID: "gone", Status: models.SandboxStatusDestroyed}}, start)
	future := &models.Sandbox{ID: "future", Status: models.SandboxStatusStarted, CreatedAt: start.Add(time.Hour)}
	usage.emitReservedUsageAt(ctx, []*models.Sandbox{future}, start)
	usage.emitNetworkUsage(ctx, &models.Sandbox{ID: "net"}, 0, 0, start)
	usage.emitNetworkUsage(ctx, &models.Sandbox{ID: "net"}, 8, 0, start)
}

func boolPtr(v bool) *bool { return &v }
