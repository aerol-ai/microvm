package service

// Benchmarks of the gateway attach a hostname-rule create waits for
// (svc_egress_attach / svc_egress_join, plans/egress-domain-filtering.md
// §8.2). They drive a real egress.Gateway behind a real egress.Server over a
// UDS, a real SQLite store, and report each sub-stage (egress_attach_stages.go)
// as its own metric, so a regression shows where it landed:
//
//	go test -run '^$' -bench 'EgressAttach|EgressCreate' -benchtime 2000x ./internal/service/
//
// The kernel variants (egress_attach_kernel_test.go) swap in the real nft
// backend and the real host firewall in a privileged Linux container.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/runtime"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// attachBenchRules is the host firewall surface the attach touches: the
// driver's block-all and its lift. *netrules.Manager satisfies it.
type attachBenchRules interface {
	BlockAllEgress(ip string) error
	ClearBlockAllEgress(ip string) error
	LiftBlockAllEgress(ip string) error
}

// benchRuntime is a concurrency-safe container runtime: creates hand out
// distinct addresses, and the block-all rules go to a real firewall when
// one is wired (kernel benchmarks) or nowhere.
type benchRuntime struct {
	*recordingRuntime
	rules attachBenchRules
	// early reports the address before the build (as containerd's netns
	// pool, Docker's pause netns and Firecracker's TAP slot do); build is
	// how long the runtime create takes after that.
	early bool
	build time.Duration

	mu   sync.Mutex
	next uint32
}

func newBenchRuntime(rules attachBenchRules) *benchRuntime {
	return &benchRuntime{recordingRuntime: &recordingRuntime{}, rules: rules, next: 2}
}

func (r *benchRuntime) nextIP() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	r.next++
	return netip.AddrFrom4([4]byte{10, 99, byte(n >> 8), byte(n)}).String()
}

func (r *benchRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, sandboxID, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	ip := r.nextIP()
	if req.NetworkBlockAll {
		if err := r.ApplyNetworkBlockAll(ip); err != nil {
			return nil, err
		}
	}
	if r.early {
		runtime.NotifyAddressKnown(ctx, ip)
	}
	time.Sleep(r.build)
	return &models.SandboxRuntimeState{SandboxID: sandboxID, ContainerID: "ctr-" + sandboxID, ContainerIP: ip, Status: models.SandboxStatusStarted}, nil
}

func (r *benchRuntime) Destroy(context.Context, *models.Sandbox) error { return nil }

func (r *benchRuntime) ApplyNetworkBlockAll(ip string) error {
	if r.rules == nil {
		return nil
	}
	return r.rules.BlockAllEgress(ip)
}

func (r *benchRuntime) ClearNetworkBlockEgress(ip string) error {
	if r.rules == nil {
		return nil
	}
	// As the drivers: the sandbox keeps its address, so this is the lift.
	return r.rules.LiftBlockAllEgress(ip)
}

// attachBench is one service wired to one in-process gateway.
type attachBench struct {
	svc *Service
	gw  *egress.Gateway
	rt  *benchRuntime
	// tolerate counts failed creates instead of failing the benchmark
	// (the per-address path under heavy churn, kept for comparison).
	tolerate bool

	mu     sync.Mutex
	stages map[string][]time.Duration
}

func (a *attachBench) record(stage string, d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stages[stage] = append(a.stages[stage], d)
}

func (a *attachBench) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stages = map[string][]time.Duration{}
}

// newAttachBench serves a Gateway over be on a UDS and wires a Service to it
// through the production client, then runs the bootstrap so the timed
// attaches all take the steady-state path.
func newAttachBench(tb testing.TB, be egress.Backend, rules attachBenchRules) *attachBench {
	tb.Helper()
	st, err := storepkg.Open(filepath.Join(tb.TempDir(), "state.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = st.Close() })
	cipher, err := secrets.NewCipher("", filepath.Join(tb.TempDir(), "key"))
	if err != nil {
		tb.Fatal(err)
	}
	st.SetSecretCipher(cipher)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := mounts.New(logger, mounts.Config{RootDir: filepath.Join(tb.TempDir(), "mounts"), CredDir: filepath.Join(tb.TempDir(), "cred"), WaitTimeout: time.Second})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(mgr.Close)

	g := egress.New(egress.Options{Backend: be, Layout: egress.LayoutConfig{DNSPort: 53054, ProxyPort: 15080}})
	if err := g.Bootstrap(); err != nil {
		tb.Fatal(err)
	}
	// A short directory: a UDS path is capped at ~104 bytes.
	dir, err := os.MkdirTemp("", "egb")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "gw.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		tb.Fatal(err)
	}
	srv := egress.NewServer(g, egress.ServerHooks{SetBridges: func([]egress.Bridge) error { return nil }}, nil, nil, nil)
	go func() { _ = srv.Serve(ln) }()
	tb.Cleanup(func() { _ = ln.Close(); srv.Close() })
	client := egress.NewClient(sock)
	tb.Cleanup(client.Close)

	rt := newBenchRuntime(rules)
	a := &attachBench{gw: g, rt: rt, stages: map[string][]time.Duration{}}
	svc := &Service{
		cfg: config.Config{Runtime: models.RuntimeDocker, ToolboxPort: 4321, HTTPClientTimeout: time.Second,
			EgressFQDNEnabled: true},
		logger:         logger,
		store:          st,
		docker:         rt,
		caddy:          caddy.New(config.Config{HTTPClientTimeout: time.Second}),
		mounts:         mgr,
		admitter:       capacity.New(capacity.HostInfo{CPUCores: 1 << 16, MemoryTotalMB: 1 << 30}, capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1}, nil),
		images:         newDefaultImageDistributionProvider(""),
		cipher:         cipher,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
	}
	svc.testAttachStage = a.record
	svc.SetEgressGateway(client, func(context.Context) []egress.Bridge {
		return []egress.Bridge{{Name: "aerolvm0", GatewayIP: netip.MustParseAddr("10.99.0.1"), Subnet: netip.MustParsePrefix("10.99.0.0/16")}}
	})
	if err := svc.EnsureEgressGatewayReady(context.Background()); err != nil {
		tb.Fatal(err)
	}
	a.svc = svc
	return a
}

// prefill attaches n other gateway-mode sandboxes, the steady state of a
// busy node: their set elements are what every later attach's batch lands
// next to.
func (a *attachBench) prefill(tb testing.TB, n int) {
	tb.Helper()
	cr := a.rt
	for i := 0; i < n; i++ {
		sb := benchSandbox(fmt.Sprintf("prefill-%d", i), a.rt.nextIP())
		if err := cr.ApplyNetworkBlockAll(sb.ContainerIP); err != nil {
			tb.Fatal(err)
		}
		if err := a.svc.attachSandboxEgress(context.Background(), sb, cr); err != nil {
			tb.Fatal(err)
		}
	}
	a.reset()
}

func benchSandbox(id, ip string) *models.Sandbox {
	return &models.Sandbox{ID: id, ContainerID: "ctr-" + id, ContainerIP: ip, Runtime: models.RuntimeDocker,
		NetworkAllowOut: []string{"pypi.org", "files.pythonhosted.org"}}
}

// attachOnce runs one attach the way a create does (driver block first)
// and detaches it after the clock stops.
func (a *attachBench) attachOnce(tb testing.TB, i int) time.Duration {
	sb := benchSandbox(fmt.Sprintf("sbx-%d", i), a.rt.nextIP())
	if err := a.rt.ApplyNetworkBlockAll(sb.ContainerIP); err != nil {
		tb.Fatal(err)
	}
	start := time.Now()
	if err := a.svc.attachSandboxEgress(context.Background(), sb, a.rt); err != nil {
		tb.Fatal(err)
	}
	return time.Since(start)
}

func (a *attachBench) reportStages(b *testing.B, total []time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	names := make([]string, 0, len(a.stages))
	for n := range a.stages {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b.ReportMetric(float64(pct(a.stages[n], 50).Microseconds()), n+"_p50_us")
	}
	b.ReportMetric(float64(pct(total, 50).Microseconds()), "attach_p50_us")
	b.ReportMetric(float64(pct(total, 99).Microseconds()), "attach_p99_us")
	if testing.Verbose() {
		b.Log(a.splitTable(total))
	}
}

// splitTable renders p50/p99 per sub-stage, for the PR and the logs.
func (a *attachBench) splitTable(total []time.Duration) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "\n%-10s %10s %10s\n", "stage", "p50", "p99")
	for _, n := range []string{attachStageLookup, attachStageReady, attachStageRPC, attachStageRelease, attachStageUnblock} {
		if v := a.stages[n]; len(v) > 0 {
			fmt.Fprintf(&sb, "%-10s %10v %10v\n", n, pct(v, 50), pct(v, 99))
		}
	}
	fmt.Fprintf(&sb, "%-10s %10v %10v (n=%d)\n", "total", pct(total, 50), pct(total, 99), len(total))
	return sb.String()
}

func pct(v []time.Duration, p int) time.Duration {
	if len(v) == 0 {
		return 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	i := (len(s)*p + 99) / 100
	if i > 0 {
		i--
	}
	return s[min(i, len(s)-1)]
}

// BenchmarkEgressAttach times attachSandboxEgress end to end against the
// in-memory nft backend, on an empty node and on one with 200 attached
// gateway-mode sandboxes.
func BenchmarkEgressAttach(b *testing.B) {
	for _, prefill := range []int{0, 200} {
		b.Run(fmt.Sprintf("prefill=%d", prefill), func(b *testing.B) {
			a := newAttachBench(b, egress.NewMemBackend(), nil)
			a.prefill(b, prefill)
			total := make([]time.Duration, 0, b.N)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				total = append(total, a.attachOnce(b, i))
			}
			b.StopTimer()
			a.reportStages(b, total)
		})
	}
}

// BenchmarkEgressCreate times a whole hostname-rule CreateSandbox and reports
// the createtiming stages the live UC-185 reads: the attach, and how long
// the create actually waited for it (svc_egress_join), for a runtime that
// reports the address only on return (late) and one that reports it before
// a 5 ms build (early).
func BenchmarkEgressCreate(b *testing.B) {
	for _, early := range []bool{false, true} {
		b.Run(map[bool]string{false: "late", true: "early"}[early], func(b *testing.B) {
			a := newAttachBench(b, egress.NewMemBackend(), nil)
			a.rt.early, a.rt.build = early, 5*time.Millisecond
			benchCreates(b, a)
		})
	}
}

func benchCreates(b *testing.B, a *attachBench) {
	stages := map[string][]time.Duration{}
	failed := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, timing := createtiming.With(context.Background())
		if _, err := a.svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}}); err != nil {
			if !a.tolerate {
				b.Fatal(err)
			}
			failed++
			continue
		}
		for _, st := range timing.Stages() {
			if strings.HasPrefix(st.Name, "svc_egress") || st.Name == "svc_persist" {
				stages[st.Name] = append(stages[st.Name], time.Duration(st.DurMS*float64(time.Millisecond)))
			}
		}
	}
	b.StopTimer()
	if a.tolerate {
		b.ReportMetric(float64(failed), "creates_failed")
	}
	names := make([]string, 0, len(stages))
	for n := range stages {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		b.ReportMetric(float64(pct(stages[n], 50).Microseconds()), n+"_p50_us")
		fmt.Fprintf(&sb, "%-28s p50 %10v p99 %10v\n", n, pct(stages[n], 50), pct(stages[n], 99))
	}
	if testing.Verbose() {
		b.Log("\n" + sb.String())
	}
}
