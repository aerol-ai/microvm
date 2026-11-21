package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd"
)

// The gate's hop on a create (plans/security-gaps-m1-m4.md §3.7): in
// privilege mode split every containerd call a create makes goes through
// the root helper's socket and the gate (checks, then a second gRPC hop to
// containerd), where single mode calls containerd directly. Both ways here
// reach the same stand-in containerd, which answers at once except for
// Tasks.Create, which waits as long as a shim and runc take to start, so
// the difference between them is the hop and the checks alone; a real
// containerd adds the same work to both.

// specFor is goodSpec for container id.
func specFor(t testing.TB, id string) *specs.Spec {
	t.Helper()
	b, err := json.Marshal(goodSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	var s specs.Spec
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(b), testID, id)), &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

// gateCreate is the create's containerd calls: the container (with its
// spec and snapshot key), the task, and its start.
func gateCreate(ctx context.Context, t testing.TB, c *cntr.Client, id string) error {
	spec := specFor(t, id)
	ct, err := c.NewContainer(ctx, id, cntr.WithSpec(spec), cntr.WithRuntime("io.containerd.runc.v2", nil),
		func(_ context.Context, _ *cntr.Client, cc *containers.Container) error {
			cc.Snapshotter, cc.SnapshotKey = "overlayfs", id
			return nil
		},
		cntr.WithContainerLabels(map[string]string{"aerolvm.managed": "true", "aerolvm.sandbox_id": id}))
	if err != nil {
		return fmt.Errorf("container: %w", err)
	}
	task, err := ct.NewTask(ctx, cio.NullIO)
	if err != nil {
		return fmt.Errorf("task: %w", err)
	}
	return task.Start(ctx)
}

// burstOf runs n at once and times each from the moment all were let go.
func burstOf(n int, one func(i int) error) ([]time.Duration, error) {
	out, errs := make([]time.Duration, n), make([]error, n)
	var wg, ready sync.WaitGroup
	start := make(chan struct{})
	var t0 time.Time
	for i := range n {
		wg.Add(1)
		ready.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			errs[i] = one(i)
			out[i] = time.Since(t0)
		}()
	}
	ready.Wait()
	t0 = time.Now()
	close(start)
	wg.Wait()
	return out, errors.Join(errs...)
}

func percentileOf(d []time.Duration, p float64) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s[int(float64(len(s)-1)*p)]
}

// gateBench is the stand-in containerd on a socket, and two clients of
// it: one direct, one through the helper's socket and the gate.
type gateBench struct {
	fake          *fakeContainerd
	direct, gated *cntr.Client
	refused       func() []Refusal
}

func newGateBench(b testing.TB, work time.Duration) *gateBench {
	b.Helper()
	dir, err := os.MkdirTemp("", "gb")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = os.RemoveAll(dir) })
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		b.Fatal(err)
	}
	r := &rig{fake: &fakeContainerd{}, stdio: &acceptStdio{}, binds: &acceptBinds{}, reads: &acceptReads{}}
	statefulContainerd(r)
	upSock := filepath.Join(dir, "ctd.sock")
	ln, err := net.Listen("unix", upSock)
	if err != nil {
		b.Fatal(err)
	}
	up := grpc.NewServer(grpc.UnknownServiceHandler(r.fake.handle), grpc.ChainStreamInterceptor(
		func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			if info.FullMethod == "/containerd.services.tasks.v1.Tasks/Create" && work > 0 {
				time.Sleep(work)
			}
			return h(srv, ss)
		}))
	go func() { _ = up.Serve(ln) }()
	b.Cleanup(up.Stop)
	upConn, err := grpc.NewClient("unix://"+upSock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = upConn.Close() })
	g, err := New(Config{Policy: testPolicy(), Upstream: upConn, Stdio: r.stdio, Binds: r.binds, Reads: r.reads,
		OnRefusal: func(_ context.Context, ref Refusal) {
			r.mu.Lock()
			r.refusals = append(r.refusals, ref)
			r.mu.Unlock()
		}})
	if err != nil {
		b.Fatal(err)
	}
	sock := filepath.Join(dir, "sock", "root.sock")
	srv, err := rootd.New(helperConfig(rootd.Config{Socket: sock, SocketGID: os.Getgid(), AgentUID: uint32(os.Getuid()), Policy: testPolicy()}, dir),
		rootd.Options{Containerd: g.Handle, ServerOptions: g.ServerOptions(), Peer: egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, "")}, nil)
	if err != nil {
		b.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	b.Cleanup(func() { srv.Shutdown(context.Background()) })
	agent := rootclient.New(rootclient.Config{Socket: sock, Timeout: 30 * time.Second, HelperUID: uint32(os.Getuid())})
	b.Cleanup(func() { _ = agent.Close() })
	gated, err := cntr.New(sock, append(agent.ContainerdOptions(), cntr.WithDefaultNamespace(testNS))...)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = gated.Close() })
	direct, err := cntr.New(upSock, cntr.WithDefaultNamespace(testNS))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = direct.Close() })
	return &gateBench{fake: r.fake, direct: direct, gated: gated, refused: r.refused}
}

// BenchmarkGateCreate100: 100 creates at once, each making the create's
// containerd writes (container, task, start), directly (single mode) and
// through the helper's socket and gate (split mode). The order turns each
// round. Reports p50 and p99 of each, and the gate's calls per create.
//
//	go test -run '^$' -bench GateCreate100 -benchtime 10x ./internal/rootd/gate/
func BenchmarkGateCreate100(b *testing.B) {
	const n = 100
	for _, work := range []time.Duration{0, 20 * time.Millisecond} {
		b.Run(fmt.Sprintf("work=%v", work), func(b *testing.B) {
			gb := newGateBench(b, work)
			ctx := namespaces.WithNamespace(context.Background(), testNS)
			var direct, gated []time.Duration
			calls, creates := 0, 0
			for i := 0; i < b.N; i++ {
				for m := range 2 {
					useGate := (i+m)%2 == 1
					c := gb.direct
					if useGate {
						c = gb.gated
					}
					before := len(gb.fake.seen())
					d, err := burstOf(n, func(j int) error { return gateCreate(ctx, b, c, fmt.Sprintf("b%d-%d-%d", i, m, j)) })
					if err != nil {
						b.Fatal(err)
					}
					if useGate {
						gated = append(gated, d...)
						calls += len(gb.fake.seen()) - before
						creates += n
					} else {
						direct = append(direct, d...)
					}
				}
			}
			if refs := gb.refused(); len(refs) != 0 {
				b.Fatalf("the gate refused the creates: %+v", refs[0])
			}
			b.ReportMetric(float64(percentileOf(direct, 0.5).Microseconds()), "single-p50-us")
			b.ReportMetric(float64(percentileOf(direct, 0.99).Microseconds()), "single-p99-us")
			b.ReportMetric(float64(percentileOf(gated, 0.5).Microseconds()), "split-p50-us")
			b.ReportMetric(float64(percentileOf(gated, 0.99).Microseconds()), "split-p99-us")
			b.ReportMetric(float64(calls)/float64(creates), "calls/create")
		})
	}
}

// TestGateCreateBurst keeps the benchmark's burst working under go test.
func TestGateCreateBurst(t *testing.T) {
	gb := newGateBench(t, 0)
	ctx := namespaces.WithNamespace(context.Background(), testNS)
	if _, err := burstOf(20, func(j int) error { return gateCreate(ctx, t, gb.gated, fmt.Sprintf("t-%d", j)) }); err != nil {
		t.Fatal(err)
	}
	if refs := gb.refused(); len(refs) != 0 {
		t.Fatalf("refused: %+v", refs)
	}
}

// BenchmarkGateCreateOne is one create's containerd calls with nothing
// else running, directly and through the gate: the hop's cost per create.
func BenchmarkGateCreateOne(b *testing.B) {
	gb := newGateBench(b, 0)
	ctx := namespaces.WithNamespace(context.Background(), testNS)
	for _, mode := range []string{"single", "split"} {
		c := gb.direct
		if mode == "split" {
			c = gb.gated
		}
		b.Run(mode, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if err := gateCreate(ctx, b, c, fmt.Sprintf("o-%s-%d", mode, i)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
