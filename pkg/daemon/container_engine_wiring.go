package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/cni"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

func netrulesUserChain(cfg config.Config) string {
	if cfg.ContainerEngine == models.ContainerEngineContainerd {
		return netrules.ChainAerolvmUser
	}
	return netrules.ChainDockerUser
}

// wireContainerEngine registers the containerd driver and event source when
// SB_CONTAINER_ENGINE=containerd. On the docker default path it only wires the
// events source to the docker client, leaving behavior byte-identical.
func wireContainerEngine(ctx context.Context, cfg config.Config, logger *slog.Logger, svc *service.Service, st *store.Store, dockerClient *docker.Client, dockerRules *netrules.Manager, admitter *capacity.Admitter) (*containerdEngineWiring, error) {
	_ = ctx
	_ = dockerRules // docker driver keeps its own DOCKER-USER manager (daemon.go)
	if cfg.ContainerEngine != models.ContainerEngineContainerd {
		svc.SetEventsSource(dockerClient)
		return nil, nil
	}
	// A configured cgroup parent must be able to hold sandboxes with their
	// limits before any is created; refuse to start otherwise (plan C7).
	if cfg.ContainerdCgroupParent != "" {
		if err := cntr.CheckCgroupParent(cntr.CgroupRoot, cfg.ContainerdCgroupParent); err != nil {
			return nil, fmt.Errorf("containerd cgroup parent: %w", err)
		}
	}
	// Dedicated AEROLVM-USER manager for the containerd driver so its rules
	// never collide with the docker driver's DOCKER-USER rules on a
	// mixed-engine (migrating) host. EnsureChain bootstraps the chain and
	// FORWARD jump; CNI-backed container networking is Phase 2 (§4).
	ctdRules, err := netrules.NewWithOptions(cfg.EnableNetworkRules, cfg.NetrulesBackend, netrules.ChainAerolvmUser)
	if err != nil {
		return nil, fmt.Errorf("create containerd netrules manager: %w", err)
	}
	// dockerd sets FORWARD policy to DROP and only ACCEPTs docker0; our aerolvm0
	// bridge needs its own FORWARD ACCEPTs or all sandbox egress + peer traffic
	// is dropped. EnsureChain installs them (below per-IP DROPs) for this subnet.
	ctdRules.SetBridgeSubnet(cni.DefaultBridgeSubnet)
	if err := ctdRules.EnsureChain(); err != nil {
		return nil, fmt.Errorf("bootstrap AEROLVM-USER chain: %w", err)
	}
	prepareBlockSets(ctdRules, netrules.ChainAerolvmUser, logger)
	reassertStop := startChainReassert(ctx, ctdRules, logger)
	driver := cntr.New(cntr.FromDaemonConfig(cfg), ctdRules, logger)
	// Same cluster-PAT pull credential the docker client got in Run (see
	// configureAOCRPullAuth in daemon.go). Installed here, before the warm pool
	// starts refilling, because ensureImage reads it without a lock.
	configureAOCRPullAuth(logger, cfg, models.ContainerEngineContainerd, driver)
	netnsPool, err := wireContainerdNativeNetnsPool(ctx, cfg, logger, st, driver)
	if err != nil {
		return nil, err
	}
	warmPool := wireContainerdWarmPool(ctx, cfg, logger, driver, admitter)
	svc.SetContainerdRuntime(driver)
	if dockerClient != nil {
		svc.SetEventsSource(newMultiEventsSource(logger, dockerClient, driver))
	} else {
		svc.SetEventsSource(driver)
	}
	logger.Info("containerd engine enabled",
		"socket", cfg.ContainerdSocket,
		"namespace", cfg.ContainerdNamespace,
		"netrules_chain", netrules.ChainAerolvmUser,
	)
	cntr.PublishEngineTag(models.ContainerEngineContainerd)
	return &containerdEngineWiring{netns: netnsPool, warm: warmPool, driver: driver, logger: logger, stopReassert: reassertStop}, nil
}

// chainReassertInterval is the AEROLVM-USER re-assert cadence. Tests shrink it
// so the ticker body is exercised without a 30s wait.
var chainReassertInterval = 30 * time.Second

// startChainReassert periodically re-asserts the AEROLVM-USER chain + FORWARD
// jump. A dockerd restart on a coexistence host can flush/reorder FORWARD and
// drop our jump; re-assertion (idempotent) restores it without waiting for a
// sandboxd restart (plan §4 item #5). Returns a cancel func the wiring calls on
// shutdown.
func startChainReassert(ctx context.Context, rules *netrules.Manager, logger *slog.Logger) func() {
	if rules == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	interval := chainReassertInterval
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := rules.ReassertChain(); err != nil {
					logger.Warn("re-assert AEROLVM-USER chain failed", "error", err)
				}
				reassertBlockSets(rules, logger)
			}
		}
	}()
	return cancel
}

// multiEventsSource fans in dockerd and containerd event streams during
// migration when both engines may own live sandboxes on one host.
//
// Each source streams on its own: one that ends is retried on its own
// backoff, and the others keep flowing. It used to be all or nothing (one
// source's error tore the rest down), and on a containerd-engine host where
// dockerd is stopped, or was never installed (the Kubernetes worker pod), the
// Docker subscribe fails at once on every try, so containerd's task-exit and
// OOM events never reached the service: a sandbox the kernel killed stayed
// "started" (Kubernetes Phase 0, finding F12). Events a source misses while
// it is down are reconcile's to find, as after any stream gap.
type multiEventsSource struct {
	sources []docker.EventsSource
	logger  *slog.Logger
}

// eventSourceRetryInitial and eventSourceRetryMax bound how often a failing
// source is subscribed again. Variables so tests can shorten them.
var (
	eventSourceRetryInitial = time.Second
	eventSourceRetryMax     = 30 * time.Second
)

func newMultiEventsSource(logger *slog.Logger, sources ...docker.EventsSource) docker.EventsSource {
	out := make([]docker.EventsSource, 0, len(sources))
	for _, s := range sources {
		if s != nil {
			out = append(out, s)
		}
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &multiEventsSource{sources: out, logger: logger}
}

// StreamEvents returns only when ctx ends (with one source, it is that
// source's own stream, retried by the service's event monitor).
func (m *multiEventsSource) StreamEvents(ctx context.Context, out chan<- docker.DockerEvent) error {
	if len(m.sources) == 0 {
		<-ctx.Done()
		return ctx.Err()
	}
	if len(m.sources) == 1 {
		return m.sources[0].StreamEvents(ctx, out)
	}
	var wg sync.WaitGroup
	for _, src := range m.sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.keepStreaming(ctx, src, out)
		}()
	}
	wg.Wait()
	return ctx.Err()
}

// keepStreaming runs one source until ctx ends, subscribing again after
// each end with a doubling wait, reset once a stream has stayed up longer
// than the longest wait.
func (m *multiEventsSource) keepStreaming(ctx context.Context, src docker.EventsSource, out chan<- docker.DockerEvent) {
	wait := eventSourceRetryInitial
	for {
		started := time.Now()
		err := forwardEvents(ctx, src, out)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > eventSourceRetryMax {
			wait = eventSourceRetryInitial
		}
		m.logger.Warn("event source ended; retrying it alone while the others keep streaming",
			"source", fmt.Sprintf("%T", src), "error", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, eventSourceRetryMax)
	}
}

// forwardEvents runs one subscription of src, copying its events to out.
// The copy runs beside the stream, not after it: StreamEvents blocks for the
// stream's lifetime, so copying only after it returned forwarded nothing and
// deadlocked once the buffer filled.
func forwardEvents(ctx context.Context, src docker.EventsSource, out chan<- docker.DockerEvent) error {
	buf := make(chan docker.DockerEvent, 32)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for ev := range buf {
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	err := src.StreamEvents(ctx, buf)
	close(buf) // StreamEvents is the only writer; safe once it returns
	<-drained
	return err
}

func (m *multiEventsSource) ContainerPID(ctx context.Context, containerRef string) (int, error) {
	var firstErr error
	for _, src := range m.sources {
		pid, err := src.ContainerPID(ctx, containerRef)
		if err == nil && pid > 0 {
			return pid, nil
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// No source owns this container ref (a stopped/foreign container). Return
	// the first real error if any source errored, else (0, nil) meaning "not
	// running here" — never re-invoke a source (the old code double-called
	// sources[0], doubling a failed RPC).
	return 0, firstErr
}
