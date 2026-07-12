package daemon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aerol-ai/microvm/internal/config"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/internal/service"
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
func wireContainerEngine(ctx context.Context, cfg config.Config, logger *slog.Logger, svc *service.Service, dockerClient *docker.Client, dockerRules *netrules.Manager) error {
	_ = ctx
	_ = dockerRules // docker driver keeps its own DOCKER-USER manager (daemon.go)
	if cfg.ContainerEngine != models.ContainerEngineContainerd {
		svc.SetEventsSource(dockerClient)
		return nil
	}
	// Dedicated AEROLVM-USER manager for the containerd driver so its rules
	// never collide with the docker driver's DOCKER-USER rules on a
	// mixed-engine (migrating) host. NOTE: creating the AEROLVM-USER chain and
	// its FORWARD jump (EnsureChain) plus CNI-backed container networking are
	// Phase 2 (plans/containerd-engine.md §4, §6). Until Phase 2 lands the
	// containerd Create path has no container IP, so no per-IP rule is applied
	// through this manager yet.
	ctdRules, err := netrules.NewWithOptions(cfg.EnableNetworkRules, cfg.NetrulesBackend, netrules.ChainAerolvmUser)
	if err != nil {
		return fmt.Errorf("create containerd netrules manager: %w", err)
	}
	driver := cntr.New(cntr.FromDaemonConfig(cfg), ctdRules, logger)
	svc.SetContainerdRuntime(driver)
	if dockerClient != nil {
		svc.SetEventsSource(newMultiEventsSource(dockerClient, driver))
	} else {
		svc.SetEventsSource(driver)
	}
	logger.Info("containerd engine enabled",
		"socket", cfg.ContainerdSocket,
		"namespace", cfg.ContainerdNamespace,
		"netrules_chain", netrules.ChainAerolvmUser,
	)
	return nil
}

// multiEventsSource fans in dockerd and containerd event streams during
// migration when both engines may own live sandboxes on one host.
type multiEventsSource struct {
	sources []docker.EventsSource
}

func newMultiEventsSource(sources ...docker.EventsSource) docker.EventsSource {
	out := make([]docker.EventsSource, 0, len(sources))
	for _, s := range sources {
		if s != nil {
			out = append(out, s)
		}
	}
	return &multiEventsSource{sources: out}
}

func (m *multiEventsSource) StreamEvents(ctx context.Context, out chan<- docker.DockerEvent) error {
	if len(m.sources) == 0 {
		<-ctx.Done()
		return ctx.Err()
	}
	if len(m.sources) == 1 {
		return m.sources[0].StreamEvents(ctx, out)
	}
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, len(m.sources))
	for _, src := range m.sources {
		src := src
		go func() {
			buf := make(chan docker.DockerEvent, 32)
			// Drain buf -> out in a SEPARATE goroutine that runs concurrently
			// with the stream. StreamEvents blocks for the source's lifetime,
			// so draining only after it returns (the original bug) forwarded
			// nothing and deadlocked once the 32-slot buffer filled.
			drained := make(chan struct{})
			go func() {
				defer close(drained)
				for ev := range buf {
					select {
					case out <- ev:
					case <-childCtx.Done():
						return
					}
				}
			}()
			err := src.StreamEvents(childCtx, buf)
			close(buf) // StreamEvents is the only writer; safe once it returns
			<-drained
			done <- err
		}()
	}
	var firstErr error
	for range m.sources {
		if err := <-done; err != nil && firstErr == nil {
			firstErr = err
			cancel() // one source failing tears the rest down
		}
	}
	return firstErr
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
