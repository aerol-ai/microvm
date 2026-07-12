package daemon

import (
	"context"
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

func wireContainerEngine(ctx context.Context, cfg config.Config, logger *slog.Logger, svc *service.Service, dockerClient *docker.Client, rules *netrules.Manager) error {
	_ = ctx
	if cfg.ContainerEngine != models.ContainerEngineContainerd {
		svc.SetEventsSource(dockerClient)
		return nil
	}
	driver := cntr.New(cntr.FromDaemonConfig(cfg), rules, logger)
	svc.SetContainerdRuntime(driver)
	if dockerClient != nil {
		svc.SetEventsSource(newMultiEventsSource(dockerClient, driver))
	} else {
		svc.SetEventsSource(driver)
	}
	logger.Info("containerd engine enabled",
		"socket", cfg.ContainerdSocket,
		"namespace", cfg.ContainerdNamespace,
		"netrules_chain", netrulesUserChain(cfg),
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
	type result struct {
		err error
	}
	done := make(chan result, len(m.sources))
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, src := range m.sources {
		src := src
		go func() {
			buf := make(chan docker.DockerEvent, 32)
			err := src.StreamEvents(childCtx, buf)
			for ev := range buf {
				select {
				case out <- ev:
				case <-childCtx.Done():
					done <- result{err: childCtx.Err()}
					return
				}
			}
			done <- result{err: err}
		}()
	}
	var firstErr error
	for range m.sources {
		res := <-done
		if res.err != nil && firstErr == nil {
			firstErr = res.err
		}
	}
	return firstErr
}

func (m *multiEventsSource) ContainerPID(ctx context.Context, containerRef string) (int, error) {
	for _, src := range m.sources {
		pid, err := src.ContainerPID(ctx, containerRef)
		if err == nil && pid > 0 {
			return pid, nil
		}
	}
	if len(m.sources) == 0 {
		return 0, nil
	}
	return m.sources[0].ContainerPID(ctx, containerRef)
}
