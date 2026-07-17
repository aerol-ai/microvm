package isolate

import (
	"context"
	"path/filepath"

	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
)

// workerdSupervisor is the production HostSupervisor: it realizes a group's
// JailSpec by starting a pkg/isolate.Host (the workerd process + controller +
// bundle-server). It lives in the driver package so pkg/isolate need not know
// the driver's seam.
//
// Phase 2 wires the run directory and workerd binary; the JailSpec's
// chroot/cgroup/seccomp realization (jail.go) is applied by pkg/isolate when
// the jail lands (the spec is already validated here). The host's per-group run
// dir is <RunDir>/<groupKey> so two groups never share sockets.
type workerdSupervisor struct {
	workerdPath string
	runDir      string
}

// NewHostSupervisor builds the production supervisor over the isolate config.
func NewHostSupervisor(cfg Config) HostSupervisor {
	return &workerdSupervisor{
		workerdPath: cfg.WorkerdPath,
		runDir:      cfg.RunDir,
	}
}

func (s *workerdSupervisor) SpawnGroup(ctx context.Context, spec JailSpec) (GroupHost, error) {
	host, err := pkgisolate.NewHost(pkgisolate.HostConfig{
		WorkerdPath: s.workerdPath,
		GroupKey:    spec.GroupKey,
		RunDir:      filepath.Join(s.runDir, spec.GroupKey),
	})
	if err != nil {
		return nil, err
	}
	if err := host.Start(ctx); err != nil {
		return nil, err
	}
	return host, nil
}
