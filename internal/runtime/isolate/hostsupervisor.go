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
type workerdSupervisor struct {
	workerdPath    string
	runDir         string
	useJail        bool
	egressPoolSize int
	egressObserver pkgisolate.EgressObserver
}

// NewHostSupervisor builds the production supervisor over the isolate config.
func NewHostSupervisor(cfg Config) HostSupervisor {
	return &workerdSupervisor{
		workerdPath:    cfg.WorkerdPath,
		runDir:         cfg.RunDir,
		useJail:        cfg.UseJail,
		egressPoolSize: cfg.EgressPoolSize,
	}
}

// SetEgressObserver installs host-mediated egress attribution on every group
// host this supervisor spawns (including warm-pool blanks).
func (s *workerdSupervisor) SetEgressObserver(obs pkgisolate.EgressObserver) {
	if s == nil {
		return
	}
	s.egressObserver = obs
}

func (s *workerdSupervisor) SpawnGroup(ctx context.Context, spec JailSpec) (GroupHost, error) {
	host, err := pkgisolate.NewHost(pkgisolate.HostConfig{
		WorkerdPath:    s.workerdPath,
		GroupKey:       spec.GroupKey,
		RunDir:         filepath.Join(s.runDir, spec.GroupKey),
		EgressPoolSize: s.egressPoolSize,
		// When UseJail is set, the host MUST realize this spec or fail closed.
		Jail: pkgisolate.JailConfig{
			Require:       s.useJail,
			ChrootDir:     spec.ChrootDir,
			UID:           spec.UID,
			GID:           spec.GID,
			CgroupName:    spec.CgroupName,
			MemoryLimitMB: spec.MemoryLimitMB,
			Jitless:       spec.Jitless,
		},
	})
	if err != nil {
		return nil, err
	}
	if s.egressObserver != nil {
		host.SetEgressObserver(s.egressObserver)
	}
	if err := host.Start(ctx); err != nil {
		return nil, err
	}
	return &hostAdapter{Host: host}, nil
}

// hostAdapter bridges pkg/isolate.Host onto the driver's GroupHost +
// EgressPolicySetter seams (the policy struct lives in both packages to avoid
// an import cycle).
type hostAdapter struct {
	*pkgisolate.Host
}

func (a *hostAdapter) SetEgressPolicy(id string, p EgressPolicy) {
	a.Host.SetEgressPolicy(id, pkgisolate.EgressPolicy{
		BlockAll: p.BlockAll,
		Allow:    p.Allow,
		Deny:     p.Deny,
	})
}
