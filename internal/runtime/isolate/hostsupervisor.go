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
