package isolate

import (
	"context"
	"fmt"
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
	// Unjailed: the group's run dir lives under the daemon's run dir. Jailed:
	// it must be inside the group's chroot (the only writable place the
	// process can reach), and pkg/isolate maps the paths for workerd.
	runDir := filepath.Join(s.runDir, spec.GroupKey)
	if s.useJail {
		if spec.ChrootDir == "" {
			return nil, fmt.Errorf("isolate: jail required but group %q has no chroot dir (spec must come from BuildJailSpec)", spec.GroupKey)
		}
		runDir = filepath.Join(spec.ChrootDir, pkgisolate.JailRunDirName)
	}
	host, err := pkgisolate.NewHost(pkgisolate.HostConfig{
		WorkerdPath:    s.workerdPath,
		GroupKey:       spec.GroupKey,
		RunDir:         runDir,
		EgressPoolSize: s.egressPoolSize,
		// When UseJail is set, the host MUST realize this spec or fail closed.
		Jail: pkgisolate.JailConfig{
			Require:         s.useJail,
			ChrootDir:       spec.ChrootDir,
			UID:             spec.UID,
			GID:             spec.GID,
			CgroupRoot:      spec.CgroupRoot,
			CgroupName:      spec.CgroupName,
			CPUQuota:        spec.CPUQuota,
			MemoryLimitMB:   spec.MemoryLimitMB,
			Jitless:         spec.Jitless,
			SeccompMode:     spec.SeccompMode,
			SeccompAllow:    spec.SeccompAllowlistFor(),
			SeccompArgRules: spec.SeccompArgRulesFor(),
			ShimPath:        spec.ShimPath,
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
