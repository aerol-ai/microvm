package isolate

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/aerol-ai/microvm/pkg/hostproc"
	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
)

// hostRecordDirName holds the group hosts' records under the run dir. The
// leading dot keeps it out of the group-key space: a key starts with a
// letter or digit (SanitizeGroupKey), so no group's run dir is ever it.
const hostRecordDirName = ".hosts"

// hostsCgroupName is the cgroup, under the cgroup v2 root, an unjailed
// workerd runs in. A jailed one has its group's cgroup under JailCgroupRoot.
const hostsCgroupName = "aerolvm-isolate-hosts"

// workerdSupervisor is the production HostSupervisor: it realizes a group's
// JailSpec by starting a pkg/isolate.Host (the workerd process + controller +
// bundle-server). It lives in the driver package so pkg/isolate need not know
// the driver's seam.
type workerdSupervisor struct {
	workerdPath    string
	runDir         string
	useJail        bool
	egressPoolSize int
	jailCgroupRoot string
	jailChrootBase string
	logger         *slog.Logger
	// hostsCgroup is where an unjailed workerd starts, outside sandboxd's
	// unit, so a restart does not stop it (pkg/hostproc).
	hostsCgroup    *hostproc.Cgroup
	egressObserver pkgisolate.EgressObserver
	denialObserver pkgisolate.EgressDenialObserver
	learnObserver  pkgisolate.LearnObserver
}

// SetLearnObserver installs learn-mode recording on every group host.
func (s *workerdSupervisor) SetLearnObserver(obs pkgisolate.LearnObserver) {
	if s == nil {
		return
	}
	s.learnObserver = obs
}

// NewHostSupervisor builds the production supervisor over the isolate config.
func NewHostSupervisor(cfg Config) HostSupervisor {
	return newWorkerdSupervisor(cfg, nil)
}

// NewHostSupervisorWithLogger is NewHostSupervisor with the daemon's logger,
// which the hosts and the boot adoption log through.
func NewHostSupervisorWithLogger(cfg Config, logger *slog.Logger) HostSupervisor {
	return newWorkerdSupervisor(cfg, logger)
}

func newWorkerdSupervisor(cfg Config, logger *slog.Logger) *workerdSupervisor {
	if logger == nil {
		logger = slog.Default()
	}
	return &workerdSupervisor{
		workerdPath:    cfg.WorkerdPath,
		runDir:         cfg.RunDir,
		useJail:        cfg.UseJail,
		egressPoolSize: cfg.EgressPoolSize,
		jailCgroupRoot: cfg.JailCgroupRoot,
		jailChrootBase: cfg.JailChrootBase,
		logger:         logger,
		hostsCgroup:    hostproc.NewCgroup(logger, "", hostsCgroupName, "V8-isolate group hosts"),
	}
}

// recordDir is where running hosts keep their records ("" without a run
// dir: no records, no adoption).
func (s *workerdSupervisor) recordDir() string {
	if s.runDir == "" {
		return ""
	}
	return filepath.Join(s.runDir, hostRecordDirName)
}

// SetEgressObserver installs host-mediated egress attribution on every group
// host this supervisor spawns (including warm-pool blanks).
func (s *workerdSupervisor) SetEgressObserver(obs pkgisolate.EgressObserver) {
	if s == nil {
		return
	}
	s.egressObserver = obs
}

// SetEgressDenialObserver installs denial audit (H5) on every group host
// this supervisor spawns.
func (s *workerdSupervisor) SetEgressDenialObserver(obs pkgisolate.EgressDenialObserver) {
	if s == nil {
		return
	}
	s.denialObserver = obs
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
		Logger:         s.logger,
		RecordDir:      s.recordDir(),
		Cgroup:         s.hostsCgroup,
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
	s.observe(host)
	if err := host.Start(ctx); err != nil {
		return nil, err
	}
	return &hostAdapter{Host: host}, nil
}

// observe installs the supervisor's observers on a host.
func (s *workerdSupervisor) observe(host *pkgisolate.Host) {
	if s.egressObserver != nil {
		host.SetEgressObserver(s.egressObserver)
	}
	if s.denialObserver != nil {
		host.SetEgressDenialObserver(s.denialObserver)
	}
	if s.learnObserver != nil {
		host.SetLearnObserver(s.learnObserver)
	}
}

// Seams for the boot pass, replaced in tests.
var (
	adoptHosts     = pkgisolate.AdoptHosts
	sweepLeftovers = pkgisolate.SweepLeftovers
)

// AdoptGroups takes over the group hosts a previous sandboxd left running
// (their records), then removes every workerd and jail no record kept. Call
// it once at boot, before any group is spawned.
func (s *workerdSupervisor) AdoptGroups(ctx context.Context) []AdoptedGroup {
	adopted := adoptHosts(ctx, pkgisolate.HostConfig{
		WorkerdPath: s.workerdPath,
		Logger:      s.logger,
		RecordDir:   s.recordDir(),
		Cgroup:      s.hostsCgroup,
	})
	out := make([]AdoptedGroup, 0, len(adopted))
	keep := make(map[string]bool, len(adopted))
	keepPIDs := make(map[int]bool, len(adopted))
	for _, a := range adopted {
		s.observe(a.Host)
		keep[a.Host.GroupKey()] = true
		if pid := a.Host.PID(); pid > 0 {
			keepPIDs[pid] = true
		}
		out = append(out, AdoptedGroup{Key: a.Host.GroupKey(), Host: &hostAdapter{Host: a.Host}, Loaded: a.Loaded})
	}
	leftovers := pkgisolate.Leftovers{HostsCgroup: s.hostsCgroup, Keep: keep, KeepPIDs: keepPIDs}
	if s.useJail {
		leftovers.JailCgroupRoot, leftovers.JailChrootBase = s.jailCgroupRoot, s.jailChrootBase
	}
	if killed := sweepLeftovers(leftovers); killed > 0 {
		s.logger.Info("isolate adopt: stopped group hosts no record kept", "processes", killed)
	}
	return out
}

// hostAdapter bridges pkg/isolate.Host onto the driver's GroupHost +
// EgressPolicySetter seams (the policy struct lives in both packages to avoid
// an import cycle).
type hostAdapter struct {
	*pkgisolate.Host
}

func (a *hostAdapter) SetEgressPolicy(id string, p EgressPolicy) {
	a.Host.SetEgressPolicy(id, toHostEgressPolicy(p))
}

func (a *hostAdapter) ClaimEgressPolicy(id string, p EgressPolicy) error {
	return a.Host.ClaimEgressPolicy(id, toHostEgressPolicy(p))
}

func toHostEgressPolicy(p EgressPolicy) pkgisolate.EgressPolicy {
	return pkgisolate.EgressPolicy{
		BlockAll: p.BlockAll,
		Allow:    p.Allow,
		Deny:     p.Deny,
		Learn:    p.Learn,
		Rules:    p.Rules,
		Secrets:  p.Secrets,
	}
}
