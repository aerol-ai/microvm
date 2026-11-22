package isolate

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
)

// The workerd jail (plans/isolate-runtime.md §2.1, Phase-1 deliverable).
//
// Isolates share an OS process, so the process boundary between isolate
// groups is the REQUIRED cross-tenant boundary — upstream workerd itself
// tells self-hosters to wrap possibly-malicious code in "an appropriate
// secure sandbox". This file is the jail's specification: given a group key
// and resource caps, it computes the chroot, cgroup, privilege-drop, and
// seccomp policy a group process must run under. Realization (clone/chroot/
// setuid/seccomp(2) on Linux) lands with the group spawner in Phase 2; the
// spec lives here so its invariants are regression-tested from Phase 1 and
// the spawner can only ever consume a validated spec.
//
// The chroot + cgroups + drop-priv shape reuses the Firecracker jailer's
// pattern. The new work — and the reason this is budgeted as its own
// subproject — is the seccomp allowlist for a JIT-heavy V8 process: V8
// rewrites page protections (W^X flips via mprotect/pkey_mprotect), backs
// code spaces with memfd, and spawns worker threads, none of which a
// conventional network-daemon allowlist permits. --jitless (SB_ISOLATE_JITLESS)
// removes that whole group at a large throughput cost — the honest
// alternative for the per-sandbox paranoid tier if the JIT allowlist proves
// too broad to mean anything.

// JailSpec describes the OS confinement for one workerd group process. Build
// one with BuildJailSpec; a hand-rolled spec must pass Validate before use.
type JailSpec struct {
	// GroupKey is the sanitized isolate-group key (per-tenant granularity:
	// the authorized tenant id; per-sandbox granularity: the sandbox id;
	// empty tenant falls back to DefaultGroupKey).
	GroupKey string
	// ChrootDir is the group's private root: <JailChrootBase>/<GroupKey>.
	ChrootDir string
	// CgroupName is the per-group cgroup that enforces the GROUP-level
	// resource caps (§2.1): OSS workerd has no per-isolate CPU enforcement,
	// so the enforced blast radius is the group.
	CgroupName string
	// UID / GID are the unprivileged identity the process drops to.
	UID int
	GID int
	// CPUQuota / MemoryLimitMB are the group cgroup caps. Zero = unlimited
	// on that axis (the cgroup controller is left unset).
	CPUQuota      float64
	MemoryLimitMB int
	// PidsMax bounds pids.max on the group cgroup (fork/thread bomb
	// containment). Zero = unlimited; enterprise mode refuses that.
	PidsMax int
	// Jitless selects the reduced seccomp profile (and --jitless on the V8
	// command line when the spawner realizes the spec).
	Jitless bool
	// CgroupRoot is the parent cgroup; empty means pkg/isolate's default.
	CgroupRoot string
	// SeccompMode is enforce (default) | audit | off.
	SeccompMode string
	// ShimPath is the daemon binary re-exec'd as the jail shim.
	ShimPath string
}

// DefaultGroupKey is the isolate-group key for the null tenant: creates whose
// group key fell back to an unscoped (operator/PAT) identity share one
// default group, which is the single-tenant self-hoster's zero-config path.
const DefaultGroupKey = "default"

// groupKeyPattern is deliberately strict: the key becomes a chroot directory
// name and a cgroup name, so anything path-ambiguous (separators, dots-only
// segments, leading dashes) is rejected rather than escaped.
var groupKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// SanitizeGroupKey validates a group key for use in host paths and cgroup
// names. Empty maps to DefaultGroupKey; anything else must match
// groupKeyPattern exactly — no normalization, because two keys that
// normalize to the same directory would silently merge two tenants into one
// process (§2.1's forced-co-residency attack, at the filesystem layer).
func SanitizeGroupKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return DefaultGroupKey, nil
	}
	if !groupKeyPattern.MatchString(key) {
		return "", fmt.Errorf("isolate group key %q: must match %s", key, groupKeyPattern.String())
	}
	if strings.Contains(key, "..") {
		return "", fmt.Errorf("isolate group key %q: must not contain '..'", key)
	}
	return key, nil
}

// BuildJailSpec computes the jail for one group under the driver config.
// cpu / memoryMB are the GROUP-level caps (map CreateSandboxRequest.CPU /
// MemoryMB onto them at create time — Phase 4 owns the exact mapping).
func BuildJailSpec(cfg Config, groupKey string, cpu float64, memoryMB int) (JailSpec, error) {
	key, err := SanitizeGroupKey(groupKey)
	if err != nil {
		return JailSpec{}, err
	}
	spec := JailSpec{
		GroupKey:      key,
		ChrootDir:     filepath.Join(cfg.JailChrootBase, key),
		CgroupName:    "aerolvm-isolate-" + key,
		UID:           cfg.JailUID,
		GID:           cfg.JailGID,
		CPUQuota:      cpu,
		MemoryLimitMB: memoryMB,
		PidsMax:       cfg.JailPidsMax,
		Jitless:       cfg.Jitless,
		CgroupRoot:    cfg.JailCgroupRoot,
		SeccompMode:   cfg.SeccompMode,
		ShimPath:      cfg.ShimPath,
	}
	if err := spec.Validate(); err != nil {
		return JailSpec{}, err
	}
	return spec, nil
}

// Validate enforces the spec's invariants. It exists separately from
// BuildJailSpec so the spawner can re-assert them at realization time — the
// spec may have crossed a channel or been rehydrated from the store by then.
func (s JailSpec) Validate() error {
	if _, err := SanitizeGroupKey(s.GroupKey); err != nil {
		return err
	}
	if s.GroupKey == "" {
		return fmt.Errorf("isolate jail: empty group key")
	}
	if s.ChrootDir == "" || !filepath.IsAbs(s.ChrootDir) {
		return fmt.Errorf("isolate jail: chroot dir %q must be absolute", s.ChrootDir)
	}
	// A jailed-but-root workerd defeats the point of the jail.
	if s.UID <= 0 || s.GID <= 0 {
		return fmt.Errorf("isolate jail: uid/gid must be non-root (> 0), got %d/%d", s.UID, s.GID)
	}
	if s.CPUQuota < 0 {
		return fmt.Errorf("isolate jail: cpu quota must be >= 0, got %f", s.CPUQuota)
	}
	if s.MemoryLimitMB < 0 {
		return fmt.Errorf("isolate jail: memory limit must be >= 0, got %d", s.MemoryLimitMB)
	}
	if s.PidsMax < 0 {
		return fmt.Errorf("isolate jail: pids max must be >= 0, got %d", s.PidsMax)
	}
	return nil
}

// The jail's seccomp profile (the allowlist, the JIT extension, the
// deny-regardless list and the jitless argument rules) lives in pkg/isolate
// (seccomp_profile.go), so the root helper builds the same filter for a
// group it starts in privilege mode split. These wrappers keep the driver's
// names.

// Argument masks the jitless rules test (Linux ABI values, identical on
// x86-64 and arm64).
const (
	protExec     = pkgisolate.SeccompProtExec
	mapAnonymous = pkgisolate.SeccompMapAnonymous
)

// SeccompArgRules returns the argument-level narrowing for a profile
// (pkgisolate.SeccompArgRules).
func SeccompArgRules(jitless bool) []pkgisolate.SeccompArgRule {
	return pkgisolate.SeccompArgRules(jitless)
}

// SeccompAllowlist returns the syscall names a group process may make
// (pkgisolate.SeccompAllowlist).
func SeccompAllowlist(jitless bool) []string { return pkgisolate.SeccompAllowlist(jitless) }

// SeccompNeverAllow returns the deny-regardless list
// (pkgisolate.SeccompNeverAllow).
func SeccompNeverAllow() []string { return pkgisolate.SeccompNeverAllow() }

// SeccompAllowlistFor returns the profile matching the spec's Jitless flag.
func (s JailSpec) SeccompAllowlistFor() []string {
	return SeccompAllowlist(s.Jitless)
}

// SeccompArgRulesFor returns the argument rules matching the spec's Jitless flag.
func (s JailSpec) SeccompArgRulesFor() []pkgisolate.SeccompArgRule {
	return SeccompArgRules(s.Jitless)
}
