package isolate

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/hostproc"
)

// The jail's seccomp filter is built by the shared builder in pkg/hostproc
// (the WASM workers use the same one) from the driver's allowlist, and
// installed by the shim (shim_linux.go) before execve. These names keep the
// jail's own vocabulary: modes, and the filter as the shim spec carries it.

// bpfInsn is struct sock_filter as the shim spec carries it.
type bpfInsn = hostproc.SockFilter

// SeccompArgMask and SeccompArgRule narrow a call by argument
// (hostproc.SeccompArgRule); the driver's jitless profile uses them.
type (
	SeccompArgMask = hostproc.SeccompArgMask
	SeccompArgRule = hostproc.SeccompArgRule
)

// seccompDefaultAction maps a mode onto the filter's fall-through result.
func seccompDefaultAction(mode string) (uint32, error) {
	switch mode {
	case SeccompEnforce, "":
		return hostproc.SeccompRetKillProcess, nil
	case SeccompAudit:
		return hostproc.SeccompRetLog, nil
	}
	return 0, fmt.Errorf("isolate jail: unknown seccomp mode %q", mode)
}

// buildSeccompProgram assembles the jail's filter: the allowlist and its
// argument rules, and everything else killed (enforce) or logged (audit).
// A foreign architecture is killed in both modes.
func buildSeccompProgram(arch uint32, table map[string]int, allow []string, rules []SeccompArgRule, mode string) ([]bpfInsn, []string, error) {
	def, err := seccompDefaultAction(mode)
	if err != nil {
		return nil, nil, err
	}
	return hostproc.BuildSeccomp(arch, table, hostproc.SeccompPolicy{Allow: allow, Rules: rules, Default: def})
}

// jailShimSpec is what the parent hands the shim (JSON in an environment
// variable): everything the child must do between fork and exec.
type jailShimSpec struct {
	Chroot  string    `json:"chroot"`
	Cwd     string    `json:"cwd"` // inside the chroot
	UID     int       `json:"uid"`
	GID     int       `json:"gid"`
	Argv    []string  `json:"argv"` // inside the chroot
	Env     []string  `json:"env,omitempty"`
	Seccomp []bpfInsn `json:"seccomp,omitempty"` // empty = no filter (SeccompOff)
}

// jailShimSpecEnv carries the spec to the shim.
const jailShimSpecEnv = "SB_ISOLATE_JAIL_SPEC"

// JailShimFlag is the daemon subcommand that runs the shim.
const JailShimFlag = "--isolate-jail-exec"

func (s jailShimSpec) validate() error {
	if s.Chroot == "" || s.Chroot[0] != '/' {
		return errors.New("isolate jail shim: chroot must be absolute")
	}
	if s.Cwd == "" || s.Cwd[0] != '/' {
		return errors.New("isolate jail shim: cwd must be absolute (inside the chroot)")
	}
	if s.UID <= 0 || s.GID <= 0 {
		return fmt.Errorf("isolate jail shim: refusing to run workerd privileged (uid/gid %d/%d)", s.UID, s.GID)
	}
	if len(s.Argv) == 0 || s.Argv[0] == "" || s.Argv[0][0] != '/' {
		return errors.New("isolate jail shim: argv[0] must be an absolute path inside the chroot")
	}
	if len(s.Seccomp) > hostproc.MaxSeccompInsns {
		return fmt.Errorf("isolate jail shim: seccomp program too long (%d)", len(s.Seccomp))
	}
	return nil
}

func encodeJailShimSpec(s jailShimSpec) (string, error) {
	if err := s.validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func decodeJailShimSpec(raw string) (jailShimSpec, error) {
	var s jailShimSpec
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return jailShimSpec{}, fmt.Errorf("isolate jail shim: decode spec: %w", err)
	}
	if err := s.validate(); err != nil {
		return jailShimSpec{}, err
	}
	return s, nil
}
