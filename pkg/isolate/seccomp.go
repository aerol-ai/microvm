package isolate

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Classic-BPF seccomp filter construction. The program is built in Go from
// the driver's allowlist and installed by the shim (shim_linux.go) via
// seccomp(2) before execve, so nothing here is Linux-specific: the encoding
// is the kernel's ABI and the tests run on every platform. The instruction
// and return constants are spelled out rather than imported so the file
// compiles everywhere the daemon builds.

const (
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfALU = 0x04
	bpfAND = 0x50
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfJGE = 0x30
	bpfK   = 0x00
	bpfRET = 0x06

	seccompRetKillProcess = 0x80000000
	seccompRetLog         = 0x7ffc0000
	seccompRetAllow       = 0x7fff0000

	auditArchX86_64  = 0xc000003e
	auditArchAARCH64 = 0xc00000b7
	// x32SyscallBit marks the x32 ABI on x86-64: same arch value, different
	// syscall numbers. A filter that only checks arch would let an x32 call
	// through by number collision, so those are refused outright.
	x32SyscallBit = 0x40000000

	// seccompDataNR / seccompDataArch / seccompDataArgs are the offsets in
	// struct seccomp_data the filter reads.
	seccompDataNR   = 0
	seccompDataArch = 4
	seccompDataArgs = 16
	// bpfMaxInsns is the kernel's program-length ceiling.
	bpfMaxInsns = 4096
)

// bpfInsn is struct sock_filter.
type bpfInsn struct {
	Code uint16 `json:"c"`
	Jt   uint8  `json:"t"`
	Jf   uint8  `json:"f"`
	K    uint32 `json:"k"`
}

func bpfStmt(code uint16, k uint32) bpfInsn { return bpfInsn{Code: code, K: k} }
func bpfJump(code uint16, k uint32, jt, jf uint8) bpfInsn {
	return bpfInsn{Code: code, Jt: jt, Jf: jf, K: k}
}

// seccompDefaultAction maps a mode onto the filter's fall-through result.
func seccompDefaultAction(mode string) (uint32, error) {
	switch mode {
	case SeccompEnforce, "":
		return seccompRetKillProcess, nil
	case SeccompAudit:
		return seccompRetLog, nil
	}
	return 0, fmt.Errorf("isolate jail: unknown seccomp mode %q", mode)
}

// resolveSyscalls maps names onto numbers for one architecture. Names the
// architecture does not have are returned separately: they cannot be called
// there, so skipping them narrows nothing, but the caller may want to log
// them once so a typo in the allowlist is not silently ignored.
func resolveSyscalls(names []string, table map[string]int) (nrs []int, unknown []string) {
	seen := map[int]struct{}{}
	for _, name := range names {
		nr, ok := table[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		if _, dup := seen[nr]; dup {
			continue
		}
		seen[nr] = struct{}{}
		nrs = append(nrs, nr)
	}
	sort.Ints(nrs)
	return nrs, unknown
}

// buildSeccompProgram assembles the filter:
//
//	if arch != want            → kill (never LOG: a foreign ABI is an escape attempt)
//	if x86-64 and nr has x32 bit → kill
//	for each plain allowed nr  → allow
//	for each arg-ruled nr      → allow unless every mask is set, then default
//	otherwise                  → default (kill in enforce, log in audit)
//
// Plain and arg-ruled syscalls are disjoint: a name with a rule is never also
// unconditionally allowed. The accumulator holds nr throughout; arg checks
// only run once a nr matched and always end in a return, so later
// comparisons still see nr.
func buildSeccompProgram(arch uint32, table map[string]int, allow []string, rules []SeccompArgRule, mode string) ([]bpfInsn, []string, error) {
	def, err := seccompDefaultAction(mode)
	if err != nil {
		return nil, nil, err
	}
	ruled := map[string]SeccompArgRule{}
	for _, r := range rules {
		if len(r.DenyIfAll) == 0 {
			return nil, nil, fmt.Errorf("isolate jail: arg rule for %q has no masks", r.Syscall)
		}
		if len(r.DenyIfAll) > 6 {
			return nil, nil, fmt.Errorf("isolate jail: arg rule for %q has %d masks (max 6)", r.Syscall, len(r.DenyIfAll))
		}
		for _, m := range r.DenyIfAll {
			if m.Arg < 0 || m.Arg > 5 || m.Mask == 0 {
				return nil, nil, fmt.Errorf("isolate jail: arg rule for %q: invalid mask %+v", r.Syscall, m)
			}
		}
		if _, dup := ruled[r.Syscall]; dup {
			return nil, nil, fmt.Errorf("isolate jail: duplicate arg rule for %q", r.Syscall)
		}
		ruled[r.Syscall] = r
	}
	var plain []string
	for _, name := range allow {
		if _, isRuled := ruled[name]; !isRuled {
			plain = append(plain, name)
		}
	}
	nrs, unknown := resolveSyscalls(plain, table)

	prog := []bpfInsn{
		bpfStmt(bpfLD|bpfW|bpfABS, seccompDataArch),
		bpfJump(bpfJMP|bpfJEQ|bpfK, arch, 1, 0),
		bpfStmt(bpfRET|bpfK, seccompRetKillProcess),
		bpfStmt(bpfLD|bpfW|bpfABS, seccompDataNR),
	}
	if arch == auditArchX86_64 {
		prog = append(prog,
			bpfJump(bpfJMP|bpfJGE|bpfK, x32SyscallBit, 0, 1),
			bpfStmt(bpfRET|bpfK, seccompRetKillProcess),
		)
	}
	for _, nr := range nrs {
		prog = append(prog,
			bpfJump(bpfJMP|bpfJEQ|bpfK, uint32(nr), 0, 1),
			bpfStmt(bpfRET|bpfK, seccompRetAllow),
		)
	}
	// Deterministic order for the rules too.
	ruleNames := make([]string, 0, len(ruled))
	for name := range ruled {
		ruleNames = append(ruleNames, name)
	}
	sort.Strings(ruleNames)
	for _, name := range ruleNames {
		nr, ok := table[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		r := ruled[name]
		k := len(r.DenyIfAll)
		// Block: jeq nr | k × (ld arg; and mask; jeq 0 → allow) | ret default | ret allow
		prog = append(prog, bpfJump(bpfJMP|bpfJEQ|bpfK, uint32(nr), 0, uint8(3*k+2)))
		for j, m := range r.DenyIfAll {
			jt := uint8(3*k - 3*j - 2)
			prog = append(prog,
				bpfStmt(bpfLD|bpfW|bpfABS, uint32(seccompDataArgs+8*m.Arg)),
				bpfStmt(bpfALU|bpfAND|bpfK, m.Mask),
				bpfJump(bpfJMP|bpfJEQ|bpfK, 0, jt, 0),
			)
		}
		prog = append(prog,
			bpfStmt(bpfRET|bpfK, def),
			bpfStmt(bpfRET|bpfK, seccompRetAllow),
		)
	}
	prog = append(prog, bpfStmt(bpfRET|bpfK, def))
	if len(prog) > bpfMaxInsns {
		return nil, nil, fmt.Errorf("isolate jail: seccomp program has %d instructions (max %d)", len(prog), bpfMaxInsns)
	}
	sort.Strings(unknown)
	return prog, unknown, nil
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
	if len(s.Seccomp) > bpfMaxInsns {
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
