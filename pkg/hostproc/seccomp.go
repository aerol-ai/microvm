package hostproc

import (
	"errors"
	"fmt"
	"sort"
)

// ErrConfineUnsupported: this host cannot drop a process's privileges or
// filter its syscalls (not Linux).
var ErrConfineUnsupported = errors.New("process confinement is Linux only")

// Classic-BPF seccomp filters for the host processes sandboxd confines: the
// V8-isolate jail shim (pkg/isolate) and the WASM workers (pkg/wasm/worker).
// The program is built in Go from a policy and installed by the process
// itself (InstallSeccomp), so nothing here is Linux-specific: the encoding
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

	// x32SyscallBit marks the x32 ABI on x86-64: same arch value, different
	// syscall numbers. A filter that only checks arch would let an x32 call
	// through by number collision, so those are refused outright.
	x32SyscallBit = 0x40000000

	// seccompDataNR / seccompDataArch / seccompDataArgs are the offsets in
	// struct seccomp_data the filter reads. An argument is read by its low
	// 32 bits, which is all the kernel looks at for the flags and modes the
	// rules test.
	seccompDataNR   = 0
	seccompDataArch = 4
	seccompDataArgs = 16
)

// Seccomp return actions (SECCOMP_RET_*).
const (
	SeccompRetKillProcess uint32 = 0x80000000
	SeccompRetLog         uint32 = 0x7ffc0000
	SeccompRetAllow       uint32 = 0x7fff0000
	seccompRetErrno       uint32 = 0x00050000
)

// SeccompRetErrno fails the call with errno instead of running it.
func SeccompRetErrno(errno uint16) uint32 { return seccompRetErrno | uint32(errno) }

// Audit architectures the filter accepts (AUDIT_ARCH_*).
const (
	AuditArchX86_64  uint32 = 0xc000003e
	AuditArchAARCH64 uint32 = 0xc00000b7
)

// MaxSeccompInsns is the kernel's program-length ceiling.
const MaxSeccompInsns = 4096

// SockFilter is struct sock_filter. The JSON names are what the V8 jail
// shim's spec has always carried (pkg/isolate).
type SockFilter struct {
	Code uint16 `json:"c"`
	Jt   uint8  `json:"t"`
	Jf   uint8  `json:"f"`
	K    uint32 `json:"k"`
}

func bpfStmt(code uint16, k uint32) SockFilter { return SockFilter{Code: code, K: k} }
func bpfJump(code uint16, k uint32, jt, jf uint8) SockFilter {
	return SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// SeccompArgMask is one argument test: (args[Arg] & Mask) != 0.
type SeccompArgMask struct {
	Arg  int
	Mask uint32
}

// SeccompArgEq is one argument test: args[Arg] == Value (low 32 bits).
type SeccompArgEq struct {
	Arg   int
	Value uint32
}

// SeccompArgRule narrows one syscall by its arguments, in one of two ways:
//
//   - DenyIfAll refuses Syscall when every mask is non-zero on the call's
//     arguments and allows it otherwise. It is how the jitless jail keeps
//     mprotect (the loader's RELRO needs it) while refusing PROT_EXEC
//     flips, and how a WASM worker keeps clone for threads while refusing
//     a new namespace.
//   - AllowIfAny allows Syscall when every test of one of its entries holds
//     and refuses it otherwise: how a WASM worker keeps socket for the
//     address families it uses and no other.
//
// Deny is the result of a call the rule refuses; 0 means the policy's
// RuleDeny.
type SeccompArgRule struct {
	Syscall    string
	DenyIfAll  []SeccompArgMask
	AllowIfAny [][]SeccompArgEq
	Deny       uint32
}

// SeccompPolicy is what a filter allows, refuses and does by default.
type SeccompPolicy struct {
	// Allow are syscall names the process may make.
	Allow []string
	// Actions give a name another fixed result: a kill for an escape
	// primitive, an errno a library falls back on (clone3 → ENOSYS). A name
	// may not also be in Allow or Rules.
	Actions map[string]uint32
	// Rules narrow some calls by argument; a ruled name may also appear in
	// Allow, where the rule wins.
	Rules []SeccompArgRule
	// RuleDeny is the result of a call a rule refuses; 0 means Default.
	RuleDeny uint32
	// Default is the result of every call nothing above names.
	Default uint32
}

// ResolveSyscalls maps names onto numbers for one architecture. Names the
// architecture does not have are returned separately: they cannot be called
// there, so skipping them narrows nothing, but the caller may want to log
// them once so a typo in a list is not silently ignored.
func ResolveSyscalls(names []string, table map[string]int) (nrs []int, unknown []string) {
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

// BuildSeccomp assembles the filter for one architecture:
//
//	if arch != want              → kill (never anything softer: a foreign ABI is an escape attempt)
//	if x86-64 and nr has x32 bit → kill
//	for each plain allowed nr    → allow
//	for each named action        → that action
//	for each arg-ruled nr        → allow unless every mask is set, then RuleDeny
//	otherwise                    → Default
//
// Plain, actioned and ruled syscalls are disjoint, so the order between
// them changes nothing. The accumulator holds nr throughout; arg checks only
// run once a nr matched and always end in a return, so later comparisons
// still see nr. The second result lists names the table lacks.
func BuildSeccomp(arch uint32, table map[string]int, p SeccompPolicy) ([]SockFilter, []string, error) {
	ruleDeny := p.RuleDeny
	if ruleDeny == 0 {
		ruleDeny = p.Default
	}
	ruled := map[string]SeccompArgRule{}
	for _, r := range p.Rules {
		if err := checkArgRule(r); err != nil {
			return nil, nil, err
		}
		if _, dup := ruled[r.Syscall]; dup {
			return nil, nil, fmt.Errorf("seccomp: duplicate arg rule for %q", r.Syscall)
		}
		ruled[r.Syscall] = r
	}
	allowed := map[string]struct{}{}
	var plain []string
	for _, name := range p.Allow {
		allowed[name] = struct{}{}
		if _, isRuled := ruled[name]; !isRuled {
			plain = append(plain, name)
		}
	}
	actionNames := make([]string, 0, len(p.Actions))
	for name := range p.Actions {
		if _, ok := allowed[name]; ok {
			return nil, nil, fmt.Errorf("seccomp: %q is both allowed and given an action", name)
		}
		if _, ok := ruled[name]; ok {
			return nil, nil, fmt.Errorf("seccomp: %q is both ruled and given an action", name)
		}
		actionNames = append(actionNames, name)
	}
	sort.Strings(actionNames)
	nrs, unknown := ResolveSyscalls(plain, table)

	prog := []SockFilter{
		bpfStmt(bpfLD|bpfW|bpfABS, seccompDataArch),
		bpfJump(bpfJMP|bpfJEQ|bpfK, arch, 1, 0),
		bpfStmt(bpfRET|bpfK, SeccompRetKillProcess),
		bpfStmt(bpfLD|bpfW|bpfABS, seccompDataNR),
	}
	if arch == AuditArchX86_64 {
		prog = append(prog,
			bpfJump(bpfJMP|bpfJGE|bpfK, x32SyscallBit, 0, 1),
			bpfStmt(bpfRET|bpfK, SeccompRetKillProcess),
		)
	}
	for _, nr := range nrs {
		prog = append(prog,
			bpfJump(bpfJMP|bpfJEQ|bpfK, uint32(nr), 0, 1),
			bpfStmt(bpfRET|bpfK, SeccompRetAllow),
		)
	}
	actioned := map[int]struct{}{}
	for _, name := range actionNames {
		nr, ok := table[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		if _, dup := actioned[nr]; dup {
			continue
		}
		actioned[nr] = struct{}{}
		prog = append(prog,
			bpfJump(bpfJMP|bpfJEQ|bpfK, uint32(nr), 0, 1),
			bpfStmt(bpfRET|bpfK, p.Actions[name]),
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
		deny := ruleDeny
		if r.Deny != 0 {
			deny = r.Deny
		}
		if len(r.AllowIfAny) > 0 {
			prog = append(prog, allowIfAnyBlock(uint32(nr), r.AllowIfAny, deny)...)
			continue
		}
		k := len(r.DenyIfAll)
		// Block: jeq nr | k × (ld arg; and mask; jeq 0 → allow) | ret deny | ret allow
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
			bpfStmt(bpfRET|bpfK, deny),
			bpfStmt(bpfRET|bpfK, SeccompRetAllow),
		)
	}
	prog = append(prog, bpfStmt(bpfRET|bpfK, p.Default))
	if len(prog) > MaxSeccompInsns {
		return nil, nil, fmt.Errorf("seccomp: program has %d instructions (max %d)", len(prog), MaxSeccompInsns)
	}
	sort.Strings(unknown)
	return prog, unknown, nil
}

// maxAllowIfAnyBlock keeps an AllowIfAny block's jumps within a BPF jump
// offset (8 bits).
const maxAllowIfAnyBlock = 255

// checkArgRule refuses a rule the builder cannot encode, or one that would
// mean something other than it says.
func checkArgRule(r SeccompArgRule) error {
	switch {
	case len(r.DenyIfAll) == 0 && len(r.AllowIfAny) == 0:
		return fmt.Errorf("seccomp: arg rule for %q has no tests", r.Syscall)
	case len(r.DenyIfAll) > 0 && len(r.AllowIfAny) > 0:
		return fmt.Errorf("seccomp: arg rule for %q both allows and denies by argument", r.Syscall)
	case len(r.DenyIfAll) > 6:
		return fmt.Errorf("seccomp: arg rule for %q has %d masks (max 6)", r.Syscall, len(r.DenyIfAll))
	}
	for _, m := range r.DenyIfAll {
		if m.Arg < 0 || m.Arg > 5 || m.Mask == 0 {
			return fmt.Errorf("seccomp: arg rule for %q: invalid mask %+v", r.Syscall, m)
		}
	}
	size := 1
	for _, entry := range r.AllowIfAny {
		if len(entry) == 0 || len(entry) > 6 {
			return fmt.Errorf("seccomp: arg rule for %q: an entry has %d tests (want 1 to 6)", r.Syscall, len(entry))
		}
		for _, eq := range entry {
			if eq.Arg < 0 || eq.Arg > 5 {
				return fmt.Errorf("seccomp: arg rule for %q: invalid test %+v", r.Syscall, eq)
			}
		}
		size += 2*len(entry) + 1
	}
	if size > maxAllowIfAnyBlock {
		return fmt.Errorf("seccomp: arg rule for %q is too long (%d instructions)", r.Syscall, size)
	}
	return nil
}

// allowIfAnyBlock is an AllowIfAny rule:
//
//	jeq nr (else past the block)
//	per entry: c × (ld arg; jeq value, else to the next entry) | ret allow
//	ret deny
func allowIfAnyBlock(nr uint32, entries [][]SeccompArgEq, deny uint32) []SockFilter {
	var body []SockFilter
	for _, entry := range entries {
		c := len(entry)
		for j, eq := range entry {
			body = append(body,
				bpfStmt(bpfLD|bpfW|bpfABS, uint32(seccompDataArgs+8*eq.Arg)),
				bpfJump(bpfJMP|bpfJEQ|bpfK, eq.Value, 0, uint8(2*c-2*j-1)),
			)
		}
		body = append(body, bpfStmt(bpfRET|bpfK, SeccompRetAllow))
	}
	body = append(body, bpfStmt(bpfRET|bpfK, deny))
	return append([]SockFilter{bpfJump(bpfJMP|bpfJEQ|bpfK, nr, 0, uint8(len(body)))}, body...)
}
