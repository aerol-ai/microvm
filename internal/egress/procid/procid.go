// Package procid traces a sandbox's TCP connection to the executables that
// hold it, for per-binary egress rules (plans/egress-domain-filtering.md
// §5.9, P3-3). The gateway sees the connection from the host: it finds the
// container-side socket in the sandbox's network namespace
// (/proc/<pid>/net/tcp), the processes in the sandbox's cgroup holding that
// socket, and compares each one's executable with the paths a rule lists,
// resolved inside the sandbox's root and compared by device and inode, so a
// copy or a symlink elsewhere is not the listed binary.
//
// Interpreted programs are named by their script too: for a process whose
// executable is an interpreter (python, node, a shell…), the script it was
// started with (argv[1], an absolute path) counts. That makes
// `binaries: [/usr/local/bin/pip]` work, and it is also why per-binary rules
// are least privilege for trusted tooling, not a boundary: code that
// controls an interpreter's environment can run under the script's name,
// and root in the sandbox can replace binaries. runc only: gVisor's sandbox
// processes are invisible from the host.
package procid

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ErrNotFound means no process in the sandbox holds the connection: it
// closed, or the sandbox isn't traceable (no pid, gVisor).
var ErrNotFound = errors.New("procid: connection owner not found")

// FileID identifies a file by device and inode.
type FileID struct{ Dev, Ino uint64 }

// Resolver reads procfs and the cgroup tree. The zero value is the host's.
type Resolver struct {
	Proc   string // default /proc
	Cgroup string // default /sys/fs/cgroup
	// resolve opens path inside root without escaping it; nil is the
	// platform's (openat2 RESOLVE_IN_ROOT on Linux).
	resolve func(root, path string) (FileID, error)
}

func (r Resolver) proc() string {
	if r.Proc == "" {
		return "/proc"
	}
	return r.Proc
}

func (r Resolver) cgroup() string {
	if r.Cgroup == "" {
		return "/sys/fs/cgroup"
	}
	return r.Cgroup
}

// Owner is one process holding a connection.
type Owner struct {
	PID    int
	Exe    FileID
	Script string // the interpreter's script, empty otherwise
}

// interpreters are executables whose argv[1] names the program they run.
var interpreters = regexp.MustCompile(`^(python[0-9.]*|node(js)?|ruby[0-9.]*|perl[0-9.]*|php[0-9.]*|bash|sh|dash|ash|zsh|busybox)$`)

// Matcher traces the connection local→remote, seen from inside the sandbox
// whose init process is pid, and returns is(path): whether one of its
// owners is the executable (or interpreted script) at path inside the
// sandbox.
func (r Resolver) Matcher(pid int, local, remote netip.AddrPort) (func(string) bool, error) {
	owners, err := r.Owners(pid, local, remote)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(r.proc(), strconv.Itoa(pid), "root")
	cache := map[string]FileID{}
	resolve := func(p string) (FileID, bool) {
		if id, ok := cache[p]; ok {
			return id, id != FileID{}
		}
		id, err := r.resolveIn(root, p)
		if err != nil {
			id = FileID{}
		}
		cache[p] = id
		return id, err == nil
	}
	return func(path string) bool {
		want, ok := resolve(path)
		if !ok {
			return false
		}
		for _, o := range owners {
			if o.Exe == want {
				return true
			}
			if o.Script != "" {
				if got, ok := resolve(o.Script); ok && got == want {
					return true
				}
			}
		}
		return false
	}, nil
}

func (r Resolver) resolveIn(root, p string) (FileID, error) {
	if r.resolve != nil {
		return r.resolve(root, p)
	}
	return resolveInRoot(root, p)
}

// Owners returns the processes holding the sandbox-side socket of the
// connection local→remote.
func (r Resolver) Owners(pid int, local, remote netip.AddrPort) ([]Owner, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("%w: no sandbox process to trace from", ErrNotFound)
	}
	inode, err := r.socketInode(pid, local, remote)
	if err != nil {
		return nil, err
	}
	pids, err := r.cgroupPIDs(pid)
	if err != nil {
		return nil, err
	}
	want := "socket:[" + inode + "]"
	var owners []Owner
	for _, p := range pids {
		if !r.holds(p, want) {
			continue
		}
		o, err := r.owner(p)
		if err != nil {
			continue // exited between the scan and the read
		}
		owners = append(owners, o)
	}
	if len(owners) == 0 {
		return nil, ErrNotFound
	}
	return owners, nil
}

// socketInode finds the TCP socket local→remote in pid's network namespace.
func (r Resolver) socketInode(pid int, local, remote netip.AddrPort) (string, error) {
	f, err := os.Open(filepath.Join(r.proc(), strconv.Itoa(pid), "net", "tcp"))
	if err != nil {
		return "", fmt.Errorf("procid: sandbox sockets: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		l, err1 := parseHexAddr(fields[1])
		rem, err2 := parseHexAddr(fields[2])
		if err1 != nil || err2 != nil || l != local || rem != remote {
			continue
		}
		if fields[9] == "0" {
			continue // a TIME_WAIT entry owns nothing
		}
		return fields[9], nil
	}
	return "", fmt.Errorf("%w: no socket %s→%s", ErrNotFound, local, remote)
}

// parseHexAddr reads procfs's IPv4 "0100007F:0050" (little-endian address).
func parseHexAddr(s string) (netip.AddrPort, error) {
	host, port, ok := strings.Cut(s, ":")
	if !ok || len(host) != 8 {
		return netip.AddrPort{}, errors.New("not an IPv4 procfs address")
	}
	b, err := hex.DecodeString(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	v := binary.LittleEndian.Uint32(b)
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], v)
	return netip.AddrPortFrom(netip.AddrFrom4(a), uint16(p)), nil
}

// cgroupPIDs lists every process in pid's cgroup and the cgroups below it
// (cgroup v2).
func (r Resolver) cgroupPIDs(pid int) ([]int, error) {
	raw, err := os.ReadFile(filepath.Join(r.proc(), strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return nil, fmt.Errorf("procid: sandbox cgroup: %w", err)
	}
	var rel string
	for _, line := range strings.Split(string(raw), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			rel = p
		}
	}
	if rel == "" {
		return nil, errors.New("procid: per-binary rules need cgroup v2")
	}
	var pids []int
	err = filepath.WalkDir(filepath.Join(r.cgroup(), rel), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "cgroup.procs" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, f := range strings.Fields(string(b)) {
			if n, err := strconv.Atoi(f); err == nil {
				pids = append(pids, n)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("procid: sandbox cgroup: %w", err)
	}
	return pids, nil
}

func (r Resolver) holds(pid int, want string) bool {
	dir := filepath.Join(r.proc(), strconv.Itoa(pid), "fd")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if l, err := os.Readlink(filepath.Join(dir, e.Name())); err == nil && l == want {
			return true
		}
	}
	return false
}

func (r Resolver) owner(pid int) (Owner, error) {
	base := filepath.Join(r.proc(), strconv.Itoa(pid))
	exe, err := statID(filepath.Join(base, "exe"))
	if err != nil {
		return Owner{}, err
	}
	o := Owner{PID: pid, Exe: exe}
	link, _ := os.Readlink(filepath.Join(base, "exe"))
	name := filepath.Base(strings.TrimSuffix(link, " (deleted)"))
	if !interpreters.MatchString(name) {
		return o, nil
	}
	cmdline, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err != nil {
		return o, nil
	}
	if argv := strings.Split(string(cmdline), "\x00"); len(argv) > 1 && strings.HasPrefix(argv[1], "/") {
		o.Script = filepath.Clean(argv[1])
	}
	return o, nil
}
