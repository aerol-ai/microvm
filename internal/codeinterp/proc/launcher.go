// Package proc starts code interpreter kernels as local processes (the
// toolboxd launcher). Each kernel is a driver script run by the language's
// interpreter, speaking the codeinterp driver protocol in "fd" mode: requests
// on fd 3, events on fd 4, user output on fd 1 and 2.
package proc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/internal/codeinterp/drivers"
)

// StartFunc starts cmd and returns the function that waits for it. toolboxd
// is PID 1 and reaps every child, so it passes its child-table start; a
// plain cmd.Start + cmd.Wait would lose exit statuses to the reaper.
type StartFunc func(cmd *exec.Cmd) (wait func() error, err error)

// Config configures a Launcher.
type Config struct {
	// Start starts a kernel process. Nil means cmd.Start and cmd.Wait.
	Start StartFunc
	// Env returns the base environment of every kernel (toolboxd: the image
	// env plus the sandbox env). Interpreters are looked up on its PATH.
	Env func() []string
	// DriverDir holds the driver scripts, written on first use with mode
	// 0700. Empty, or a folder that cannot be kept private to this user,
	// means a fresh directory under os.TempDir() (see driverDir).
	DriverDir string
}

// defaultPath is what a shell searches when PATH is unset, so an image
// whose env has no PATH still finds /usr/bin/python3.
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// lookupDriver is drivers.Lookup; tests swap in a fake driver so the
// protocol is tested without an interpreter installed.
var lookupDriver = drivers.Lookup

// Launcher implements codeinterp.Launcher with local processes.
type Launcher struct {
	cfg Config

	mu      sync.Mutex
	dir     string
	written map[string]bool
}

// New returns a Launcher. It starts nothing.
func New(cfg Config) *Launcher { return &Launcher{cfg: cfg, written: map[string]bool{}} }

// Languages lists the languages this launcher has drivers for, so an
// adapter can refuse the others before it tries to start anything.
func (l *Launcher) Languages() []string { return drivers.Languages() }

// Launch starts a kernel for spec and waits until its driver is ready.
func (l *Launcher) Launch(ctx context.Context, spec codeinterp.Spec) (codeinterp.Kernel, error) {
	d, ok := lookupDriver(spec.Language)
	if !ok {
		return nil, fmt.Errorf("%w: %q", codeinterp.ErrUnsupportedLanguage, spec.Language)
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	env := kernelEnv(l.baseEnv(), spec.Env, d.Env, nonce)
	program, err := findProgram(d, envValue(env, "PATH"))
	if err != nil {
		return nil, err
	}
	if spec.Cwd != "" {
		if err := checkCwd(spec.Cwd); err != nil {
			return nil, err
		}
	}
	script, err := l.script(d)
	if err != nil {
		return nil, err
	}
	cmd := &exec.Cmd{
		Path: program,
		Args: d.Args(program, script),
		Dir:  spec.Cwd,
		Env:  env,
		// Own process group: an interrupt reaches the code's children too,
		// and Close kills the whole tree.
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
	}
	start := l.cfg.Start
	if start == nil {
		start = func(cmd *exec.Cmd) (func() error, error) {
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			return cmd.Wait, nil
		}
	}
	k, err := startKernel(cmd, start, nonce)
	if err != nil {
		return nil, fmt.Errorf("codeinterp: start %s: %w", program, err)
	}
	if err := k.awaitReady(ctx, d.Language); err != nil {
		_ = k.Close()
		return nil, err
	}
	return k, nil
}

func (l *Launcher) baseEnv() []string {
	if l.cfg.Env != nil {
		return l.cfg.Env()
	}
	return os.Environ()
}

func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("codeinterp: nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// kernelEnv is base, then the context's env, then the driver's, then the
// protocol variables. A later value for a name replaces an earlier one.
func kernelEnv(base []string, ctxEnv, driverEnv map[string]string, nonce string) []string {
	var order []string
	values := map[string]string{}
	set := func(name, value string) {
		if _, seen := values[name]; !seen {
			order = append(order, name)
		}
		values[name] = value
	}
	for _, kv := range base {
		if name, value, ok := strings.Cut(kv, "="); ok && name != "" {
			set(name, value)
		}
	}
	for _, m := range []map[string]string{ctxEnv, driverEnv} {
		names := make([]string, 0, len(m))
		for name := range m {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			set(name, m[name])
		}
	}
	set("AEROL_INTERP_MODE", "fd")
	set("AEROL_INTERP_NONCE", nonce)
	// Output from the code and its python children streams as it is
	// written instead of when a buffer fills.
	set("PYTHONUNBUFFERED", "1")
	// No display in a sandbox: plots render to images, which the driver
	// sends as results. A user's own choice wins.
	if _, ok := values["MPLBACKEND"]; !ok {
		set("MPLBACKEND", "Agg")
	}
	out := make([]string, 0, len(order))
	for _, name := range order {
		out = append(out, name+"="+values[name])
	}
	return out
}

func envValue(env []string, name string) string {
	value := ""
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			value = v
		}
	}
	return value
}

// findProgram looks the driver's programs up on the kernel's PATH, not on
// toolboxd's own: the sandbox env may add folders (a venv, /opt/conda/bin).
func findProgram(d drivers.Driver, path string) (string, error) {
	if path == "" {
		path = defaultPath
	}
	for _, name := range d.Programs {
		if strings.Contains(name, "/") {
			if isExecutable(name) {
				return name, nil
			}
			continue
		}
		for _, dir := range filepath.SplitList(path) {
			// A relative PATH entry would resolve against toolboxd's cwd,
			// which is not where the user expects programs to come from.
			if dir == "" || !filepath.IsAbs(dir) {
				continue
			}
			candidate := filepath.Join(dir, name)
			if isExecutable(candidate) {
				return candidate, nil
			}
		}
	}
	return "", &codeinterp.MissingInterpreterError{
		Language: d.Language,
		Programs: d.Programs,
		Detail:   "install one of them in the sandbox image",
	}
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func checkCwd(cwd string) error {
	info, err := os.Stat(cwd)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("codeinterp: cwd %q does not exist", cwd)
		}
		return fmt.Errorf("codeinterp: cwd %q: %w", cwd, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("codeinterp: cwd %q is not a directory", cwd)
	}
	return nil
}

// script writes the driver into the driver folder once and returns its
// path. The name carries a hash of the content, so a toolboxd upgrade never
// runs a stale driver left by the old binary.
func (l *Launcher) script(d drivers.Driver) (string, error) {
	sum := sha256.Sum256(d.Script)
	name := hex.EncodeToString(sum[:8]) + "-" + d.FileName

	l.mu.Lock()
	defer l.mu.Unlock()
	dir, err := l.driverDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	if l.written[path] {
		// A cleaner of /tmp may have removed it since. The folder is
		// private, so a script still there is the one written.
		if _, err := os.Lstat(path); err == nil {
			return path, nil
		}
	}
	tmp, err := os.CreateTemp(dir, ".driver-*")
	if err != nil {
		return "", fmt.Errorf("codeinterp: write driver: %w", err)
	}
	_, werr := tmp.Write(d.Script)
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		// CreateTemp already made it 0600; rename makes the write atomic
		// for a launch that races this one in another toolboxd process.
		werr = os.Rename(tmp.Name(), path)
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("codeinterp: write driver: %w", werr)
	}
	l.written[path] = true
	return path, nil
}

// driverDir returns the folder the driver scripts go in, checked on every
// use. Whoever can write to it chooses the code toolboxd runs, so it must
// be private: a real directory (not a symlink) owned by this process's
// user, mode 0700. The configured folder is used when it is, or can be
// made, private; otherwise, and with none configured, a fresh folder from
// os.MkdirTemp is. A fixed name under a shared /tmp could be planted by
// another user of the sandbox, and a folder that was private once can be
// removed (a /tmp cleaner) and replaced, so a folder that no longer passes
// is never written to again.
func (l *Launcher) driverDir() (string, error) {
	if l.dir != "" && isPrivateDir(l.dir) == nil {
		return l.dir, nil
	}
	if l.cfg.DriverDir != "" && claimDir(l.cfg.DriverDir) == nil {
		l.dir = l.cfg.DriverDir
		return l.dir, nil
	}
	dir, err := os.MkdirTemp("", "aerolvm-codeinterp-")
	if err != nil {
		return "", fmt.Errorf("codeinterp: driver folder: %w", err)
	}
	l.dir = dir
	return dir, nil
}

// claimDir makes dir when it is missing and makes sure it is private. A
// folder of ours that only others could read is tightened to 0700 (MkdirAll
// leaves an existing folder's mode alone); one others could write to is
// refused, since they may have put files in it already.
func claimDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// O_NOFOLLOW: the checks and the chmod act on the folder itself, never
	// on what a symlink in its place points to.
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if err := checkOwnerAndMode(uint32(st.Mode), st.Uid, true); err != nil {
		return err
	}
	if st.Mode&0o777 != 0o700 {
		if err := syscall.Fchmod(fd, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// isPrivateDir reports why dir is not a private folder, or nil.
func isPrivateDir(dir string) error {
	var st syscall.Stat_t
	if err := syscall.Lstat(dir, &st); err != nil {
		return err
	}
	return checkOwnerAndMode(uint32(st.Mode), st.Uid, false)
}

// checkOwnerAndMode checks a stat of a would-be driver folder. With
// tighten, only the group and other write bits disqualify it (the caller
// fixes the rest); without, the mode must be 0700 exactly.
func checkOwnerAndMode(mode, uid uint32, tighten bool) error {
	switch {
	case mode&syscall.S_IFMT != syscall.S_IFDIR:
		return errors.New("not a directory")
	case int(uid) != os.Geteuid():
		return fmt.Errorf("owned by uid %d, not %d", uid, os.Geteuid())
	case tighten && mode&0o022 != 0:
		return fmt.Errorf("mode %#o lets others write to it", mode&0o777)
	case !tighten && mode&0o777 != 0o700:
		return fmt.Errorf("mode %#o, not 0700", mode&0o777)
	}
	return nil
}

// readyDrain bounds how long a launch that failed waits for the driver's
// last stderr bytes, which carry the reason.
const readyDrain = 2 * time.Second

func (k *kernel) awaitReady(ctx context.Context, language string) error {
	timer := time.NewTimer(codeinterp.LaunchTimeout)
	defer timer.Stop()
	select {
	case fr, ok := <-k.frames:
		if !ok {
			return k.exitedEarly(language)
		}
		switch fr.kind {
		case "READY":
			return nil
		case "FATAL":
			return fmt.Errorf("codeinterp: %s driver failed to start: %s", language, strings.TrimSpace(string(fr.payload)))
		}
		return fmt.Errorf("codeinterp: %s driver sent %s before READY", language, fr.kind)
	case <-k.exited:
		return k.exitedEarly(language)
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("codeinterp: %s driver did not start within %s", language, codeinterp.LaunchTimeout)
	}
}

// exitedEarly explains a driver that ended before READY: most often the
// interpreter is too old or broken, and its stderr says so.
func (k *kernel) exitedEarly(language string) error {
	deadline := time.NewTimer(readyDrain)
	defer deadline.Stop()
	select {
	case <-k.exited:
	case <-deadline.C:
	}
	select {
	case <-k.pipes[1].eof:
	case <-deadline.C:
	}
	k.mu.Lock()
	tail := strings.TrimSpace(string(k.tail))
	waitErr := k.waitErr
	k.mu.Unlock()
	if tail == "" {
		tail = "no output"
		if waitErr != nil {
			tail = waitErr.Error()
		}
	}
	return fmt.Errorf("codeinterp: %s driver exited before it was ready: %s", language, tail)
}
