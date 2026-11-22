package mounts

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

const toolSecret = "tool-s3cr3t-never-on-argv"

// toolRig is an isolated-tool Manager whose kernel and process hooks are
// stand-ins: the FUSE mount is a file, the memfd a file, and the tool a
// sleep that the started command is swapped for.
type toolRig struct {
	m       *Manager
	mu      sync.Mutex
	started []*exec.Cmd
	fuse    []string // mount points the FUSE device was "mounted" at
	creds   [][]byte
	unmount []string
}

func newToolRig(t *testing.T) *toolRig {
	t.Helper()
	r := &toolRig{}
	base := t.TempDir()
	prevOwner := toolFolderOwner
	toolFolderOwner = uint32(os.Getuid())
	prevFuse, prevCred, prevStart, prevWait := openToolFuse, toolCredFile, startToolCmd, waitForToolProbe
	prevU, prevL := runUmount, runLazyUmount
	t.Cleanup(func() {
		toolFolderOwner = prevOwner
		openToolFuse, toolCredFile, startToolCmd, waitForToolProbe = prevFuse, prevCred, prevStart, prevWait
		runUmount, runLazyUmount = prevU, prevL
	})
	openToolFuse = func(hostPath, subtype string, uid, gid uint32, ro bool) (*os.File, error) {
		r.mu.Lock()
		r.fuse = append(r.fuse, hostPath+" fuse."+subtype)
		r.mu.Unlock()
		return os.Open(os.DevNull)
	}
	toolCredFile = func(body []byte, uid, gid uint32) (*os.File, error) {
		r.mu.Lock()
		r.creds = append(r.creds, slices.Clone(body))
		r.mu.Unlock()
		return os.Open(os.DevNull)
	}
	startToolCmd = func(cmd *exec.Cmd) error {
		r.mu.Lock()
		r.started = append(r.started, cmd)
		r.mu.Unlock()
		// The stand-in tool: a sleep in the tool's own process group,
		// run as this user (a test cannot change users).
		cmd.SysProcAttr.Credential = nil
		cmd.Path, cmd.Args, cmd.Err = "/bin/sleep", []string{"sleep", "30"}, nil
		return cmd.Start()
	}
	waitForToolProbe = func(string, time.Duration, <-chan struct{}) error { return nil }
	runUmount = func(p string) error {
		r.mu.Lock()
		r.unmount = append(r.unmount, p)
		r.mu.Unlock()
		return nil
	}
	runLazyUmount = runUmount
	m, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
		RootDir: filepath.Join(base, "mounts"), CredDir: filepath.Join(base, "creds"), WaitTimeout: time.Second,
		Tools: &ToolUser{UID: testToolUID(), GID: testToolGID(), CacheDir: filepath.Join(base, "cache")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	r.m = m
	return r
}

// testToolUID is the tools' user in tests: this user, who may chown to
// itself, or an unused uid when the tests run as root.
func testToolUID() uint32 {
	if os.Getuid() == 0 {
		return 4242
	}
	return uint32(os.Getuid())
}

func testToolGID() uint32 {
	if os.Getgid() == 0 {
		return 4243
	}
	return uint32(os.Getgid())
}

func toolSpecs() []models.MountSpec {
	return []models.MountSpec{
		{Type: models.MountTypeS3, Target: "/data", Source: "s3://bucket/p", ReadOnly: true,
			Options:     map[string]string{"endpoint": "http://10.0.0.5:9000", "extra_args": "--force-path-style"},
			Credentials: map[string]string{"access_key_id": "minio", "secret_access_key": toolSecret}},
		{Type: models.MountTypeSSHFS, Target: "/ssh", Source: "u@h:/srv", Credentials: map[string]string{"private_key_pem": toolSecret}},
		{Type: models.MountTypeRclone, Target: "/rc", Source: "store:b",
			Credentials: map[string]string{"rclone_conf": "[store]\ntype = s3\nsecret_access_key = " + toolSecret + "\n"}},
	}
}

// TestToolPlan: each FUSE tool's command, as an isolated tool runs it.
func TestToolPlan(t *testing.T) {
	r := newToolRig(t)
	m := r.m
	host := m.hostPath("sb-1", 0)
	build := func(spec models.MountSpec) adapters.Plan {
		plan, err := adapters.Adapters()[spec.Type].Build("sb-1", 0, spec, host, m.credDir)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	specs := toolSpecs()

	s3, run, err := m.toolPlan("sb-1", 0, models.MountTypeS3, build(specs[0]), host)
	if err != nil {
		t.Fatal(err)
	}
	if s3.Argv[len(s3.Argv)-1] != toolFuseFD || !slices.Contains(s3.Argv, "--allow-other") ||
		slices.Index(s3.Argv, "--allow-other") > slices.Index(s3.Argv, "--") {
		t.Fatalf("s3 argv %q", s3.Argv)
	}
	if !slices.Contains(s3.Env, "AWS_SHARED_CREDENTIALS_FILE="+toolCredFD) || !slices.Contains(s3.Env, toolMarkEnv+"="+host) ||
		!slices.Contains(s3.Env, "HOME="+toolHome) || s3.CredFile != "" || string(run.creds) == "" || run.cacheDir != "" {
		t.Fatalf("s3 env %q cred file %q creds %q", s3.Env, s3.CredFile, run.creds)
	}
	// Nothing of the helper's own environment: only what is set here.
	for _, e := range s3.Env {
		name, _, _ := strings.Cut(e, "=")
		if !slices.Contains([]string{"PATH", "HOME", toolMarkEnv, "AWS_SHARED_CREDENTIALS_FILE", "AWS_PROFILE"}, name) {
			t.Fatalf("s3 env carries %s", e)
		}
	}
	// --allow-root is the caller's, and stays.
	rooted := specs[0]
	rooted.Options = map[string]string{"extra_args": "--allow-root"}
	if p, _, _ := m.toolPlan("sb-1", 0, models.MountTypeS3, build(rooted), host); slices.Contains(p.Argv, "--allow-other") {
		t.Fatalf("--allow-other beside --allow-root: %q", p.Argv)
	}
	// No static keys: no credentials descriptor.
	ambient := specs[0]
	ambient.Credentials = nil
	if p, run, _ := m.toolPlan("sb-1", 0, models.MountTypeS3, build(ambient), host); run.creds != nil || slices.ContainsFunc(p.Env, func(e string) bool { return strings.HasPrefix(e, "AWS_SHARED") }) {
		t.Fatalf("ambient s3: %q %q", p.Env, run.creds)
	}

	ssh, run, err := m.toolPlan("sb-1", 0, models.MountTypeSSHFS, build(specs[1]), host)
	if err != nil || ssh.Argv[len(ssh.Argv)-1] != toolFuseFD || ssh.CredFile == "" || run.creds != nil ||
		!strings.Contains(strings.Join(ssh.Argv, " "), "IdentityFile="+ssh.CredFile) {
		t.Fatalf("sshfs %q %q %v", ssh.Argv, ssh.CredFile, err)
	}

	rc, run, err := m.toolPlan("sb-1", 0, models.MountTypeRclone, build(specs[2]), host)
	if err != nil || rc.Argv[1] != "mount2" || !slices.Contains(rc.Argv, "--allow-non-empty") ||
		!slices.Contains(rc.Argv, "--cache-dir="+run.cacheDir) || !slices.Contains(rc.Argv, toolCredFD) ||
		run.cacheDir != filepath.Join(m.tools.CacheDir, "sb-1-0") || rc.CredFile != "" {
		t.Fatalf("rclone %q %+v %v", rc.Argv, run, err)
	}
	for _, p := range []adapters.Plan{s3, ssh, rc} {
		for _, w := range append(slices.Clone(p.Argv), p.Env...) {
			if strings.Contains(w, toolSecret) || strings.Contains(w, host) && !strings.HasPrefix(w, toolMarkEnv) {
				t.Fatalf("%q carries the secret or the mount point", w)
			}
		}
	}

	nfs, _ := adapters.NFS{}.Build("sb-1", 0, models.MountSpec{Type: models.MountTypeNFS, Source: "h:/e"}, host, m.credDir)
	if _, _, err := m.toolPlan("sb-1", 0, models.MountTypeNFS, nfs, host); err == nil {
		t.Fatal("an NFS plan became a tool plan")
	}
	if _, _, err := m.toolPlan("sb-1", 0, models.MountTypeS3, adapters.Plan{Argv: []string{"mount-s3", "--", "b", "/elsewhere"}}, host); err == nil {
		t.Fatal("a plan for another mount point passed")
	}
	if _, _, err := m.toolPlan("sb-1", 0, models.MountTypeRclone, adapters.Plan{Argv: []string{"rclone", "serve", "--", "x:", host}}, host); err == nil {
		t.Fatal("an rclone that is not a mount passed")
	}
}

// TestMountToolLifecycle: a mount set of each FUSE tool starts each as the
// tools' user, from its own FUSE descriptor, with credentials only in the
// descriptor or its own key file, and the teardown leaves nothing behind.
func TestMountToolLifecycle(t *testing.T) {
	r := newToolRig(t)
	m := r.m
	binds, err := m.MountAll(context.Background(), "sb-1", toolSpecs())
	if err != nil {
		t.Fatal(err)
	}
	if len(binds) != 3 || binds[0].HostPath != m.hostPath("sb-1", 0) || !binds[0].ReadOnly || binds[0].RootOnly {
		t.Fatalf("binds %+v", binds)
	}
	r.mu.Lock()
	started := slices.Clone(r.started)
	fuse := slices.Clone(r.fuse)
	creds := slices.Clone(r.creds)
	r.mu.Unlock()
	if len(started) != 3 || len(fuse) != 3 || !strings.HasSuffix(fuse[0], "fuse.mount-s3") || !strings.HasSuffix(fuse[2], "fuse.rclone") {
		t.Fatalf("started %d fuse %v", len(started), fuse)
	}
	var pids []int
	for _, cmd := range started {
		pids = append(pids, cmd.Process.Pid)
	}
	for i, cmd := range started {
		// The stand-in cleared Credential to run; the rest is as started.
		if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid || cmd.Dir != "/" {
			t.Fatalf("tool %d attrs %+v", i, cmd.SysProcAttr)
		}
		want := 1 // the FUSE descriptor
		if i != 1 {
			want = 2 // and the credentials (s3, rclone)
		}
		if len(cmd.ExtraFiles) != want {
			t.Fatalf("tool %d has %d descriptors, want %d", i, len(cmd.ExtraFiles), want)
		}
		for _, e := range cmd.Env {
			if strings.Contains(e, toolSecret) {
				t.Fatalf("tool %d environment carries the secret: %s", i, e)
			}
		}
	}
	if len(creds) != 2 || !strings.Contains(string(creds[0]), toolSecret) || !strings.Contains(string(creds[1]), toolSecret) {
		t.Fatalf("memfd bodies %q", creds)
	}
	key := filepath.Join(m.credDir, "sb-1-1.id")
	st, err := os.Lstat(key)
	if err != nil || st.Mode().Perm() != 0o400 {
		t.Fatalf("sshfs key %v %v", st, err)
	}
	cache := filepath.Join(m.tools.CacheDir, "sb-1-2")
	if st, err := os.Lstat(cache); err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("rclone cache %v %v", st, err)
	}
	if err := m.UnmountAll("sb-1"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{key, cache, filepath.Join(m.rootDir, "sb-1")} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s left after the teardown: %v", p, err)
		}
	}
	for _, pid := range pids {
		deadline := time.Now().Add(5 * time.Second)
		for syscall.Kill(pid, 0) == nil {
			if time.Now().After(deadline) {
				t.Fatalf("tool %d still runs", pid)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// Each way a tool's start can fail leaves no mount, key or cache behind,
// and a missing tool is the node's setup (ErrMountToolUnavailable).
func TestMountToolFailures(t *testing.T) {
	spec := []models.MountSpec{toolSpecs()[1]} // sshfs: a key file to clean
	t.Run("fuse", func(t *testing.T) {
		r := newToolRig(t)
		openToolFuse = func(string, string, uint32, uint32, bool) (*os.File, error) { return nil, errors.New("no /dev/fuse") }
		if _, err := r.m.MountAll(context.Background(), "sb-1", spec); err == nil || !strings.Contains(err.Error(), "no /dev/fuse") {
			t.Fatal(err)
		}
		assertToolGone(t, r.m, "sb-1")
	})
	t.Run("credentials", func(t *testing.T) {
		r := newToolRig(t)
		toolCredFile = func([]byte, uint32, uint32) (*os.File, error) { return nil, errors.New("no memfd") }
		if _, err := r.m.MountAll(context.Background(), "sb-1", toolSpecs()[:1]); err == nil || !strings.Contains(err.Error(), "no memfd") {
			t.Fatal(err)
		}
		if len(r.unmount) == 0 {
			t.Fatal("the FUSE mount was left")
		}
		assertToolGone(t, r.m, "sb-1")
	})
	t.Run("missing tool", func(t *testing.T) {
		r := newToolRig(t)
		startToolCmd = func(*exec.Cmd) error { return exec.ErrNotFound }
		_, err := r.m.MountAll(context.Background(), "sb-1", spec)
		if !errors.Is(err, ErrMountToolUnavailable) {
			t.Fatal(err)
		}
		assertToolGone(t, r.m, "sb-1")
	})
	t.Run("never serves", func(t *testing.T) {
		r := newToolRig(t)
		waitForToolProbe = func(string, time.Duration, <-chan struct{}) error { return errors.New("timed out waiting for mount") }
		if _, err := r.m.MountAll(context.Background(), "sb-1", spec); err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatal(err)
		}
		if len(r.unmount) == 0 {
			t.Fatal("the FUSE mount was left")
		}
		assertToolGone(t, r.m, "sb-1")
	})
	t.Run("a WASM consumer", func(t *testing.T) {
		r := newToolRig(t)
		ctx := WithConsumer(context.Background(), Consumer{UID: 5000, GID: 5000})
		if _, err := r.m.MountAll(ctx, "sb-1", spec); err == nil || !strings.Contains(err.Error(), "no WASM consumer") {
			t.Fatal(err)
		}
	})
}

func assertToolGone(t *testing.T, m *Manager, id string) {
	t.Helper()
	for _, pattern := range []string{filepath.Join(m.credDir, id+"-*"), filepath.Join(m.tools.CacheDir, id+"-*"), filepath.Join(m.rootDir, id)} {
		if got, _ := filepath.Glob(pattern); len(got) != 0 {
			t.Errorf("left behind: %v", got)
		}
	}
}

// TestRestartTool: an isolated tool that exits is started again on a
// fresh FUSE mount, its credentials made again.
func TestRestartTool(t *testing.T) {
	r := newToolRig(t)
	if _, err := r.m.MountAll(context.Background(), "sb-1", toolSpecs()[:1]); err != nil {
		t.Fatal(err)
	}
	st := toolStateOf(r.m, "sb-1")
	cmd, _, exit, err := r.m.restartTool(st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = killMount(cmd); <-exit.done })
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.fuse) != 2 || len(r.creds) != 2 || len(r.unmount) == 0 || r.unmount[0] != st.hostPath {
		t.Fatalf("fuse %v creds %d unmount %v", r.fuse, len(r.creds), r.unmount)
	}
}

// TestToolFolders: a mount point's folders are the Manager's own; a link
// planted where one goes, a file, or a folder others can write is never
// mounted through, and nothing lands where the link points.
func TestToolFolders(t *testing.T) {
	r := newToolRig(t)
	m := r.m
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(m.rootDir, "sb-link")); err != nil {
		t.Fatal(err)
	}
	_, err := m.MountAll(context.Background(), "sb-link", toolSpecs()[:1])
	if !errors.Is(err, ErrToolFolder) {
		t.Fatalf("a linked sandbox folder: %v", err)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("something landed where the link points: %v", entries)
	}
	if len(r.fuse) != 0 {
		t.Fatalf("mounted %v", r.fuse)
	}
	if err := os.WriteFile(filepath.Join(m.rootDir, "sb-file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.MountAll(context.Background(), "sb-file", toolSpecs()[:1]); !errors.Is(err, ErrToolFolder) {
		t.Fatalf("a file for a folder: %v", err)
	}
	open := filepath.Join(m.rootDir, "sb-open")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := m.MountAll(context.Background(), "sb-open", toolSpecs()[:1]); !errors.Is(err, ErrToolFolder) {
		t.Fatalf("a folder others can write: %v", err)
	}
	// The mount point itself, planted as a link.
	if err := os.Mkdir(filepath.Join(m.rootDir, "sb-2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(m.rootDir, "sb-2", "0")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.MountAll(context.Background(), "sb-2", toolSpecs()[:1]); !errors.Is(err, ErrToolFolder) {
		t.Fatalf("a linked mount point: %v", err)
	}
	if len(r.fuse) != 0 {
		t.Fatalf("mounted %v", r.fuse)
	}
}

func TestPrepareToolDirs(t *testing.T) {
	prev := toolFolderOwner
	toolFolderOwner = uint32(os.Getuid())
	t.Cleanup(func() { toolFolderOwner = prev })
	base := t.TempDir()
	root, creds, cache := filepath.Join(base, "m"), filepath.Join(base, "c"), filepath.Join(base, "k")
	for _, d := range []string{root, creds} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepareToolDirs(root, creds, &ToolUser{UID: 1, GID: 1, CacheDir: cache}); err != nil {
		t.Fatal(err)
	}
	for d, mode := range map[string]os.FileMode{root: 0o700, creds: 0o711, cache: 0o711} {
		if st, err := os.Stat(d); err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s: %v %v", d, st.Mode(), err)
		}
	}
	for _, tc := range []*ToolUser{{UID: 0, GID: 1, CacheDir: cache}, {UID: 1, GID: 0, CacheDir: cache}, {UID: 1, GID: 1, CacheDir: "k"}, {UID: 1, GID: 1, CacheDir: cache + "/"}} {
		if err := prepareToolDirs(root, creds, tc); err == nil {
			t.Errorf("%+v passed", tc)
		}
	}
	if _, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{RootDir: root, CredDir: creds, Tools: &ToolUser{CacheDir: cache}}); err == nil {
		t.Fatal("a root tool user passed")
	}
}

func TestWaitForServed(t *testing.T) {
	dir := t.TempDir()
	never := make(chan struct{})
	if err := waitForServed(dir, time.Second, never); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	close(exited)
	if err := waitForServed(filepath.Join(dir, "gone"), time.Second, exited); !errors.Is(err, errMountToolExited) {
		t.Fatalf("exited: %v", err)
	}
	if err := waitForServed(filepath.Join(dir, "gone"), time.Second, never); err == nil || errors.Is(err, errMountToolExited) {
		t.Fatalf("no answer: %v", err)
	}
	// A stat that never answers (a tool that never serves) times out.
	block := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(block, 0o600); err != nil {
		t.Skip(err)
	}
	prev := waitForServed
	_ = prev
	if err := waitForServedAt(block, 50*time.Millisecond, never); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout: %v", err)
	}
}

// waitForServedAt is waitForServed with a stat that blocks: opening a FIFO
// for reading waits for a writer, as a stat of an unserved FUSE mount
// waits for its tool.
func waitForServedAt(fifo string, timeout time.Duration, exited <-chan struct{}) error {
	served := make(chan error, 1)
	go func() {
		f, err := os.Open(fifo)
		if err == nil {
			_ = f.Close()
		}
		served <- err
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case err := <-served:
		return err
	case <-exited:
		return errMountToolExited
	case <-t.C:
		w, _ := os.OpenFile(fifo, os.O_WRONLY, 0) // let the open return
		if w != nil {
			_ = w.Close()
		}
		return errors.New("timed out waiting for mount")
	}
}

// TestAdoptTool: after a restart an isolated tool is taken over by its
// marker and its command, and a tool marked for the path but running
// other arguments is cleared instead.
func TestAdoptTool(t *testing.T) {
	r := newToolRig(t)
	m := r.m
	proc := t.TempDir()
	withProcRoot(t, proc)
	withProbeMount(t, func(string) mountProbe { return mountLive })
	spec := toolSpecs()[0]
	host := m.hostPath("sb-1", 0)
	plan, _ := adapters.S3{}.Build("sb-1", 0, spec, host, m.credDir)
	tplan, _, err := m.toolPlan("sb-1", 0, spec.Type, plan, host)
	if err != nil {
		t.Fatal(err)
	}
	fakeProc(t, proc, 501, tplan.Argv...)
	writeEnviron(t, proc, 501, toolMarkEnv+"="+host)
	// The same command for another mount: never taken for this one.
	fakeProc(t, proc, 502, tplan.Argv...)
	writeEnviron(t, proc, 502, toolMarkEnv+"="+m.hostPath("sb-9", 0))
	prevOpen := openHelperProcess
	var opened []int
	openHelperProcess = func(pid int, argv []string) (liveProcess, error) {
		opened = append(opened, pid)
		return newFakeLive(pid, syscall.SIGTERM), nil
	}
	t.Cleanup(func() { openHelperProcess = prevOpen })
	if err := os.MkdirAll(filepath.Dir(host), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := m.Reestablish(context.Background(), "sb-1", []models.MountSpec{spec}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(opened, []int{501}) || len(r.started) != 0 {
		t.Fatalf("opened %v started %d", opened, len(r.started))
	}
	st := toolStateOf(m, "sb-1")
	if st == nil || st.tool == nil || st.proc == nil {
		t.Fatalf("state %+v", st)
	}
	helpers := m.listHelperProcesses()
	if got := markedFor(helpers, host); len(got) != 1 || got[0].pid != 501 {
		t.Fatalf("marked %+v", got)
	}
	// Another spec for the same path: the running tool is not taken.
	other := spec
	other.Options = map[string]string{"extra_args": "--allow-delete"}
	if st, _ := m.adoptTool("sb-1", 0, other, host, mustBuild(t, other, host, m.credDir), helpers); st != nil {
		t.Fatal("a tool running other arguments was adopted")
	}
	kills := recordGroupKills(t)
	m.clearStaleMount("sb-1", 0, helpers)
	if len(*kills) == 0 {
		t.Fatal("the stale tool was not stopped by its marker")
	}
}

func mustBuild(t *testing.T, spec models.MountSpec, host, credDir string) adapters.Plan {
	t.Helper()
	plan, err := adapters.Adapters()[spec.Type].Build("sb-1", 0, spec, host, credDir)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// writeStatusUID writes a stand-in /proc/<pid>/status: real, effective,
// saved and filesystem uid all uid.
func writeStatusUID(t *testing.T, root string, pid int, uid uint32) {
	t.Helper()
	u := strconv.FormatUint(uint64(uid), 10)
	body := "Name:\tx\nUid:\t" + u + "\t" + u + "\t" + u + "\t" + u + "\nGid:\t0\t0\t0\t0\n"
	if err := os.WriteFile(filepath.Join(root, strconv.Itoa(pid), "status"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeEnviron(t *testing.T, root string, pid int, env ...string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, strconv.Itoa(pid), "environ"), []byte(strings.Join(env, "\x00")+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestToolStartsInItsOwnSession: an isolated tool starts as the leader of
// a session of its own, so it cannot move to another process group, and
// teardown's signal to its group reaches only it and its children.
func TestToolStartsInItsOwnSession(t *testing.T) {
	r := newToolRig(t)
	if _, err := r.m.MountAll(context.Background(), "sb-1", toolSpecs()[:1]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.m.UnmountAll("sb-1") })
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.started) != 1 {
		t.Fatalf("%d starts", len(r.started))
	}
	if a := r.started[0].SysProcAttr; !a.Setsid || a.Setpgid {
		t.Fatalf("the tool starts with Setsid %v Setpgid %v, want a session of its own", a.Setsid, a.Setpgid)
	}
}

// TestKillMarked: the sweep stops a marked tool under the folder, by its
// own process group, and nothing else.
func TestKillMarked(t *testing.T) {
	proc := t.TempDir()
	tool := exec.Command("sleep", "30")
	tool.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := tool.Start(); err != nil {
		t.Fatal(err)
	}
	other := exec.Command("sleep", "30")
	other.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
	uid := uint32(os.Getuid())
	fakeProc(t, proc, tool.Process.Pid, "mount-s3")
	writeEnviron(t, proc, tool.Process.Pid, "PATH=/bin", toolMarkEnv+"=/m/sb-1/0")
	writeStatusUID(t, proc, tool.Process.Pid, uid)
	fakeProc(t, proc, other.Process.Pid, "mount-s3")
	writeEnviron(t, proc, other.Process.Pid, toolMarkEnv+"=/m/sb-10/0")
	writeStatusUID(t, proc, other.Process.Pid, uid)
	fakeProc(t, proc, 1, "init") // no environ: skipped
	killMarkedInRoot(slog.New(slog.NewTextHandler(io.Discard, nil)), "/m/sb-1", proc, uid)
	done := make(chan error, 1)
	go func() { done <- tool.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the marked tool still runs")
	}
	if err := other.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("another sandbox's tool was stopped: %v", err)
	}
	if got := readMark(tool.Process.Pid); got != "" && got != "/m/sb-1/0" {
		t.Fatalf("readMark %q", got)
	}
}

// TestClearToolFiles: a sandbox's key files and caches go with its folder,
// and only its own: never another sandbox's whose ID starts the same.
func TestClearToolFiles(t *testing.T) {
	r := newToolRig(t)
	m := r.m
	files := map[string]bool{
		filepath.Join(m.credDir, "sb-1-0.id"):        true,
		filepath.Join(m.tools.CacheDir, "sb-1-2"):    true,
		filepath.Join(m.credDir, "sb-1-x.id"):        false,
		filepath.Join(m.credDir, "sb-10-0.id"):       false,
		filepath.Join(m.tools.CacheDir, "sb-1-name"): false,
	}
	for p := range files {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m.clearToolFiles("sb-1")
	m.clearToolFiles("../x")
	for p, gone := range files {
		if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) != gone {
			t.Errorf("%s gone=%v", p, !gone)
		}
	}
	(&Manager{}).clearToolFiles("sb-1") // single mode: nothing to clear
}

func TestWriteToolCred(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k.id")
	if err := writeToolCred(p, []byte("one"), uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	// Written afresh: never through an old name, a link above all.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if err := writeToolCred(p, []byte("two"), uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("written through a link: %q", b)
	}
	if st, _ := os.Lstat(p); st.Mode()&fs.ModeSymlink != 0 || st.Mode().Perm() != 0o400 {
		t.Fatalf("mode %v", st.Mode())
	}
	if err := writeToolCred(filepath.Join(dir, "no", "k"), nil, 0, 0); err == nil {
		t.Fatal("a missing folder passed")
	}
	if err := ensureToolCache(filepath.Join(dir, "no", "c"), 0, 0); err == nil {
		t.Fatal("a cache in a missing folder passed")
	}
	if err := ensureToolCache(target, 0, 0); err == nil {
		t.Fatal("a file for a cache passed")
	}
}

func TestToolSubtypeAndBeforeEnd(t *testing.T) {
	for typ, want := range map[models.MountType]string{models.MountTypeS3: "mount-s3", models.MountTypeSSHFS: "sshfs",
		models.MountTypeRclone: "rclone", models.MountTypeNFS: "nfs"} {
		if got := toolSubtype(typ); got != want {
			t.Errorf("%s: %s", typ, got)
		}
	}
	if got := beforeOptionsEnd([]string{"a", "b"}, "c"); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatal(got)
	}
	if argvName(nil) != "mount tool" {
		t.Fatal("argvName")
	}
}

func toolStateOf(m *Manager, id string) *mountState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.state[id]; len(s) > 0 {
		return s[0]
	}
	return nil
}

// TestToolCacheFolder: rclone's cache is <CacheDir>/<id>-<index> for every
// id mountSet accepts, and none for an id it refuses.
func TestToolCacheFolder(t *testing.T) {
	cache := t.TempDir()
	m := &Manager{tools: &ToolUser{UID: 1, GID: 1, CacheDir: cache + "/./"}}
	for _, c := range []struct {
		id     string
		want   string
		wantOK bool
	}{
		{"sb-1", filepath.Join(cache, "sb-1-2"), true},
		{"", "", false},
		{"..", "", false},
		{"../x", "", false},
		{"a/b", "", false},
		{strings.Repeat("a", 129), "", false},
	} {
		got, ok := m.toolCacheFolder(c.id, 2)
		if got != c.want || ok != c.wantOK {
			t.Errorf("toolCacheFolder(%q) = %q, %v; want %q, %v", c.id, got, ok, c.want, c.wantOK)
		}
	}
	host := filepath.Join(t.TempDir(), "x", "0")
	plan := adapters.Plan{Argv: []string{"rclone", "mount", "--", "r:b", host}}
	if _, _, err := m.toolPlan("../x", 0, models.MountTypeRclone, plan, host); err == nil || !strings.Contains(err.Error(), "no cache folder") {
		t.Fatalf("toolPlan with a bad id = %v", err)
	}
}

// TestToolBinary: an isolated tool runs one of three fixed programs; a plan
// whose program is not its type's is refused, and a type with no tool
// starts nothing.
func TestToolBinary(t *testing.T) {
	for typ, want := range map[models.MountType]string{models.MountTypeS3: "mount-s3", models.MountTypeSSHFS: "sshfs", models.MountTypeRclone: "rclone"} {
		if got, ok := toolBinary(typ); !ok || got != want {
			t.Errorf("toolBinary(%s) = %q, %v", typ, got, ok)
		}
		if toolSubtype(typ) != want {
			t.Errorf("toolSubtype(%s) = %q", typ, toolSubtype(typ))
		}
	}
	if _, ok := toolBinary(models.MountTypeNFS); ok || toolSubtype(models.MountTypeNFS) != "nfs" {
		t.Fatal("nfs runs no FUSE tool")
	}
	r := newToolRig(t)
	host := r.m.hostPath("sb-1", 0)
	plan := adapters.Plan{Argv: []string{"/tmp/other", "--", "s3://b", host}}
	if _, _, err := r.m.toolPlan("sb-1", 0, models.MountTypeS3, plan, host); err == nil || !strings.Contains(err.Error(), "runs mount-s3") {
		t.Fatalf("a plan running another program = %v", err)
	}
	s := &mountState{sandboxID: "sb-1", spec: models.MountSpec{Type: models.MountTypeNFS}, hostPath: host, tool: &toolRun{}}
	if _, _, _, err := r.m.startTool(s); err == nil || !strings.Contains(err.Error(), "runs no FUSE tool") {
		t.Fatalf("startTool for nfs = %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.started) != 0 || len(r.fuse) != 0 {
		t.Fatalf("started %d fuse %v", len(r.started), r.fuse)
	}
}
