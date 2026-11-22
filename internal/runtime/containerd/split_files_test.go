package containerd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/privmode"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeParts is the root helper's container parts (M1 PR 7): it records
// each request and answers with paths in its own folder, with real FIFOs.
type fakeParts struct {
	mu         sync.Mutex
	dir        string
	prepares   []*rootdpb.PrepareSandboxRequest
	releases   []*rootdpb.ReleaseSandboxRequest
	prepareErr error
	releaseErr error
	// drop leaves one path out of the answer.
	drop string
	// during runs inside each prepare, as the helper would see the host.
	during func(*rootdpb.PrepareSandboxRequest)
}

func (p *fakeParts) PrepareSandbox(_ context.Context, req *rootdpb.PrepareSandboxRequest) (*rootdpb.PrepareSandboxResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prepares = append(p.prepares, proto.Clone(req).(*rootdpb.PrepareSandboxRequest))
	if p.during != nil {
		p.during(req)
	}
	if p.prepareErr != nil {
		return nil, p.prepareErr
	}
	id, s := req.GetContainerId(), req.GetSetup()
	dir := filepath.Join(p.dir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f := &rootdpb.SandboxFilePaths{ToolboxPath: filepath.Join(p.dir, "toolboxd")}
	if s.GetNaming() != nil {
		f.HostnamePath, f.HostsPath, f.ResolvConfPath = filepath.Join(dir, "hostname"), filepath.Join(dir, "hosts"), filepath.Join(dir, "resolv.conf")
	}
	if s.GetTaskFifos() {
		f.StdoutPath, f.StderrPath = filepath.Join(dir, "stdout"), filepath.Join(dir, "stderr")
		for _, fifo := range []string{f.StdoutPath, f.StderrPath} {
			_ = os.Remove(fifo)
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				return nil, err
			}
		}
	}
	if n := s.GetReadyNonce(); n != "" {
		f.ReadySocketPath = filepath.Join(dir, n+".sock")
	}
	if s.GetRunscConfig() != rootdpb.RunscConfig_RUNSC_CONFIG_UNSPECIFIED {
		f.RunscConfigPath = filepath.Join(p.dir, "config.toml")
	}
	switch p.drop {
	case "stdout":
		f.StdoutPath = ""
	case "toolbox":
		f.ToolboxPath = ""
	case "ready":
		f.ReadySocketPath = ""
	}
	return &rootdpb.PrepareSandboxResponse{Files: f}, nil
}

func (p *fakeParts) ReleaseSandbox(_ context.Context, req *rootdpb.ReleaseSandboxRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.releases = append(p.releases, proto.Clone(req).(*rootdpb.ReleaseSandboxRequest))
	return p.releaseErr
}

func (p *fakeParts) released() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, r := range p.releases {
		out = append(out, r.GetContainerId())
	}
	return out
}

// partsHelper is the root helper with container parts.
type partsHelper struct {
	*fakeHelper
	*fakeParts
}

func newPartsHelper(t *testing.T) *partsHelper {
	return &partsHelper{fakeHelper: &fakeHelper{addrs: map[string][]string{"sb-stopped": {"10.88.0.7"}}}, fakeParts: &fakeParts{dir: t.TempDir()}}
}

// noHostNaming keeps the tests off the host's resolv.conf.
func noHostNaming(t *testing.T) {
	orig := hostNamingFn
	hostNamingFn = func(id string) (*rootdpb.HostNaming, error) {
		return &rootdpb.HostNaming{Hostname: id, Hosts: localhostEntries, Nameservers: []string{"10.0.0.2"}}, nil
	}
	t.Cleanup(func() { hostNamingFn = orig })
}

// stoppedSplitContainer is a stopped sandbox created in split mode: its
// spec binds the helper's ready socket name and joins a pool namespace.
func stoppedSplitContainer(helperDir string) (*fakeContainer, *fakeTask) {
	task := &fakeTask{status: cntr.Stopped}
	return &fakeContainer{id: "sb-stopped", task: task, labels: map[string]string{containerIPLabelKey: "10.88.0.7"}, specOverride: &oci.Spec{
		Process: &specs.Process{Env: []string{"SB_TOOLBOX_TOKEN=tok", "SB_SANDBOX_ID=sb-stopped"}},
		Mounts:  []specs.Mount{readyMountAt(filepath.Join(helperDir, "sb-stopped", "ab12.sock"))},
		Linux:   &specs.Linux{Namespaces: []specs.LinuxNamespace{{Type: specs.NetworkNamespace, Path: "/run/aerolvm-rootd/netns/sb-stopped"}}},
	}}, task
}

func readyMountAt(source string) specs.Mount {
	return specs.Mount{Type: "bind", Source: source, Destination: dockerpkg.GuestReadySocketPath, Options: []string{"rbind", "ro"}}
}

// TestSplitStartMakesTheContainersFiles (M1 PR 7): a split start asks the
// helper for the container's files in one files part (host files, fresh
// FIFOs, the toolbox, and the ready socket's name, which the agent has
// bound again by then), never writes a host file of its own, and drains
// the task's output from the helper's FIFOs into its own task log.
func TestSplitStartMakesTheContainersFiles(t *testing.T) {
	stubToolboxProbe(t)
	noHostNaming(t)
	h := newPartsHelper(t)
	readyDir := shortReadyDir(t)
	h.during = func(*rootdpb.PrepareSandboxRequest) {
		if _, err := os.Stat(filepath.Join(readyDir, "sb-stopped.ab12.sock")); err != nil {
			t.Errorf("the agent's ready socket is not bound when the helper names it: %v", err)
		}
	}
	tr := newFakeTransport()
	c, task := stoppedSplitContainer(h.dir)
	c.runIO = true
	tr.containers["sb-stopped"] = c
	d := newTestDriver(t)
	d.cfg.ReadyDir = readyDir
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetRootHelper(h)
	state, err := d.Start(context.Background(), "sb-stopped")
	if err != nil {
		t.Fatal(err)
	}
	if state.ContainerIP != "10.88.0.7" || task.status != cntr.Running {
		t.Fatalf("state %+v, task %v", state, task.status)
	}
	want := &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: "sb-stopped", Setup: &rootdpb.ContainerSetup{
		Naming:    &rootdpb.HostNaming{Hostname: "sb-stopped", Hosts: localhostEntries, Nameservers: []string{"10.0.0.2"}},
		TaskFifos: true, ReadyNonce: "ab12", Toolbox: true,
	}}
	if len(h.prepares) != 1 || !proto.Equal(h.prepares[0], want) {
		t.Fatalf("asked %v, want %v", h.prepares, want)
	}
	if _, err := os.Stat(filepath.Join(d.cfg.RunDir, "hosts")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a split start wrote host files of its own: %v", err)
	}
	// The task's output: the helper's FIFOs, drained into the task log.
	tio := c.tio
	if tio == nil {
		t.Fatal("no task IO")
	}
	if cfg := tio.Config(); cfg.Stdout != filepath.Join(h.dir, "sb-stopped", "stdout") || cfg.Stderr != filepath.Join(h.dir, "sb-stopped", "stderr") || cfg.Stdin != "" {
		t.Fatalf("task IO %+v", cfg)
	}
	w, err := os.OpenFile(tio.Config().Stdout, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "hello from the sandbox\n")
	_ = w.Close()
	ew, err := os.OpenFile(tio.Config().Stderr, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = ew.Close()
	tio.Wait()
	_ = tio.Close()
	logPath, _ := d.taskLogPath("sb-stopped")
	if b, _ := os.ReadFile(logPath); !strings.Contains(string(b), "hello from the sandbox") {
		t.Fatalf("task log %q", b)
	}
	// The FIFOs stay: they are the helper's, removed with the container.
	if _, err := os.Lstat(tio.Config().Stdout); err != nil {
		t.Fatalf("the task's IO removed the helper's FIFO: %v", err)
	}
}

// TestSplitStartFailures: a start whose files the helper cannot make, or
// whose answer lacks one, creates no task; a parked container cannot start
// in split mode (no warm pool there yet).
func TestSplitStartFailures(t *testing.T) {
	stubToolboxProbe(t)
	noHostNaming(t)
	for _, tc := range []struct {
		name string
		set  func(*partsHelper, *fakeContainer)
		want string
	}{
		{"the helper fails", func(h *partsHelper, _ *fakeContainer) {
			h.prepareErr = errors.New("root helper refused the call (bad_request)")
		}, "bad_request"},
		{"no FIFO in the answer", func(h *partsHelper, _ *fakeContainer) { h.drop = "stdout" }, "lacks a path"},
		{"no toolbox in the answer", func(h *partsHelper, _ *fakeContainer) { h.drop = "toolbox" }, "lacks a path"},
		{"no ready socket in the answer", func(h *partsHelper, _ *fakeContainer) { h.drop = "ready" }, "lacks a path"},
		{"no host naming", func(*partsHelper, *fakeContainer) {
			hostNamingFn = func(string) (*rootdpb.HostNaming, error) { return nil, errors.New("resolv.conf unreadable") }
		}, "resolv.conf unreadable"},
		{"a parked container", func(_ *partsHelper, c *fakeContainer) {
			c.specOverride.Process.Env = append(c.specOverride.Process.Env, "SB_POOL_PARKED=1", "SB_POOL_BOOTSTRAP_TOKEN=bt", "SB_POOL_PARK_NONCE=pn")
			c.specOverride.Mounts = []specs.Mount{readyMountAt("/tmp/park-1.sock")}
		}, "warm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noHostNaming(t)
			h := newPartsHelper(t)
			tr := newFakeTransport()
			c, task := stoppedSplitContainer(h.dir)
			tr.containers["sb-stopped"] = c
			tc.set(h, c)
			d := newTestDriver(t)
			d.cfg.ReadyDir = shortReadyDir(t)
			d.SetClient(NewTestClient("aerolvm", tr))
			d.SetRootHelper(h)
			_, err := d.StartWithIdentity(context.Background(), "sb-stopped", "sb-stopped", "tok")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if c.taskIO != nil || task.status == cntr.Running {
				t.Fatal("a task was made after the files failed")
			}
		})
	}
}

// TestSplitDestroyReleasesHelperFiles: a split destroy has the helper
// remove the container's files, by the sandbox ID and by the container's
// own ID when they differ; a failed release is logged, not returned. A
// single-mode destroy asks nothing.
func TestSplitDestroyReleasesHelperFiles(t *testing.T) {
	h := newPartsHelper(t)
	var logs bytes.Buffer
	d := newTestDriver(t)
	d.logger = slog.New(slog.NewTextHandler(&logs, nil))
	d.SetRootHelper(h)
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-a", ContainerID: "park-1"}); err != nil {
		t.Fatal(err)
	}
	if got := h.released(); !slices.Equal(got, []string{"sb-a", "park-1"}) {
		t.Fatalf("released %v", got)
	}
	for _, r := range h.releases {
		if !slices.Equal(r.GetParts(), []string{rootdpb.PartFiles}) || r.GetNetnsName() != "" {
			t.Fatalf("release %v", r)
		}
	}
	h.releaseErr = errors.New("helper down")
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-b"}); err != nil {
		t.Fatalf("a failed release failed the destroy: %v", err)
	}
	if !strings.Contains(logs.String(), "sweep removes them later") {
		t.Fatalf("log %q", logs.String())
	}
	// A key that is no ID is never sent.
	d.releaseHelperFiles(context.Background(), "../etc")
	if got := h.released(); len(got) != 3 {
		t.Fatalf("a bad key was sent: %v", got)
	}
	single := newTestDriver(t)
	single.releaseHelperFiles(context.Background(), "sb-a")
}

// TestSplitGapsWithContainerParts: with the helper's container parts a
// split start names no gap, and a split create no longer names the
// container files; without them both still do.
func TestSplitGapsWithContainerParts(t *testing.T) {
	d := newTestDriver(t)
	d.SetRootHelper(newPartsHelper(t))
	if d.splitStartGaps() != nil {
		t.Fatal("a start with container parts has a gap")
	}
	var g *privmode.Gap
	err := d.splitCreateGaps(models.CreateSandboxRequest{})
	if !errors.As(err, &g) || slices.Contains(g.Steps, privmode.StepContainerFile) || !slices.Contains(g.Steps, privmode.StepImageUser) {
		t.Fatalf("create gaps %v", err)
	}
	d.SetRootHelper(&fakeHelper{})
	if !errors.As(d.splitStartGaps(), &g) || !slices.Equal(g.Steps, []privmode.Step{privmode.StepContainerFile}) {
		t.Fatalf("start gaps without parts %v", d.splitStartGaps())
	}
}

// TestSplitReadyResume: a start rebinds the agent's socket for the ready
// mount its spec names in the helper's folder, by that mount's container
// ID and nonce; any other shape binds nothing.
func TestSplitReadyResume(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyDir = shortReadyDir(t)
	env := []string{"SB_TOOLBOX_TOKEN=tok"}
	for _, tc := range []struct {
		name  string
		spec  *specs.Spec
		nonce string
	}{
		{"the helper's name", &specs.Spec{Process: &specs.Process{Env: env}, Mounts: []specs.Mount{readyMountAt("/run/aerolvm-rootd/ready/sb-1/ab12.sock")}}, "ab12"},
		{"no spec", nil, ""},
		{"no process", &specs.Spec{}, ""},
		{"no ready mount", &specs.Spec{Process: &specs.Process{Env: env}}, ""},
		{"no token", &specs.Spec{Process: &specs.Process{}, Mounts: []specs.Mount{readyMountAt("/run/aerolvm-rootd/ready/sb-1/ab12.sock")}}, ""},
		{"not a socket", &specs.Spec{Process: &specs.Process{Env: env}, Mounts: []specs.Mount{readyMountAt("/run/aerolvm-rootd/ready/sb-1/ab12")}}, ""},
		{"a folder that is no ID", &specs.Spec{Process: &specs.Process{Env: env}, Mounts: []specs.Mount{readyMountAt("/run/aerolvm-rootd/ready/_runtime/ab12.sock")}}, ""},
		{"an empty nonce", &specs.Spec{Process: &specs.Process{Env: env}, Mounts: []specs.Mount{readyMountAt("/run/aerolvm-rootd/ready/sb-1/.sock")}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rl, nonce := d.splitReadyResume(tc.spec)
			if nonce != tc.nonce || (rl != nil) != (tc.nonce != "") {
				t.Fatalf("nonce %q (listener %v), want %q", nonce, rl != nil, tc.nonce)
			}
			if rl != nil {
				if rl.HostSocketPath() != filepath.Join(d.cfg.ReadyDir, "sb-1.ab12.sock") {
					t.Fatalf("bound %s", rl.HostSocketPath())
				}
				_ = rl.Close()
			}
		})
	}
	// A ready folder the agent cannot bind in: no listener, and the start
	// goes on without one.
	d.cfg.ReadyDir = filepath.Join(t.TempDir(), "missing", strings.Repeat("x", 120))
	if rl, nonce := d.splitReadyResume(&specs.Spec{Process: &specs.Process{Env: env}, Mounts: []specs.Mount{readyMountAt("/r/sb-1/ab12.sock")}}); rl != nil || nonce != "" {
		t.Fatal("bound a socket in a folder that cannot hold one")
	}
}

// TestHelperFilesAsks: the files part a split driver sends, and its
// checks of the answer.
func TestHelperFilesAsks(t *testing.T) {
	noHostNaming(t)
	h := newPartsHelper(t)
	d := newTestDriver(t)
	if _, err := d.helperFiles(context.Background(), "sb-1", "", rootdpb.RunscConfig_RUNSC_CONFIG_UNSPECIFIED); err == nil {
		t.Fatal("a driver with no helper made files")
	}
	d.SetRootHelper(h)
	f, err := d.helperFiles(context.Background(), "sb-1", "ab12", rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT)
	if err != nil || f.GetRunscConfigPath() == "" || f.GetReadySocketPath() == "" {
		t.Fatalf("files %v, %v", f, err)
	}
	if s := h.prepares[0].GetSetup(); s.GetRunscConfig() != rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT || !s.GetToolbox() || !s.GetTaskFifos() {
		t.Fatalf("setup %v", s)
	}
}

// TestHostNaming: the host files' values are single mode's: the container
// ID as hostname, the localhost lines, and the host's resolver settings.
func TestHostNaming(t *testing.T) {
	n, err := hostNaming("sb-1")
	if _, statErr := os.Stat("/etc/resolv.conf"); statErr != nil {
		if err == nil {
			t.Fatal("no resolv.conf, and no error")
		}
		return
	}
	if err != nil || n.GetHostname() != "sb-1" || len(n.GetHosts()) != 2 {
		t.Fatalf("naming %v, %v", n, err)
	}
}

// TestTaskLogIOAtFails: a task log that cannot be opened fails before the
// task, and a FIFO that is not there fails its attach.
func TestTaskLogIOAtFails(t *testing.T) {
	d := newTestDriver(t)
	if _, _, err := d.taskLogIOAt(filepath.Join(t.TempDir(), "no", "such", "x.log"), &rootdpb.SandboxFilePaths{}); err == nil {
		t.Fatal("opened a log in a missing folder")
	}
	creator, release, err := d.taskLogIOAt(filepath.Join(t.TempDir(), "x.log"), &rootdpb.SandboxFilePaths{
		StdoutPath: filepath.Join(t.TempDir(), "gone", "stdout"), StderrPath: filepath.Join(t.TempDir(), "gone", "stderr")})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := creator("sb-x"); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("attached to FIFOs that are not there")
		}
	case <-ctx.Done():
		t.Fatal("the attach hung")
	}
}
