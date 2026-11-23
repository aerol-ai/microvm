package rootd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/network/workerfence"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// memWorkerFence is the worker fence's kernel in memory.
type memWorkerFence struct {
	mu      sync.Mutex
	applied [][]workerfence.Rule
	fail    error
}

func (m *memWorkerFence) Apply(rules []workerfence.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	m.applied = append(m.applied, rules)
	return nil
}

func (m *memWorkerFence) Check([]workerfence.Rule) (bool, error) { return true, nil }
func (m *memWorkerFence) Remove() error                          { return nil }

func (m *memWorkerFence) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.applied)
}

func testWasmHostsConfig(t testing.TB, dir string) *WasmHostsConfig {
	return &WasmHostsConfig{Binary: "/usr/local/bin/aerolvm-rootd", UID: 61000, GID: 61000, SocketDir: filepath.Join(dir, "wasm"),
		SocketGID: os.Getgid(), CacheRoot: filepath.Join(dir, "cache"), AgentUID: 65531, ReadyWait: 2 * time.Second,
		Fence: true, Env: []string{"PATH=/usr/bin"}, NodePorts: []uint16{80}}
}

// wasmRig is a WASM worker launcher with its kernel parts in memory: the
// socket a file, the cache a folder, the fence a table in memory.
func wasmRig(t *testing.T) (*wasmHosts, *memWorkerFence, string) {
	t.Helper()
	dir := shortDir(t)
	cfg := testWasmHostsConfig(t, dir)
	fence := &memWorkerFence{}
	wf := newWasmFence(cfg, fence, slog.New(slog.NewTextHandler(io.Discard, nil)))
	wf.readResolv = func() ([]byte, error) { return []byte("nameserver 10.0.0.2\n"), nil }
	t.Cleanup(wf.close)
	w := newWasmHosts(cfg, rootpolicy.HostWasmWorker, wf, filepath.Join(dir, "hosts.log"))
	w.listen = func(path string, _ int) (*os.File, error) { return os.Create(path + ".fake") }
	w.openCache = func(d string, _ uint32) (*os.File, error) { return os.Open(d) }
	if err := os.MkdirAll(filepath.Join(cfg.CacheRoot, "owners", "operator"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.SocketDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return w, fence, dir
}

func TestWasmHostCommand(t *testing.T) {
	w, fence, dir := wasmRig(t)
	req := &rootdpb.SpawnHostRequest{Kind: rootdpb.HostKind_HOST_KIND_WASM_WORKER, Id: "sb-1",
		Wasm: &rootdpb.WasmHostSpec{Cache: "operator", Env: []string{"SB_AUDIT_INGEST_PORT=7000", "SB_NODE_ID=n1"}}}
	cmd, done, err := w.command(context.Background(), "sb-1", req)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	sock := filepath.Join(dir, "wasm", "w-sb-1.sock")
	if cmd.Path != "/usr/local/bin/aerolvm-rootd" || !slices.Equal(cmd.Args, []string{"/usr/local/bin/aerolvm-rootd", worker.WorkerFlag, sock}) {
		t.Fatalf("command %s %v", cmd.Path, cmd.Args)
	}
	if w.socket("sb-1") != sock {
		t.Fatalf("socket %s", w.socket("sb-1"))
	}
	// The helper's own settings first, then the agent's, then what the
	// helper hands over: the socket, the ready pipe and the cache, by
	// descriptor; the drop to the worker user; group sharing.
	want := []string{"PATH=/usr/bin", "SB_AUDIT_INGEST_PORT=7000", "SB_NODE_ID=n1", worker.ListenFDEnv + "=3", worker.ReadyFDEnv + "=4",
		worker.ShareGroupEnv + "=1", worker.ConfineEnv + "=61000:61000", worker.CacheDirEnv + "=/proc/self/fd/5"}
	if !slices.Equal(cmd.Env, want) {
		t.Fatalf("env %v\nwant %v", cmd.Env, want)
	}
	if len(cmd.ExtraFiles) != 3 || filepath.Base(cmd.ExtraFiles[2].Name()) != "operator" {
		t.Fatalf("extra files %v", cmd.ExtraFiles)
	}
	if cmd.Stdout == nil || cmd.Stdout != cmd.Stderr {
		t.Fatal("output not in the hosts' log")
	}
	// The fence went in, with the agent's audit port, before the command.
	if fence.count() == 0 || w.fence.auditPort.Load() != 7000 {
		t.Fatalf("fence applied %d times, audit port %d", fence.count(), w.fence.auditPort.Load())
	}
	// A cache it cannot open is no cache, never a failed start.
	w.openCache = func(string, uint32) (*os.File, error) { return nil, errors.New("not the agent's") }
	cmd2, done2, err := w.command(context.Background(), "sb-2", &rootdpb.SpawnHostRequest{Wasm: &rootdpb.WasmHostSpec{Cache: "owner-0123456789abcdef"}})
	if err != nil {
		t.Fatal(err)
	}
	done2()
	if slices.ContainsFunc(cmd2.Env, func(e string) bool { return strings.HasPrefix(e, worker.CacheDirEnv) }) || len(cmd2.ExtraFiles) != 2 {
		t.Fatalf("a cache it could not open was handed: %v", cmd2.Env)
	}
	_ = w.started(context.Background(), cmd2)
}

// TestWasmHostRefusals: the agent names no path and no setting off the
// list; a fence that cannot go in starts no worker.
func TestWasmHostRefusals(t *testing.T) {
	w, fence, _ := wasmRig(t)
	for _, tc := range []struct {
		name   string
		spec   *rootdpb.WasmHostSpec
		reason string
	}{
		{"a cache up the tree", &rootdpb.WasmHostSpec{Cache: "../../root"}, string(rootpolicy.RuleHost)},
		{"a cache by its folder", &rootdpb.WasmHostSpec{Env: []string{worker.CacheDirEnv + "=/"}}, ReasonBadRequest},
		{"a library to load as root", &rootdpb.WasmHostSpec{Env: []string{"LD_PRELOAD=/tmp/x.so"}}, ReasonBadRequest},
		{"the operator's file", &rootdpb.WasmHostSpec{Env: []string{"SB_EGRESS_OPERATOR_FILE=/etc/shadow"}}, ReasonBadRequest},
		{"no drop", &rootdpb.WasmHostSpec{Env: []string{worker.ConfineEnv + "=0:0"}}, ReasonBadRequest},
		{"a setting twice", &rootdpb.WasmHostSpec{Env: []string{"SB_NODE_ID=a", "SB_NODE_ID=b"}}, ReasonBadRequest},
		{"a setting with no value", &rootdpb.WasmHostSpec{Env: []string{"SB_NODE_ID"}}, ReasonBadRequest},
		{"a NUL in a value", &rootdpb.WasmHostSpec{Env: []string{"SB_NODE_ID=a\x00b"}}, ReasonBadRequest},
		{"a huge value", &rootdpb.WasmHostSpec{Env: []string{"SB_NODE_ID=" + strings.Repeat("x", maxWasmEnvValue+1)}}, ReasonBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := w.command(context.Background(), "sb-1", &rootdpb.SpawnHostRequest{Wasm: tc.spec})
			var fe *fileError
			if !errors.As(err, &fe) || fe.reason != tc.reason {
				t.Fatalf("got %v, want a %q refusal", err, tc.reason)
			}
		})
	}
	if _, _, err := w.command(context.Background(), "../x", &rootdpb.SpawnHostRequest{Wasm: &rootdpb.WasmHostSpec{}}); err == nil {
		t.Fatal("a socket up the tree")
	}
	fence.mu.Lock()
	fence.fail = errors.New("nft: no such table")
	fence.mu.Unlock()
	w2, _, _ := wasmRig(t)
	w2.fence.fence = workerfence.New(fence, w2.fence.spec, nil)
	_, _, err := w2.command(context.Background(), "sb-1", &rootdpb.SpawnHostRequest{Wasm: &rootdpb.WasmHostSpec{}})
	var fe *fileError
	if !errors.As(err, &fe) || fe.code != codes.Unavailable {
		t.Fatalf("no fence: %v", err)
	}
	if _, err := os.Stat(w2.socket("sb-1") + ".fake"); !os.IsNotExist(err) {
		t.Fatal("a socket was bound for a worker that cannot start")
	}
	// A listener that cannot be made fails the start.
	w.listen = func(string, int) (*os.File, error) { return nil, errors.New("folder not root's") }
	if _, _, err := w.command(context.Background(), "sb-9", &rootdpb.SpawnHostRequest{Wasm: &rootdpb.WasmHostSpec{}}); err == nil {
		t.Fatal("started with no socket")
	}
}

func TestWasmHostStarted(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(*os.File)
		want  string
	}{
		{"says it serves", func(w *os.File) { _, _ = w.Write([]byte{1}); _ = w.Close() }, ""},
		{"exits first", func(w *os.File) { _ = w.Close() }, "exited before it served"},
		{"never says", func(*os.File) {}, "did not serve"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _, _ := wasmRig(t)
			w.cfg.ReadyWait = 100 * time.Millisecond
			cmd, done, err := w.command(context.Background(), "sb-1", &rootdpb.SpawnHostRequest{Wasm: &rootdpb.WasmHostSpec{}})
			if err != nil {
				t.Fatal(err)
			}
			pw := cmd.ExtraFiles[1]
			tc.write(pw)
			err = w.started(context.Background(), cmd)
			done()
			if (tc.want == "" && err != nil) || (tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want))) {
				t.Fatalf("started = %v, want %q", err, tc.want)
			}
			// Read once: a second call has nothing to wait for.
			if err := w.started(context.Background(), cmd); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// tinyDir is a folder short enough for socket paths under it on macOS
// too, reached with no link on the way.
func tinyDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "w")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	if d, err = filepath.EvalSymlinks(d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestWasmHostTeardownAndPresent(t *testing.T) {
	dir := tinyDir(t)
	cfg := testWasmHostsConfig(t, dir)
	for _, k := range []rootpolicy.HostKind{rootpolicy.HostWasmWorker, rootpolicy.HostWasmResident} {
		w := newWasmHosts(cfg, k, nil, "")
		// No folder yet: nothing there.
		if ids, err := w.present(); err != nil || ids != nil {
			t.Fatalf("present with no folder = %v, %v", ids, err)
		}
		if err := w.teardown("sb-1"); err != nil {
			t.Fatal(err)
		}
	}
	w := newWasmHosts(cfg, rootpolicy.HostWasmWorker, nil, "")
	r := newWasmHosts(cfg, rootpolicy.HostWasmResident, nil, "")
	for _, id := range []string{"sb-1", "sb-2"} {
		f, err := w.listen(w.socket(id), os.Getgid())
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	f, err := r.listen(r.socket("b-1"), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := os.WriteFile(filepath.Join(cfg.SocketDir, "w-not.a.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ids, err := w.present()
	if err != nil || !slices.Equal(ids, []string{"sb-1", "sb-2"}) {
		t.Fatalf("worker sockets %v, %v", ids, err)
	}
	if ids, _ := r.present(); !slices.Equal(ids, []string{"b-1"}) {
		t.Fatalf("resident sockets %v", ids)
	}
	if err := w.teardown("sb-1"); err != nil {
		t.Fatal(err)
	}
	if ids, _ := w.present(); !slices.Equal(ids, []string{"sb-2"}) {
		t.Fatalf("after teardown %v", ids)
	}
	// Teardown removes a socket only: a file at its name is left, refused.
	if err := os.WriteFile(w.socket("sb-3"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.teardown("sb-3"); err == nil {
		t.Fatal("a plain file was removed as a socket")
	}
	if err := w.teardown("../x"); err == nil {
		t.Fatal("a teardown up the tree")
	}
	if p, l := w.prepare("sb-1", false, nil); p == nil || l != nil {
		t.Fatalf("prepare = %v, %v", p, l)
	}
	if _, ok := w.limits(rootpolicy.HostLimits{}); ok {
		t.Fatal("WASM hosts take limits")
	}
}

func TestOpenAgentFolder(t *testing.T) {
	dir := shortDir(t)
	cache := filepath.Join(dir, "owners", "operator")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := openAgentFolder(cache, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := openAgentFolder(cache, uint32(os.Getuid())+1); err == nil {
		t.Fatal("a folder that is not the agent's was opened")
	}
	link := filepath.Join(dir, "owners", "linked")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	if _, err := openAgentFolder(link, uint32(os.Getuid())); err == nil {
		t.Fatal("a link was followed")
	}
}

func TestWasmFenceSpec(t *testing.T) {
	dir := shortDir(t)
	cfg := testWasmHostsConfig(t, dir)
	op := filepath.Join(dir, "operator.yaml")
	if err := os.WriteFile(op, []byte("upstream_proxy:\n  url: http://10.1.2.3:3128\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.OperatorFile = op
	f := newWasmFence(cfg, &memWorkerFence{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.readResolv = func() ([]byte, error) { return []byte("nameserver 10.0.0.2\n"), nil }
	f.auditPort.Store(7000)
	spec, err := f.spec()
	if err != nil {
		t.Fatal(err)
	}
	var why []string
	for _, a := range spec.Allow {
		why = append(why, a.Why+" "+a.Prefix.String())
	}
	if spec.UID != 61000 || !slices.Equal(spec.NodePorts, []uint16{80}) || len(spec.Floor) == 0 ||
		!slices.Contains(why, "audit ingest 127.0.0.1/32") || !slices.Contains(why, "name server 10.0.0.2/32") {
		t.Fatalf("spec %+v (%v)", spec, why)
	}
	// An unreadable floor file fails closed: no fence, no worker.
	t.Setenv("SB_EGRESS_DENY_FLOOR_FILE", filepath.Join(dir, "missing"))
	if _, err := f.spec(); err == nil {
		t.Fatal("a fence with no floor")
	}
	if _, err := url.Parse("http://x"); err != nil {
		t.Fatal(err)
	}
	// Off, there is nothing to ensure; nil is off too.
	cfg.Fence = false
	off := newWasmFence(cfg, &memWorkerFence{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := off.ensure(nil); err != nil || off.fence != nil {
		t.Fatalf("fence off: %v", err)
	}
	var none *wasmFence
	if err := none.ensure(nil); err != nil {
		t.Fatal(err)
	}
	none.close()
}

// TestWasmHostsThroughTheServer: a helper with WASM hosts lists both kinds
// and answers a spawn with the socket it made, through the server.
func TestWasmHostsThroughTheServer(t *testing.T) {
	kernel := newFakeHostKernel()
	var wh *wasmHosts
	r := newRig(t, func(c *Config, o *Options) {
		c.Hosts = HostsConfig{LogPath: filepath.Join(t.TempDir(), "hosts.log"), Wasm: testWasmHostsConfig(t, shortDir(t))}
		c.Hosts.Wasm.Fence = false
		o.HostKernel = kernel
		o.WorkerFence = &memWorkerFence{}
		wh = newWasmHosts(c.Hosts.Wasm, rootpolicy.HostWasmWorker, nil, c.Hosts.LogPath)
		wh.listen = func(path string, _ int) (*os.File, error) { return os.CreateTemp("", "sock") }
		wh.cfg.ReadyWait = 50 * time.Millisecond
		o.hostLaunchers = map[rootpolicy.HostKind]hostLauncher{rootpolicy.HostWasmWorker: wh}
	})
	t.Cleanup(func() { r.srv.hosts.reaping.Wait() })
	resp, err := hostClient(r).Version(callCtx(t), &rootdpb.VersionRequest{})
	if err != nil || !slices.Equal(resp.GetHosts(), []string{"wasm_worker", "wasm_resident"}) {
		t.Fatalf("hosts %v, %v", resp.GetHosts(), err)
	}
	// The fake kernel's stand-in never says it serves: the start fails and
	// the group is killed.
	_, err = hostClient(r).SpawnHost(callCtx(t), &rootdpb.SpawnHostRequest{Kind: rootdpb.HostKind_HOST_KIND_WASM_WORKER, Id: "sb-1",
		Wasm: &rootdpb.WasmHostSpec{}})
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "did not serve") {
		t.Fatalf("spawn = %v", err)
	}
	if len(kernel.killed) != 1 {
		t.Fatalf("killed %v", kernel.killed)
	}
}
