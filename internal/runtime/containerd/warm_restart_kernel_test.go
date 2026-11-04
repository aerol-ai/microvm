//go:build linux && kerneltest

package containerd

// A sandbox adopted from the containerd warm pool, stopped and started again,
// on a real containerd + runc (and runsc when listed). As root:
//
//	AEROL_KT_CONTAINERD_SOCKET=/run/containerd-kt/containerd.sock \
//	AEROL_KT_TOOLBOXD=/path/to/linux/toolboxd \
//	AEROL_KT_RUNTIMES=docker,gvisor \
//	AEROL_KT_NETNS=/var/run/netns/kt \
//	go test -tags kerneltest ./internal/runtime/containerd/ -run KernelWarmAdopted -v
//
// The image (AEROL_KT_IMAGE, default docker.io/library/alpine:3.20) is pulled
// on first use; AEROL_KT_CYCLES (default 2) sets the cycles per runtime and
// the test logs the adopt-path create p50 over them. AEROL_KT_ADOPT_ONLY=1
// stops each cycle after the adopt, for timing a tree whose start fails. Without the socket and toolboxd the test skips, so a plain
// `go test -tags kerneltest` on a host without containerd stays green.
//
// What it proves, per runtime: a parked container adopted by a create can be
// stopped and started again (live: "open .../hosts/park-<id>/resolv.conf: no
// such file or directory"), its toolboxd serves the sandbox's identity and
// token after the start, its resolv.conf is the one the park generated, it
// starts again under a fresh driver (a sandboxd restart, its ready sockets
// swept), and Destroy leaves no host file, task log or ready socket behind.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

// identityStarter is runtime.IdentityStarter, looked up dynamically so this
// test also builds (and shows the failure) on a tree without it.
type identityStarter interface {
	StartWithIdentity(ctx context.Context, containerRef, sandboxID, toolboxToken string) (*models.SandboxRuntimeState, error)
}

func ktRandHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func ktDriver(t *testing.T, base, runtime string) *Driver {
	t.Helper()
	cfg := Config{
		Socket:             os.Getenv("AEROL_KT_CONTAINERD_SOCKET"),
		Namespace:          "aerolvm-kt",
		ToolboxBinaryPath:  os.Getenv("AEROL_KT_TOOLBOXD"),
		ToolboxMountPath:   "/.aerol/toolboxd",
		ToolboxPort:        2280,
		DefaultRuntime:     runtime,
		WaitTimeout:        60 * time.Second,
		ToolboxWaitTimeout: 60 * time.Second,
		ReadyEnabled:       true,
		ReadyDir:           filepath.Join(base, "ready"),
		LogDir:             filepath.Join(base, "logs"),
		RunDir:             filepath.Join(base, "run"),
		PullMaxConcurrent:  1,
		HTTPClientTimeout:  60 * time.Second,
		ResourceLimitsOff:  os.Getenv("AEROL_KT_LIMITS_OFF") == "1",
	}
	d := New(cfg, nil, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	// A fresh netns has lo down; runc brings it up, runsc does not. The
	// netns pool hands out prepared namespaces, so stand one in that has lo
	// up (AEROL_KT_NETNS, made with `ip netns add`).
	if path := os.Getenv("AEROL_KT_NETNS"); path != "" {
		d.cfg.NativeNetnsPool = true
		d.SetNetnsHandoff(ktNetns{path: path})
	}
	return d
}

// ktNetns hands every container the same prepared netns; the test runs one
// container at a time.
type ktNetns struct{ path string }

func (n ktNetns) Provision(context.Context, string) (string, string, error) {
	return n.path, "127.0.0.1", nil
}
func (ktNetns) Release(context.Context, string) error               { return nil }
func (ktNetns) ReassignOwner(context.Context, string, string) error { return nil }

type ktSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *ktSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *ktSyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// ktExec runs args inside the container's running task and returns its
// combined output and exit code.
func ktExec(t *testing.T, d *Driver, containerID string, args ...string) (string, uint32) {
	t.Helper()
	ctx := namespaced(context.Background(), d.cfg.Namespace)
	client, err := d.ensureClient()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.LoadContainer(ctx, containerID)
	if err != nil {
		t.Fatalf("load %s: %v", containerID, err)
	}
	task, err := c.Task(ctx, nil)
	if err != nil {
		t.Fatalf("task of %s: %v", containerID, err)
	}
	spec, err := c.Spec(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proc := *spec.Process
	proc.Args = args
	proc.Terminal = false
	// stdout and stderr are copied by two goroutines into one buffer.
	out := &ktSyncBuffer{}
	execID := "kt-" + ktRandHex(t, 4)
	p, err := task.Exec(ctx, execID, &proc, cio.NewCreator(cio.WithStreams(nil, out, out)))
	if err != nil {
		t.Fatalf("exec %v: %v", args, err)
	}
	defer func() { _, _ = p.Delete(ctx, cntr.WithProcessKill) }()
	statusC, err := p.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(ctx); err != nil {
		t.Fatalf("exec start %v: %v", args, err)
	}
	select {
	case st := <-statusC:
		// The IO copier drains after the exit; read the buffer once it has.
		p.IO().Wait()
		return out.String(), st.ExitCode()
	case <-time.After(30 * time.Second):
		t.Fatalf("exec %v timed out; output so far: %q", args, out.String())
	}
	return "", 1
}

// ktExecOut is ktExec retried until the command exits 0 with output: the
// toolbox may still be binding its port right after a start, and a short
// exec's output can reach the client after its exit status does.
func ktExecOut(t *testing.T, d *Driver, containerID string, args ...string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var out string
	var code uint32
	for time.Now().Before(deadline) {
		if out, code = ktExec(t, d, containerID, args...); code == 0 && strings.TrimSpace(out) != "" {
			return out
		}
		time.Sleep(200 * time.Millisecond)
	}
	diag, _ := ktExec(t, d, containerID, "sh", "-c", "echo diag; ip addr 2>&1; netstat -ltn 2>&1; wget -O- http://127.0.0.1:2280/health 2>&1; ps 2>&1")
	t.Fatalf("exec %v in %s: exit %d, output %q; diagnostics: %s", args, containerID, code, out, diag)
	return ""
}

// ktAssertServes checks the container's toolboxd took the sandbox's identity
// and token: before adoption it answers everything but /health with 503.
func ktAssertServes(t *testing.T, d *Driver, containerID, sandboxID, token string) {
	t.Helper()
	if out := ktExecOut(t, d, containerID, "wget", "-qO-", "http://127.0.0.1:2280/"); !strings.Contains(out, `"sandbox_id":"`+sandboxID+`"`) {
		t.Fatalf("toolboxd / = %q, want sandbox_id %q", out, sandboxID)
	}
	if out := ktExecOut(t, d, containerID, "wget", "-qO-", "--header", "Authorization: Bearer "+token,
		"http://127.0.0.1:2280/files/info?path=/etc/resolv.conf"); !strings.Contains(out, "resolv.conf") {
		t.Fatalf("authenticated toolbox call with the sandbox token = %q", out)
	}
}

func ktListDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestKernelWarmAdoptedSandboxRestarts(t *testing.T) {
	if os.Getenv("AEROL_KT_CONTAINERD_SOCKET") == "" || os.Getenv("AEROL_KT_TOOLBOXD") == "" {
		t.Skip("set AEROL_KT_CONTAINERD_SOCKET and AEROL_KT_TOOLBOXD (see the comment at the top)")
	}
	runtimes := strings.Split(os.Getenv("AEROL_KT_RUNTIMES"), ",")
	if os.Getenv("AEROL_KT_RUNTIMES") == "" {
		runtimes = []string{models.RuntimeDocker}
	}
	for _, rt := range runtimes {
		rt := strings.TrimSpace(rt)
		t.Run(rt, func(t *testing.T) { ktAdoptStopStart(t, rt) })
	}
}

func ktAdoptStopStart(t *testing.T, runtime string) {
	image := os.Getenv("AEROL_KT_IMAGE")
	if image == "" {
		image = "docker.io/library/alpine:3.20"
	}
	// Unix socket paths are capped near 108 bytes: keep the base short.
	base, err := os.MkdirTemp("/tmp", "kt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })

	// No netns pool here: the container gets containerd's private netns
	// (loopback only), so stand in for the address probe.
	origIP := containerIPv4FromTaskFn
	containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) { return "127.0.0.1", nil }
	t.Cleanup(func() { containerIPv4FromTaskFn = origIP })

	d := ktDriver(t, base, runtime)
	ctx := namespaced(context.Background(), d.cfg.Namespace)
	req := models.CreateSandboxRequest{Image: image, Runtime: runtime, CPU: models.DefaultCPU, MemoryMB: models.DefaultMemoryMB}
	key := containerdpool.KeyFromRequest(req, runtime)

	cycles := 2
	if n, err := strconv.Atoi(os.Getenv("AEROL_KT_CYCLES")); err == nil && n > 0 {
		cycles = n
	}
	var adoptTimes, startTimes []time.Duration
	t.Cleanup(func() {
		for _, m := range []struct {
			what  string
			times []time.Duration
		}{{"adopt-path create", adoptTimes}, {"start of a stopped adopted sandbox", startTimes}} {
			if len(m.times) == 0 {
				continue
			}
			slices.Sort(m.times)
			t.Logf("%s over %d runs: p50 %s, max %s", m.what, len(m.times), m.times[len(m.times)/2], m.times[len(m.times)-1])
		}
	})
	for cycle := 0; cycle < cycles; cycle++ {
		parkID := "park-" + ktRandHex(t, 8)
		sandboxID := "sb-kt-" + ktRandHex(t, 6)
		token := ktRandHex(t, 32)

		slot, err := (&PoolSpawner{Driver: d}).Park(ctx, parkID, key)
		if err != nil {
			t.Fatalf("park: %v", err)
		}
		pool := containerdpool.New(nil)
		pool.NoteTarget(key)
		pool.RecordLoaded(slot)
		d.SetWarmPool(pool)

		start := time.Now()
		state, err := d.Create(ctx, req, sandboxID, token, nil)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		adoptTimes = append(adoptTimes, time.Since(start))
		if state.AdoptedParkID != parkID || state.ContainerID != parkID {
			t.Fatalf("create did not adopt the parked slot: %+v", state)
		}
		d.SetWarmPool(nil)
		ktAssertServes(t, d, parkID, sandboxID, token)
		if os.Getenv("AEROL_KT_ADOPT_ONLY") == "1" {
			// Timing runs (comparable on a tree where the start fails).
			if err := d.Destroy(ctx, &models.Sandbox{ID: sandboxID, ContainerID: parkID}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		resolvBefore := ktExecOut(t, d, parkID, "cat", "/etc/resolv.conf")

		// The live failure: stop, then start again.
		if err := d.Stop(ctx, parkID); err != nil {
			t.Fatalf("stop: %v", err)
		}
		startAgain := func(d *Driver) {
			t.Helper()
			var err error
			startedAt := time.Now()
			defer func() { startTimes = append(startTimes, time.Since(startedAt)) }()
			if is, ok := any(d).(identityStarter); ok {
				_, err = is.StartWithIdentity(ctx, parkID, sandboxID, token)
			} else {
				_, err = d.Start(ctx, parkID)
			}
			if err != nil {
				t.Fatalf("start of a stopped warm-adopted sandbox: %v", err)
			}
		}
		startAgain(d)
		ktAssertServes(t, d, parkID, sandboxID, token)
		if resolvAfter := ktExecOut(t, d, parkID, "cat", "/etc/resolv.conf"); resolvAfter != resolvBefore {
			t.Fatalf("resolv.conf after the start = %q, want the park's %q", resolvAfter, resolvBefore)
		}

		// A sandboxd restart: a fresh driver, and the boot-time ready-socket
		// sweep has removed every socket file.
		for _, name := range ktListDir(t, d.cfg.ReadyDir) {
			_ = os.Remove(filepath.Join(d.cfg.ReadyDir, name))
		}
		d2 := ktDriver(t, base, runtime)
		if err := d2.Stop(ctx, parkID); err != nil {
			t.Fatalf("stop after restart: %v", err)
		}
		startAgain(d2)
		ktAssertServes(t, d2, parkID, sandboxID, token)

		if err := d2.Destroy(ctx, &models.Sandbox{ID: sandboxID, ContainerID: parkID, ContainerIP: state.ContainerIP}); err != nil {
			t.Fatalf("destroy: %v", err)
		}
		for _, dir := range []string{filepath.Join(d.cfg.RunDir, "hosts"), d.cfg.LogDir, d.cfg.ReadyDir} {
			if left := ktListDir(t, dir); len(left) > 0 {
				t.Fatalf("cycle %d: %s holds %v after the destroy, want nothing", cycle, dir, left)
			}
		}
	}
}
