package containerd

import (
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	cntr "github.com/containerd/containerd/v2/client"
)

func TestBuildEnvIncludesToolboxContractAndUserEnv(t *testing.T) {
	req := models.CreateSandboxRequest{Env: map[string]string{"FOO": "bar", "BAZ": "qux"}}
	env := buildEnv(req, "sb-1", "tok-123", 2280)

	// Sorted for deterministic spec assembly.
	if !slices.IsSorted(env) {
		t.Fatalf("env not sorted: %v", env)
	}
	want := []string{"SB_TOOLBOX_PORT=2280", "SB_TOOLBOX_TOKEN=tok-123", "SB_SANDBOX_ID=sb-1", "FOO=bar", "BAZ=qux"}
	for _, w := range want {
		if !slices.Contains(env, w) {
			t.Fatalf("env missing %q: %v", w, env)
		}
	}
}

func TestBuildMountsIncludesToolboxAndHostFilesAndUserBinds(t *testing.T) {
	cfg := Config{ToolboxBinaryPath: "/host/toolboxd", ToolboxMountPath: "/.aerol/toolboxd"}
	hf := &sandboxHostFiles{ResolvConf: "/run/r", Hosts: "/run/h", Hostname: "/run/n"}
	binds := []mounts.ContainerBind{
		{HostPath: "/host/data", ContainerPath: "/data", ReadOnly: false},
		{HostPath: "/host/ro", ContainerPath: "/ro", ReadOnly: true},
	}
	ms := buildMounts(cfg, hf, binds)

	byDest := map[string][]string{}
	for _, m := range ms {
		byDest[m.Destination] = m.Options
	}
	if _, ok := byDest["/.aerol/toolboxd"]; !ok {
		t.Fatal("toolbox binary mount missing")
	}
	for _, dest := range []string{"/etc/resolv.conf", "/etc/hosts", "/etc/hostname"} {
		if _, ok := byDest[dest]; !ok {
			t.Fatalf("host file mount %q missing", dest)
		}
	}
	roOpts, ok := byDest["/ro"]
	if !ok || !slices.Contains(roOpts, "ro") {
		t.Fatalf("read-only user bind should carry ro option, got %v", roOpts)
	}
	rwOpts := byDest["/data"]
	if slices.Contains(rwOpts, "ro") {
		t.Fatalf("read-write bind must not carry ro option, got %v", rwOpts)
	}
}

func TestCreateSnapshotRequiresLiveContainerd(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	tr.containers["c"] = &fakeContainer{id: "c", task: &fakeTask{status: cntr.Running}}
	d.SetClient(NewTestClient("aerolvm", tr))
	if _, err := d.CreateSnapshot(t.Context(), "c", "img:latest"); err == nil || !strings.Contains(err.Error(), "live containerd") {
		t.Fatalf("CreateSnapshot should require live containerd, got %v", err)
	}
}

func TestResizeUpdatesRunningTask(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	tr.containers["c"] = &fakeContainer{id: "c", task: &fakeTask{status: cntr.Running}}
	d.SetClient(NewTestClient("aerolvm", tr))
	// Resize is implemented (task.Update): a CPU/mem change against a running
	// task succeeds, and an empty request is a no-op.
	if err := d.Resize(t.Context(), "c", models.ResizeSandboxRequest{CPU: 2, MemoryMB: 512}); err != nil {
		t.Fatalf("Resize should succeed against a running task, got %v", err)
	}
	if err := d.Resize(t.Context(), "c", models.ResizeSandboxRequest{}); err != nil {
		t.Fatalf("empty Resize should be a no-op, got %v", err)
	}
}
